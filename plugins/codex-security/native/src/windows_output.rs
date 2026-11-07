use crate::windows::{current_user_sid, io_error, os_string, sid_string};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{File, OpenOptions},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    },
};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, LocalFree, RtlNtStatusToDosError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
        ERROR_FILENAME_EXCED_RANGE, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
        ERROR_INVALID_ACL, ERROR_PATH_NOT_FOUND, GENERIC_ALL, GENERIC_WRITE, OBJ_CASE_INSENSITIVE,
        OBJ_DONT_REPARSE, UNICODE_STRING,
    },
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        LookupAccountSidW, SidTypeUser, ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    },
    Storage::FileSystem::{
        DELETE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, READ_CONTROL, WRITE_DAC,
        WRITE_OWNER,
    },
};

use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const CHANGE_ACL: u32 = WRITE_DAC | WRITE_OWNER;
const SET_REPARSE_POINT: u32 = FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA;
const OUTPUT_RIGHTS: u32 =
    FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | DELETE | CHANGE_ACL | SET_REPARSE_POINT;
const EVERYONE: &str = "S-1-1-0";
const AUTHENTICATED_USERS: &str = "S-1-5-11";

fn trusted(sid: &str, user: &str) -> bool {
    sid == user
        || matches!(
            sid,
            "S-1-5-18" // SYSTEM
                | "S-1-5-32-544" // Administrators
                | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
        )
}

fn named_authenticated_user(sid: PSID, text: &str) -> bool {
    // Account-domain SIDs also identify groups and the Guest account.
    if !text.starts_with("S-1-5-21-") || text.ends_with("-501") {
        return false;
    }
    let (mut names, mut domains, mut kind) = (0, 0, 0);
    let lookup = |name, names: &mut u32, domain, domains: &mut u32, kind: &mut i32| unsafe {
        LookupAccountSidW(null(), sid, name, names, domain, domains, kind)
    };
    lookup(null_mut(), &mut names, null_mut(), &mut domains, &mut kind);
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return false;
    }
    let (mut name, mut domain) = (vec![0; names as usize], vec![0; domains as usize]);
    lookup(
        name.as_mut_ptr(),
        &mut names,
        domain.as_mut_ptr(),
        &mut domains,
        &mut kind,
    ) != 0
        && kind == SidTypeUser
}

fn inspect_dacl(acl: *const ACL, user: &str) -> Result<u32, u32> {
    if acl.is_null() {
        return Ok(OUTPUT_RIGHTS); // A NULL DACL grants everyone full access.
    }
    let mut grants = 0;
    let mut denied = HashMap::<String, u32>::new();
    // GetSecurityInfo owns the ACL and its ACEs in one descriptor until LocalFree.
    let header = unsafe { &*acl };
    let bytes = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), header.AclSize.into()) };
    let mut entries = bytes.get(size_of::<ACL>()..).ok_or(ERROR_INVALID_ACL)?;
    for _ in 0..header.AceCount {
        let &[kind, flags, low, high, ..] = entries else {
            return Err(ERROR_INVALID_ACL);
        };
        let size = usize::from(u16::from_le_bytes([low, high]));
        if size < 4 {
            return Err(ERROR_INVALID_ACL);
        }
        let (bytes, rest) = entries.split_at_checked(size).ok_or(ERROR_INVALID_ACL)?;
        entries = rest;
        if u32::from(flags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        // Every access ACE starts with its four-byte header and access mask.
        let (mask, payload) = bytes[4..]
            .split_first_chunk::<4>()
            .ok_or(ERROR_INVALID_ACL)?;
        let mut mask = u32::from_le_bytes(*mask);
        if mask & GENERIC_ALL != 0 {
            mask |= OUTPUT_RIGHTS;
        }
        if mask & GENERIC_WRITE != 0 {
            mask |= FILE_ADD_SUBDIRECTORY | SET_REPARSE_POINT;
        }
        mask &= OUTPUT_RIGHTS;
        if mask == 0 {
            continue;
        }
        // ACCESS_ALLOWED, ACCESS_DENIED, their object and callback variants.
        // A conditional deny cannot prove that another identity lacks access.
        let sid_bytes = match kind {
            0 | 1 | 9 => payload,
            5 | 6 | 11 => {
                let (flags, rest) = payload.split_first_chunk::<4>().ok_or(ERROR_INVALID_ACL)?;
                let flags = u32::from_le_bytes(*flags);
                if kind == 6 && flags & 1 != 0 {
                    continue; // Object-specific deny.
                }
                rest.get(16 * (flags & 3).count_ones() as usize..)
                    .ok_or(ERROR_INVALID_ACL)?
            }
            10 | 12 => continue, // Conditional deny.
            _ => return Err(ERROR_INVALID_ACL),
        };
        let (sid_header, subauthorities) = sid_bytes
            .split_first_chunk::<8>()
            .ok_or(ERROR_INVALID_ACL)?;
        if subauthorities.len() < 4 * usize::from(sid_header[1]) {
            return Err(ERROR_INVALID_ACL);
        }
        let raw_sid = sid_bytes.as_ptr().cast_mut().cast();
        let sid = unsafe { sid_string(raw_sid) }?;
        if trusted(&sid, user) || sid == "S-1-3-4" {
            continue; // OWNER RIGHTS applies to the already-verified owner.
        }
        if matches!(kind, 1 | 6) {
            *denied.entry(sid).or_default() |= mask;
        } else {
            let mut excluded =
                denied.get(EVERYONE).copied().unwrap_or(0) | denied.get(&sid).copied().unwrap_or(0);
            if let Some(&authenticated) = denied.get(AUTHENTICATED_USERS) {
                if mask & authenticated != 0 && named_authenticated_user(raw_sid, &sid) {
                    excluded |= authenticated;
                }
            }
            grants |= mask & !excluded;
        }
    }
    Ok(if grants & CHANGE_ACL != 0 {
        OUTPUT_RIGHTS
    } else {
        grants
    })
}

fn output_rights(file: &File, user: &str) -> Result<u32, u32> {
    let attributes = file.metadata().map_err(io_error)?.file_attributes();
    if attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
        != FILE_ATTRIBUTE_DIRECTORY
    {
        return Err(ERROR_ACCESS_DENIED);
    }
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut descriptor = null_mut();
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(error);
    }
    let rights = unsafe { sid_string(owner) }.and_then(|sid| {
        if trusted(&sid, user) {
            inspect_dacl(acl, user)
        } else {
            Err(ERROR_ACCESS_DENIED)
        }
    });
    unsafe { LocalFree(descriptor) };
    rights
}

const PIN_ACCESS: u32 = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL;

fn relative_directory(
    parent: &File,
    name: &OsStr,
    descriptor: Option<PSECURITY_DESCRIPTOR>,
) -> Result<File, u32> {
    let mut units: Vec<_> = name.encode_wide().collect();
    let length = u16::try_from(units.len() * 2).map_err(|_| ERROR_FILENAME_EXCED_RANGE)?;
    let mut name = UNICODE_STRING {
        Buffer: units.as_mut_ptr(),
        Length: length,
        MaximumLength: length,
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: descriptor.unwrap_or(null_mut()).cast(),
        ..Default::default()
    };
    let mut handle = null_mut();
    let mut io = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            PIN_ACCESS,
            &attributes,
            &mut io,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            if descriptor.is_some() {
                FILE_CREATE
            } else {
                FILE_OPEN
            },
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(unsafe { RtlNtStatusToDosError(status) });
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// Open each directory relative to its verified parent, including creation of
/// a missing leaf. A reparse point added to an empty directory cannot redirect
/// an absolute-path operation beyond the directory whose ACL we inspected.
/// For validation, an omitted writable_leaf preflights a prospective path.
/// Both read and write validation of a selected directory require it to exist.
pub(crate) fn inspect_output_path(
    path: &Path,
    user: &str,
    create: Option<PSECURITY_DESCRIPTOR>,
    writable_leaf: Option<bool>,
    retained_directory: Option<&OsStr>,
) -> Result<(), u32> {
    let mut ancestors: Vec<File> = Vec::new();
    let mut parent = 0;
    for entry in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let opened = if let Some(handle) = ancestors.last() {
            relative_directory(handle, entry.file_name().ok_or(ERROR_ACCESS_DENIED)?, None)
        } else {
            OpenOptions::new()
                .access_mode(PIN_ACCESS)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(entry)
                .map_err(io_error)
        };
        let file = match opened {
            Ok(file) => file,
            Err(error @ (ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)) => {
                if replaceable(parent, 0) {
                    return Err(ERROR_ACCESS_DENIED);
                }
                if create.is_none() {
                    return if writable_leaf.is_some() {
                        Err(error)
                    } else {
                        Ok(())
                    };
                }
                if entry != path {
                    return Err(ERROR_PATH_NOT_FOUND);
                }
                relative_directory(
                    ancestors.last().ok_or(ERROR_PATH_NOT_FOUND)?,
                    entry.file_name().ok_or(ERROR_ACCESS_DENIED)?,
                    create,
                )?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let rights = output_rights(&file, user)?;
        if replaceable(parent, rights) {
            return Err(ERROR_ACCESS_DENIED);
        }
        if entry == path && writable_leaf == Some(true) && rights & SET_REPARSE_POINT != 0 {
            // Windows can retag only an empty directory. A known child that
            // another user cannot remove keeps a resumed output nonempty.
            let name = retained_directory
                .filter(|name| Path::new(name).file_name() == Some(*name))
                .ok_or(ERROR_ACCESS_DENIED)?;
            if rights & FILE_DELETE_CHILD != 0 {
                return Err(ERROR_ACCESS_DENIED);
            }
            let child = relative_directory(&file, name, None)?;
            if output_rights(&child, user)? & DELETE != 0 {
                return Err(ERROR_ACCESS_DENIED);
            }
        }
        ancestors.push(file);
        parent = rights;
    }
    if create.is_some() {
        Err(ERROR_ALREADY_EXISTS)
    } else {
        Ok(())
    }
}

fn replaceable(parent: u32, child: u32) -> bool {
    parent & (FILE_ADD_SUBDIRECTORY | SET_REPARSE_POINT) != 0
        && (parent & FILE_DELETE_CHILD != 0 || child & DELETE != 0)
}

#[napi]
pub fn validate_windows_output_path(
    path: Buffer,
    writable_leaf: Option<bool>,
    retained_directory: Option<String>,
) -> napi::Result<u32> {
    let path = os_string(path)?;
    Ok(current_user_sid()
        .and_then(|user| {
            inspect_output_path(
                Path::new(&path),
                &user,
                None,
                writable_leaf,
                retained_directory.as_deref().map(OsStr::new),
            )
        })
        .map_or_else(|e| e, |_| 0))
}
