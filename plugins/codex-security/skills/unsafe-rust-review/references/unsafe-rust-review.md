---
name: unsafe-rust-review
description: Write and review unsafe Rust `# Safety` documentation and safety comments (e.g., `// safety:` or `/// safety:` in any capitalization) as proof obligations grounded in the Rust Reference, standard library documentation, trusted opted-in dependency contracts, and explicit project invariants.
---

<!-- Vendored from google/rust-skills at 4b4f8b25d19c5ad3ad78b23c4c55ac35adad75a3. Prose line wrapping was changed for this repository; wording and fenced examples are unchanged. See UPSTREAM.md for attribution and licensing. -->

# Unsafe Rust Safety Documentation and Commenting Skill

## Mission

Act as an extremely strict unsafe Rust author and reviewer. Treat every `# Safety` section as an English-language theorem or lemma, and every safety comment (e.g., `// safety:` or `/// safety:` in any capitalization) as an English-language proof.

The goal is not reassuring prose. The goal is logic bulletproof-ness. A reviewer should be able to mechanically translate the prose into proof obligations and check each obligation against authoritative Rust axioms, documented dependency contracts, project-local invariants, type-system facts, and local code facts.

The governing standard is:

> Every unsafe boundary creates proof obligations, and every unsafe operation
> must locally prove that those obligations are discharged.

An `unsafe fn` or `unsafe trait` states extra conditions that callers or implementers must satisfy. An `unsafe {}` block, `unsafe impl`, or unsafe attribute use is the code author’s assertion that the relevant conditions have been satisfied at that exact program point.

Unsafe documentation and comments must therefore be written in the style of formal proof:

-   Define the proposition being proved.
-   Enumerate all required assumptions.
-   Classify each assumption by source.
-   Show that the assumptions imply the required unsafe contract.
-   State the postconditions and state transitions caused by the unsafe
    operation.
-   Reject every implicit, circular, stale, unverifiable, or folklore premise.

## Activation criteria

Use this skill whenever authoring or reviewing Rust code that contains, exposes, wraps, depends on, or reasons about any unsafe surface, including:

-   `unsafe fn`
-   `unsafe trait`
-   unsafe trait methods
-   `unsafe impl`
-   `unsafe extern` blocks or functions
-   unsafe attributes such as `no_mangle`, `export_name`, `link_section`, or
    `naked`
-   `unsafe {}` blocks
-   raw pointer dereferences
-   calls to unsafe functions
-   accesses to union fields
-   accesses to mutable statics or extern statics
-   inline assembly
-   FFI boundaries
-   `target_feature`-sensitive code
-   manual allocation, deallocation, ownership reconstruction, or layout
    manipulation
-   manual initialization or drop management
-   pin projection or pinned destruction logic
-   unsafe abstractions over safe callback, trait, iterator, comparator, or
    closure inputs
-   safe API surfaces that can establish, expose, or break unsafe invariants,
    including public fields, constructors, safe methods, safe trait methods, and
    macro-generated APIs
-   macro-generated or build-generated unsafe code or safe API surfaces
-   feature-gated, cfg-gated, target-specific, allocator-specific,
    SIMD-specific, or debug/release-specific unsafe code paths

Use the strictest reasonable interpretation of all requirements. When style or review advice conflicts, choose the more demanding rule unless it conflicts with the Rust Reference or standard library documentation.

## Core model

### Safety documentation is a theorem

A `# Safety` section on an unsafe API states a theorem of the following shape:

```text
If the caller or implementer satisfies preconditions P1 ... Pn,
then invoking or implementing this unsafe API preserves Rust soundness.
```

The documentation must say exactly who is responsible for the preconditions and how long each precondition must hold.

### Safety comments are proofs

A safety comment (which may use `// SAFETY:`, `// safety:`, `// Safety:`, or their doc comment equivalents like `/// safety:`) immediately adjacent to an unsafe operation proves a theorem of the following shape:

```text
The unsafe operation O requires obligations Q1 ... Qn.
At this program point, facts F1 ... Fm hold.
Facts F1 ... Fm imply Q1 ... Qn.
Therefore O's unsafe contract is discharged.
After O, state changes S1 ... Sk hold.
```

The proof must be local enough that a maintainer can audit it without searching through the entire program, except for explicitly named project-local invariants, dependency contracts, and upstream `# Safety` preconditions.

### Soundness target

Unsafe code is sound only if safe Rust code using the abstraction cannot trigger undefined behavior without crossing an unsafe contract. The abstraction may have logic bugs, panic, leak memory, or produce incorrect values, but it must not allow safe callers to cause UB merely by using safe APIs in type-correct but adversarial ways.

## Authority and evidence hierarchy

Use this hierarchy when writing or reviewing safety documentation.

### 1. Core Rust axioms

The only core axioms for Rust language and standard-library semantics are:

1.  The Rust Reference.
2.  The Rust standard library documentation.

All claims about undefined behavior, validity, aliasing, layout, references, pointer arithmetic, initialization, drop, standard-library unsafe contracts, and standard-library safe API semantics must bottom out in these sources.

Do not use folklore as an axiom. Do not rely on current compiler behavior, LLVM behavior, Miri behavior, blog posts, examples, or "how Rust usually works" unless the fact is entailed by the Rust Reference or standard library documentation.

### 2. Trusted opted-in dependency contracts

It is acceptable to assume that safe dependencies intentionally selected by the code author work as documented.

For example, if this crate intentionally depends on a library or uses a standard-library safe API, the safety proof may assume that the dependency's safe APIs perform their documented safe behavior. In particular, it is acceptable to rely on a dependency function such as `Vec::sort` actually performing the sorting operation documented by the standard library, subject to that API's own documented assumptions and inputs.

This rule is a trust-boundary rule, not a Rust-language axiom:

-   Treat non-std dependency behavior as a `DEPENDENCY LEMMA`, not as a core
    Rust axiom.
-   Prefer pinned versions and exact documentation links when relying on non-std
    dependency semantics.
-   Do not let dependency documentation invent Rust layout, aliasing, validity,
    provenance, or UB rules that are not supported by the Reference or std docs.
-   Do not use a dependency lemma to discharge an unsafe contract unless the
    dependency API actually guarantees the needed fact.
-   Do not silently rely on a dependency's undocumented behavior.
-   If the dependency API is unsafe, discharge its unsafe contract exactly like
    any other unsafe API.

### 3. Caller-provided safe code is not trusted for semantic correctness

The "safe dependencies work as documented" assumption does not apply to caller-provided safe code.

Caller-provided safe code includes, without limitation:

-   safe function arguments
-   closures
-   callbacks
-   function pointers supplied by the caller
-   iterator implementations supplied by the caller
-   safe trait implementations supplied by the caller
-   implementations of `Ord`, `Eq`, `Hash`, `Iterator`, `ExactSizeIterator`,
    `Drop`, `Deref`, `Borrow`, `AsRef`, `Default`, `Clone`, or other safe traits
-   values whose behavior is mediated by caller-controlled interior mutability
-   safe methods reachable through generic type parameters
-   safe code transitively invoked by a dependency through caller-supplied
    callbacks or trait methods

Model caller-provided safe code as adversarial but type-correct. It may:

-   panic at any point where panicking is possible;
-   fail to terminate;
-   return arbitrary values permitted by its type signature;
-   violate safe trait laws such as ordering, equality, hashing, length hints,
    or clone consistency;
-   mutate reachable state through `Cell`, `RefCell`, atomics, locks,
    `UnsafeCell`, global state, or reentrant calls;
-   call back into this crate;
-   observe intermediate states that are exposed to it;
-   drop values at inconvenient times;
-   use safe APIs in unexpected order;
-   exploit every behavior allowed by safe Rust and the public API surface.

Do not assume caller-provided safe code "works as documented" for memory-safety proofs. Safe trait documentation may describe logic contracts, but unsafe code must not rely on a safe trait law for memory safety unless one of the following is true:

1.  the trait is unsafe and the needed law is part of its `# Safety` contract;
2.  the property is checked dynamically before unsafe reliance;
3.  every possible implementation that can reach the unsafe code is
    crate-controlled or comes from a trusted opted-in dependency, and
    downstream/caller code cannot add a new implementation that violates the
    law;
4.  the trait is sealed, and sealing is airtight: downstream crates cannot name,
    implement, forge, or indirectly satisfy the sealing condition, including
    through blanket impls, public fields, public constructors, macros, or
    re-exported marker types;
5.  the type system enforces the property independently of caller honesty.

An unsafe API may explicitly place a caller obligation on the behavior of an otherwise safe implementation. In that case, do not assume the safe trait law for arbitrary caller-provided implementations; instead, quote the unsafe API's precondition and prove that every concrete implementation reachable in this call satisfies it through crate control, a trusted dependency contract, sealing, type-system enforcement, or direct inspection. `Pin::new_unchecked` is a key example: its caller must establish the required behavior of the concrete pointer type's `Deref`, `DerefMut`, and `Drop` implementations. (See also [Safety-usable invariants on safe helpers](#safety-usable-invariants-on-safe-helpers).)

A sealed-trait proof must be mechanical, not aspirational. Documentation saying "do not implement this trait" is not sealing. A public supertrait, public marker type, public token constructor, public blanket impl, re-exported sealing mechanism, or downstream-invoked macro may reopen the implementation set. If downstream safe code can choose, generate, or influence an implementation that violates the law, the implementation is caller-provided for proof purposes.

When relying on a trusted dependency's safe trait implementation, rely on a concrete implementation for a concrete type or a documented closed implementation set. Do not generalize from "this dependency implements the trait correctly for its types" to "an arbitrary caller-provided `T: Trait` satisfies the law."

The abstraction must remain memory-safe even if caller-provided safe code is semantically wrong. Violating safe trait laws may be a logic error by the caller, but it must not become UB caused by this unsafe abstraction.

#### Example: sorting

It is acceptable to rely on the standard library's `Vec::sort` implementation to perform the documented sort operation. It is not acceptable to assume that a caller-provided `Ord` implementation defines a total order for memory-safety purposes. If memory safety depends on the vector being sorted according to a trustworthy relation, then either the relation must be trusted, made unsafe, controlled by this crate, or checked after sorting.

#### Example: iterator length

It is not acceptable to rely on a caller-provided safe `Iterator::size_hint` or `ExactSizeIterator::len` claim for memory safety unless the relevant trait contract is unsafe or the value is checked. A lying safe iterator must not let your unsafe code write out of bounds, read uninitialized memory, set an incorrect length, or double-drop elements.

#### Example: callbacks

It is not acceptable to assume a caller-provided callback will not panic, reenter, mutate global state, mutate aliased state through interior mutability, or violate documented semantic promises. If unsafe code temporarily breaks an invariant, do not call caller-provided safe code until the invariant has been restored or a guard ensures restoration during unwinding.

### 4. Advisory sources

The following sources are explanatory or advisory unless their claims are also entailed by the Reference, std docs, a trusted dependency contract, or an explicit project invariant:

-   Rust API Guidelines
-   Rust standard-library developer guide
-   Clippy documentation
-   Rust Edition Guide
-   RFCs
-   The Rust Book
-   The Rustonomicon
-   Unsafe Code Guidelines material
-   blog posts
-   academic papers
-   issue discussions
-   forum posts
-   Miri documentation
-   sanitizer documentation

Use these sources to improve rigor and style, but do not treat them as final authority for UB, layout, aliasing, validity, or provenance.

### 5. Project-local lemmas and invariants

Project-local invariants may be used as proof premises only if they are explicitly documented and maintained by all constructors, mutators, destructors, trait impls, FFI entry points, and panic paths.

Acceptable project-local premises include:

-   module invariants;
-   type invariants;
-   representation invariants;
-   ownership invariants;
-   initialization invariants;
-   aliasing invariants;
-   pinning invariants;
-   FFI invariants;
-   synchronization invariants;
-   previously documented safety contracts.

Project-local invariants are not self-proving. Every unsafe proof that cites one must name it precisely, and review must verify that the invariant is established and preserved everywhere.

### 6. Local facts

Local facts include facts visible at the program point:

-   branch conditions;
-   runtime checks;
-   values copied into locals;
-   ownership state;
-   initialization state;
-   lifetime relationships;
-   borrow relationships;
-   arithmetic facts;
-   control-flow facts;
-   no-intervening-mutation facts;
-   no-callback/no-reentrancy facts;
-   exact type facts enforced by the compiler.

Local facts are valid only if still true at the unsafe operation. If a fact was checked earlier, the safety comment must explain why it has not been invalidated by mutation, reallocation, aliasing, callbacks, panics, drops, or interior mutability.

## Mandatory fact classification

Every proof-sensitive sentence must be classifiable as one of:

-   `AXIOM`: Rust Reference or standard library documentation.
-   `DEPENDENCY LEMMA`: documented behavior of an intentionally selected safe
    dependency.
-   `PRECONDITION`: documented in a relevant `# Safety` section.
-   `INVARIANT`: documented project-local invariant.
-   `LOCAL FACT`: visible checked condition or control-flow fact.
-   `TYPE FACT`: guaranteed by Rust's type system or by a documented type.
-   `POSTCONDITION`: state established by a preceding operation whose contract
    has already been proved.

Reject any unclassified fact.

A rigorous proof does not have to mechanically label every sentence with these words, but the classification must be obvious. If a reviewer asks "where does this fact come from?", the answer must be immediate and precise.

## Core distinction: documentation vs comments

### Safety documentation

Safety documentation belongs on unsafe APIs and unsafe extension points. It states the theorem that callers or implementers must satisfy.

Examples:

```rust
/// # Safety
///
/// The caller must ensure that ...
pub unsafe fn f(...) -> ...
```

```rust
/// # Safety
///
/// Implementors must ensure that ...
pub unsafe trait T { ... }
```

```rust
/// # Safety
///
/// The caller must ensure that this function is called only when ...
unsafe extern "C" fn callback(...) { ... }
```

### Safety comments

Safety comments belong next to concrete unsafe operations. They prove that the exact operation is valid at the exact program point.

For unsafe attributes, use a safety comment to justify the whole-program, linkage, ABI, symbol, section, or target-feature obligation being asserted.

#### Comment Formatting

*   **Canonical spelling:** Generate `// SAFETY:` immediately before an unsafe operation or `unsafe impl`. This form is recognized by Clippy's `undocumented_unsafe_blocks` lint.
*   **Review significance:** Capitalization or punctuation differences (such as `// Safety`, `/// safety`, or `// safety:`) do not change the semantic adequacy of a safety proof. When a project enables a lint that rejects the local spelling, mention the canonical form as a brief tooling note; do not report it as a soundness defect or let it dominate the review.
*   **Doc Comments**: Safety comments can be regular comments (e.g., `// safety`) or doc comments (e.g., `/// safety`).
*   **Safety Comments on `unsafe impl`**: A doc comment or regular comment placed directly on an `unsafe impl` is a completely acceptable and valid safety comment.
*   **Public API Documentation**: Use `/// # Safety` for the caller or implementer contract on public unsafe functions and traits.

Example:

```rust
// SAFETY:
// Operation: `core::slice::from_raw_parts(ptr, len)`.
// Required contract: `ptr` must be non-null, properly aligned, valid for reads
// of `len * size_of::<T>()` bytes, refer to one allocation, and point to `len`
// initialized `T` values. The memory must not be mutated by any alias for `'a`
// except through nested `UnsafeCell`.
// Evidence:
// - By this function's `# Safety` precondition, the caller provides a live
//   allocation containing `len` initialized `T` values starting at `ptr`.
// - The same precondition requires `ptr` to be non-null and aligned for `T`.
// - `len` was checked above so that `len * size_of::<T>() <= isize::MAX`, and
//   no intervening code mutates `len` or `ptr`.
// - By `# Safety` precondition, the caller guarantees that for the full returned
//   lifetime `'a`, no access path—including pre-existing raw pointers, aliases,
//   callbacks, reentrant code, foreign code, or concurrent agents—will mutate the
//   range except within nested `UnsafeCell` values.
// - Between accepting that precondition and constructing the slice, this function
//   invokes no unknown code and performs no state transition that can invalidate it.
// Therefore all obligations of `from_raw_parts` are discharged.
let s = unsafe { core::slice::from_raw_parts(ptr, len) };
```

Example for unsafe attributes:

```rust
// SAFETY:
// This `export_name` is globally unique in the final linked artifact, and no
// other object defines an incompatible symbol with this name.
#[unsafe(export_name = "my_custom_symbol")]
```

The comment must not merely restate "caller guarantees this." It must show that the caller's documented obligation, plus local facts and invariants, logically implies the callee's documented safety contract.

### Field invariants

If a struct has private fields whose values are constrained by invariants that are necessary for the correctness of unsafe code inside the struct, those invariants must be documented on the fields.

The comment must start with `// Safety invariant:`.

```rust
struct Foo {
    // Safety invariant: `ptr` is non-null and points to a valid `Bar`.
    ptr: *mut Bar,
}
```

Additionally, any safe code that mutates these fields must maintain the invariant, and any such mutation should be documented with a comment explaining how the invariant is maintained.

### Safety-usable invariants on safe helpers

Sometimes, safe helper functions exist to establish or verify invariants. While these are safe to call, unsafe code may rely on their correctness for soundness. In this case, the helper function should document this contract under a `/// # Safety-usable invariant` heading.

```rust
impl Foo {
    /// # Safety-usable invariant
    ///
    /// This function guarantees that the returned index is valid for `self.buffer`.
    fn find_index(&self) -> usize { ... }
}
```

The unsafe code that relies on this helper must then document this in its `// SAFETY:` comment:

```rust
// SAFETY:
// ...
// - Relies on the safety-usable invariant of `find_index` to ensure that
//   the index is in bounds.
```

## Criteria for `# Safety` documentation

A `# Safety` section must satisfy all criteria in this section.

### 1. Name the responsible party

State whether the obligations are on the caller, implementer, linker, host environment, foreign code, whole program, or some combination.

Use this for unsafe functions:

```rust
/// # Safety
///
/// The caller must ensure ...
```

Use this for unsafe traits:

```rust
/// # Safety
///
/// Implementors must ensure ...
```

Do not use vague subjects such as "it must be ensured." Say who must ensure it.

### 2. Be complete enough to imply soundness

The contract must include every precondition needed to prevent UB through this API. A proof reviewer should be able to derive the safety of every internal unsafe operation from:

-   the `# Safety` section;
-   local code facts;
-   documented dependency lemmas;
-   documented project-local invariants;
-   Reference and std axioms.

Do not write:

```rust
/// # Safety
/// The pointer must be valid.
```

Write the exact validity required:

```rust
/// # Safety
///
/// The caller must ensure that `ptr` is non-null, properly aligned for `T`,
/// points to `len` consecutive initialized `T` values, is valid for reads of
/// `len * size_of::<T>()` bytes, and that the entire range lies within a
/// single live allocation.
```

Pointer validity is operation-specific. A pointer is not simply "valid" in the abstract. It may be valid for one kind of access, one byte range, one lifetime, or one aliasing mode, but invalid for another.

### 3. Specify temporal scope

Every obligation must say when it must hold.

Examples:

```rust
/// The memory must remain valid for reads for the entire lifetime `'a` of the
/// returned slice.
```

```rust
/// For the duration in which the returned `&mut T` is relied upon, the pointee
/// must not be accessed through any pointer or reference whose access is not
/// permitted by the applicable mutable-reference rules. `UnsafeCell` does not
/// relax the uniqueness guarantee of `&mut`; it only permits mutation of its
/// contents through shared references.
```

```rust
/// For `!Unpin` data, the pointee must remain pinned in memory (never moved,
/// deallocated, or repurposed without dropping) until its destructor completes.
/// Dropping a temporary `Pin<&mut T>` wrapper does not release this obligation.
```

```rust
/// For this unsafe async function, `ptr` must remain valid until the returned
/// future is dropped or completes.
```

Do not say only "during the call" unless the obligation truly ends before the function returns. Returned references, futures, iterators, guards, trait objects, raw handles, and pinned values often extend obligations beyond the initial call.

### 4. Specify byte ranges, allocation identity, alignment, and initialization

For pointer, slice, buffer, allocation, and FFI APIs, the contract must state every relevant low-level condition:

-   read validity vs write validity;
-   exact byte count;
-   exact element count;
-   alignment for the accessed type;
-   non-nullness;
-   initialization state;
-   Rust value validity for type `T`;
-   allocation liveness;
-   whether the entire range lies in one allocation;
-   provenance or allocation origin when relevant;
-   aliasing and exclusivity;
-   mutation permissions;
-   arithmetic constraints;
-   maximum size constraints such as `isize::MAX`;
-   no address-space wraparound;
-   deallocation layout, allocator identity, and capacity when reconstructing
    ownership.

Example:

```rust
/// # Safety
///
/// The caller must ensure that:
///
/// 1. `ptr` is non-null and aligned for `T` (e.g. `NonNull::dangling()` for ZSTs or zero capacity).
/// 2. If `size_of::<T>() != 0 && cap != 0`, `ptr` was allocated by the global allocator
///    with layout `Layout::array::<T>(cap).unwrap()`, and `cap` is the allocation capacity.
/// 3. The first `len` elements are initialized valid `T` values.
/// 4. `len <= cap`.
/// 5. `cap * size_of::<T>() <= isize::MAX as usize`.
/// 6. No other owner will read, write, drop, or deallocate the allocation after
///    this function takes ownership.
```

### 5. Distinguish validity, initialization, and aliasing

These are separate proof obligations.

A pointer can be:

-   non-null but dangling;
-   live but misaligned;
-   aligned but not initialized;
-   initialized but invalid for type `T`;
-   valid for reads but not writes;
-   valid for writes but not reads of initialized `T`;
-   valid for one byte range but not another;
-   valid at one time but invalid after reallocation or deallocation;
-   valid for raw access but not valid for creating a reference;
-   non-aliasing at one point but aliased after a callback or reentrant call.

Never collapse these into "valid pointer." State each property explicitly when relevant.

### 6. Do not rely on folklore facts

Reject any proof sentence whose source is "everyone knows Rust works this way."

Examples of facts that must be grounded in Reference or std docs:

| Claimed fact                         | Required source               |
| ------------------------------------ | ----------------------------- |
| `bool` has only two valid values     | Rust Reference validity rules |
| a reference must be non-null,        | Rust Reference validity rules |
: aligned, and non-dangling            :                               :
| zero-length slices still need        | `slice::from_raw_parts` /     |
: non-null aligned pointers            : `from_raw_parts_mut` docs     :
| `ptr::read` creates a bitwise copy   | `ptr::read` docs              |
: and can cause double-use issues for  :                               :
: non-`Copy` values                    :                               :
| `ptr::write` does not drop the old   | `ptr::write` docs             |
: value                                :                               :
| unaligned packed-field raw pointer   | `ptr::read_unaligned` docs    |
: creation must avoid an intermediate  :                               :
: reference                            :                               :
| `transmute` requires both source and | `mem::transmute` docs         |
: result to be valid at their types    :                               :
| `Vec::from_raw_parts` requires matching | `Vec` docs                    |
: allocator layout/capacity when `cap > 0`:                               :
: and `size_of::<T>() > 0`; otherwise     :                               :
: non-null aligned pointer & `len <= cap` :                               :
| raw pointer arithmetic has           | primitive pointer docs        |
: same-allocation and `isize`          :                               :
: constraints                          :                               :

The safety proof should cite or paraphrase exact contracts rather than importing informal knowledge.

### 7. Do not impose hidden safety obligations on safe callers

A safe function must not require the caller to uphold unchecked memory-safety preconditions. If such preconditions are required, the function should be `unsafe` or the function should validate the preconditions dynamically.

Public safe API surfaces include more than `pub fn`. Public fields, constructors, safe methods, safe trait methods, and macro-generated APIs all count as safe API surfaces. Treat all of the following as surfaces that safe caller code may use adversarially:

-   public fields;
-   public constructors and builder methods;
-   public safe methods and inherent impls;
-   safe trait methods and safe trait impl surfaces;
-   public macros and proc macros;
-   macro-generated APIs;
-   re-exported APIs;
-   safe callbacks, closures, comparators, allocators, and trait methods
    accepted by public APIs;
-   public types whose auto traits, blanket impls, `Deref`, `Drop`, or interior
    mutability can affect unsafe invariants.

A public field is a safe mutator. A public constructor is a safe invariant-establishing boundary. A macro-generated safe function is still a safe function. If any such surface lets safe caller code create a value or state that later makes internal unsafe code unsound, the abstraction is unsound unless the condition is dynamically checked, made impossible by the type system, or moved behind an unsafe contract.

Bad:

```rust
/// Caller must pass a pointer valid for reads of `len` elements.
pub fn from_ptr<T>(ptr: *const T, len: usize) -> &'static [T] {
    unsafe { core::slice::from_raw_parts(ptr, len) }
}
```

The caller can call this safe function with an invalid pointer. That would let safe code trigger UB. The function is unsound.

Use a different heading for internal invariants of safe types:

```rust
/// # Invariants
///
/// `ptr` is either null or points to an allocation created by `Box<T>`.
```

Do not write a `# Safety` section for a safe API to shift unchecked memory-safety obligations onto a safe caller.

This rule applies to private helper functions as well. Do not rely on module privacy to hide memory-safety preconditions on a safe function. If a private helper function must only be called under certain conditions to prevent UB, mark it `unsafe` and document those conditions under `# Safety`. Do not make it safe and rely on "internal module invariants" without an explicit safety contract, as future changes to the module might violate those invariants.

### 8. Do not strengthen contracts you do not own

For unsafe functions inside traits, the implementation cannot arbitrarily require stricter preconditions than the trait method's contract allows. A caller who satisfies the trait-defined contract must be able to call the implementation soundly.

Bad pattern:

```rust
unsafe trait Trait {
    /// # Safety
    /// Caller must pass any non-null pointer.
    unsafe fn f(ptr: *const u8);
}

struct Impl;

unsafe impl Trait for Impl {
    /// # Safety
    /// Caller must pass a pointer to at least 16 initialized bytes.
    unsafe fn f(ptr: *const u8) {
        // implementation relies on stronger condition
    }
}
```

The implementation has silently strengthened the trait contract. Unsafe code using the trait may call according to the trait contract, not the implementation's private contract. This is unsound unless the trait contract permits the strengthening.

### 9. Separate semantic preconditions from memory-safety preconditions

A function may have ordinary semantic requirements, but memory-safety requirements belong in `# Safety` only if violation can lead to UB.

For safe APIs, semantic preconditions must be handled safely:

-   return `Result`;
-   panic;
-   clamp;
-   ignore;
-   validate;
-   document as a logic error that cannot cause UB.

For unsafe APIs, the `# Safety` section must contain all unchecked memory-safety preconditions. Do not hide memory-safety preconditions in prose under `# Panics`, `# Errors`, examples, type names, module docs, or comments elsewhere.

### 10. Include postconditions when unsafe callers may rely on them

A `# Safety` section should usually state not only what the caller must guarantee, but also what the function guarantees in return when those preconditions hold.

Examples:

```rust
/// If these preconditions hold, the returned slice contains exactly the `len`
/// initialized `T` values starting at `ptr`, and no safe operation on the slice
/// can mutate the memory except through `UnsafeCell`.
```

```rust
/// If these preconditions hold, this function takes exclusive ownership of the
/// allocation and will deallocate it exactly once using the original layout.
```

Postconditions are especially important for unsafe traits and unsafe constructors whose results are later used by safe code or other unsafe proofs.

### 11. Do not rely on the absence of an impl

An `unsafe impl`'s obligation must be discharged with facts that remain true under program extension: new crates, new types, new impls. The impl set of a safe trait is open and extendable by safe code, and the absence of a trait implementation on a type is not such a fact.

The suspect pattern:
```rust
/// # Safety
/// If a type implements both `UnsafeTr` and `SafeTr`, `SafeTr` must behave
/// a certain way.
unsafe trait UnsafeTr {}
```

This conditions an unsafe obligation on the behavior of a safe trait. Whichever impl completes the pair `UnsafeTr + SafeTr` last decides soundness, and the `SafeTr` half can be completed in safe code. Classify as follows.

Bad:

1.  The unsafe trait is dyn-compatible. Downstream safe code may write:

    ```rust
    trait Sub: UnsafeTr {}
    impl SafeTr for dyn Sub { // impl that behaves incorrectly }
    ```
    `dyn Sub: UnsafeTr` holds via the built-in supertrait impl; no `unsafe`
    appears downstream. Reject the contract as designed unless the defining
    crate owns a blanket `impl<T: UnsafeTr + ?Sized> SafeTr for T` (making
    every such downstream impl a coherence error), or the unsafe trait is
    non-dyn-compatible *by construction* — an explicit dyn-incompatible
    supertrait or other property that would be a semver-breaking-change
    to remove. A bare marker trait is dyn-compatible by default.

2.  A blanket `unsafe impl` over a `#[fundamental]` constructor:

    ```rust
    unsafe impl<T: UnsafeTr> UnsafeTr for Box<T> {}
    ```

    No party can discharge this. A downstream crate owning `Local` may
    soundly write `unsafe impl UnsafeTr for Local` (vacuous: `Local` has no
    `SafeTr` impl) and then, because `Box` is fundamental, legally write
    `impl SafeTr for Box<Local>` in safe code. `Box<Local>: UnsafeTr +
    SafeTr` now violates a contract that no single impl broke. Reject
    fundamental blankets under a conditional cross-trait contract unless the
    defining crate owns the matching safe-trait blanket for the same coverage
    (`impl<T: UnsafeTr> SafeTr for Box<T>`).

Iffy (accept, with an explicit label):

3.  Coherence-based negative reasoning about a concrete local type:

    ```rust
    // dyn-incompatible; same safety requirements.
    unsafe trait UnsafeTr: Sized {}

    // SAFETY: `ExampleStruct` has no `SafeTr` impl in this crate, and
    // the orphan rule prevents any other crate from adding one, so the
    // conditional obligation is vacuous.
    unsafe impl UnsafeTr for ExampleStruct {}
    ```

    Sound today, but only because current coherence rules forbid the
    downstream impl. The orphan rule exists to make enforcing coherence easier,
    but it is not a stated soundness guarantee, and active proposals would weaken
    it. Accept only when cases 1 and 2 are absent (non-dyn-compatible unsafe trait,
    no fundamental blankets) and the premise is flagged as orphan-rule-reliant so it
    can be found and re-audited if coherence rules change. Flag as fragile
    and prefer a restructuring below.

Good:

-   Move the constrained behavior into the unsafe trait itself, so each
    `unsafe impl` carries the obligation directly (such as by making `SafeTr`
    a supertrait, or tying the constrained behaviour to an unsafe marker
    trait which is a subtrait of both).
-   Validate dynamically before unsafe reliance (check the returned value,
    then use the checked value).
-   Have the defining crate own the safe trait's impl for the entire
    `T: UnsafeTr + ?Sized` coverage, closing the impl set by coherence.
-   Seal the safe trait, with sealing airtight per the sealing rule.

## Criteria for safety comments

A safety comment (e.g., using `// safety:`, `// SAFETY:`, or doc comment equivalents like `/// safety:`) must answer all five questions in this section, plus any specialized rule that applies to the operation, such as reference creation, FFI, global state, or target-feature-sensitive execution.

### 1. What exact unsafe operation is being justified?

Bad:

```rust
// SAFETY: This is safe.
unsafe { ptr.add(i).read() }
```

Good:

```rust
// SAFETY:
// Justifies both:
// 1. `ptr.add(i)`
// 2. `.read()` from the resulting pointer
unsafe { ptr.add(i).read() }
```

Stricter rule: prefer one unsafe operation per unsafe block. If a block contains multiple unsafe operations, the comment must itemize and prove each one separately.

### 2. What contract is being discharged?

The comment must name the contract source and the relevant obligations.

Example:

```rust
// SAFETY:
// Contract from `ptr::read`: `src` must be valid for reads, properly aligned,
// and point to an initialized `T`.
let value = unsafe { src.read() };
```

For raw pointer arithmetic:

```rust
// SAFETY:
// Contract from `ptr.add`: the offset in bytes must fit in `isize`; if the
// offset is non-zero, the original pointer must be derived from an allocation,
// and the entire range from the original pointer to the result must remain in
// bounds of that allocation without address-space wraparound.
let p = unsafe { ptr.add(i) };
```

Do not merely say "bounds checked above" unless the callee contract is only a bounds obligation. Most pointer operations have allocation, alignment, initialization, provenance, aliasing, and size obligations too.

### 3. Which premises prove the contract?

Every premise must be classified as one of:

-   Rust Reference or std axiom;
-   documented dependency lemma;
-   caller precondition from this function's `# Safety` section;
-   implementer precondition from an unsafe trait's `# Safety` section;
-   documented type invariant;
-   documented module invariant;
-   runtime check;
-   control-flow fact;
-   type-system fact;
-   postcondition from a previous proved operation.

Bad:

```rust
// SAFETY: `i` is in bounds.
let x = unsafe { slice.get_unchecked(i) };
```

Good:

```rust
// SAFETY:
// Contract from `get_unchecked`: `i < slice.len()`.
// Evidence: this branch is reached only after `if i < slice.len()` succeeds.
// `slice` is immutably borrowed and no intervening code can change its length.
// Therefore `i` is a valid element index for `slice` at this call.
let x = unsafe { slice.get_unchecked(i) };
```

### 4. Why do the premises still hold at this program point?

The proof must account for intervening code.

Bad:

```rust
// SAFETY: We checked the length above.
unsafe { v.set_len(len) }
```

Good:

```rust
// SAFETY:
// Contract from `Vec::set_len`: `len <= capacity`, and the first `len`
// elements must be initialized.
// Evidence:
// - `len <= v.capacity()` was checked above.
// - Since that check, no code has mutated, reallocated, or moved `v`.
// - The loop initialized exactly indices `0..len` using `MaybeUninit::write`;
//   the loop counter is local and cannot be changed by external code.
// Therefore the new length exposes only initialized elements and does not exceed
// capacity.
unsafe { v.set_len(len) }
```

Many comments fail because they cite a fact that was true earlier but may have been invalidated by mutation, reallocation, aliasing, callbacks, drops, panics, or interior mutability.

### 5. What state changes after the unsafe operation?

Unsafe comments must document postconditions when the operation changes ownership, initialization, aliasing, lifetime, pinning, or drop obligations.

Example for `ptr::read`:

```rust
// SAFETY:
// Contract from `ptr::read`: `src` is valid for reads, properly aligned, and
// points to an initialized `T`.
// Evidence: ...
// Postcondition: the value at `src` has been bitwise-copied out. Because `T`
// may be non-`Copy`, this code must not later treat the original location as an
// initialized owned `T` unless it is overwritten without first being dropped.
let value = unsafe { src.read() };
```

Postconditions are mandatory for operations such as:

-   `ptr::read`
-   `ptr::write`
-   `ptr::copy` / `copy_nonoverlapping`
-   `MaybeUninit::assume_init`
-   `Vec::set_len`
-   `Vec::from_raw_parts`
-   `Box::from_raw`
-   `slice::from_raw_parts`
-   `mem::transmute`
-   `ManuallyDrop` operations
-   raw allocation or deallocation
-   FFI calls that transfer ownership
-   pin projection
-   partially initialized arrays or buffers

## Auditing procedure for writing safety comments

When adding a `// SAFETY:` comment, follow this step-by-step procedure:

1.  **Identify the unsafe operations**: Locate all `unsafe` blocks, `unsafe fn`
    calls, `unsafe impl`s, or unsafe attributes.
2.  **Determine the safety contracts**: Look up the exact safety contracts for
    each operation in the Rust Reference or standard library documentation. Do
    not guess.
3.  **Audit the surrounding code**: Trace the inputs, lifetime bounds, and state
    transitions of the surrounding code to ensure they satisfy the safety
    contracts.
4.  **Write the proof**: Write the `// SAFETY:` comment, explaining step-by-step
    how the contracts are met using the classified premises (Axioms,
    Preconditions, Invariants, Local Facts).
5.  **Verify**: Re-read the code and the proof to ensure there are no logical
    gaps.

## Required proof topics checklist

For every unsafe site, check whether each topic is relevant. If relevant, the proof must address it explicitly.

| Topic               | What the proof must establish                          |
| ------------------- | ------------------------------------------------------ |
| UB scope            | Safe code cannot trigger UB through this abstraction   |
:                     : without crossing an unsafe contract.                   :
| Operation identity  | The exact unsafe operation or unsafe contract being    |
:                     : discharged is named.                                   :
| Pointer validity    | Operation-specific validity: read/write, byte range,   |
:                     : liveness, provenance/allocation, alignment.            :
| Nullness            | Whether null is permitted; references and slices often |
:                     : require non-null even for zero-size or zero-length     :
:                     : cases when docs say so.                                :
| Alignment           | Alignment for the accessed type, not merely            |
:                     : byte-addressability.                                   :
| Initialization      | Memory contains initialized values where the operation |
:                     : reads or exposes initialized values.                   :
| Type validity       | Values satisfy Rust validity invariants, such as valid |
:                     : discriminants, valid references, valid `bool`, valid   :
:                     : `char`, valid `NonZero*`, and valid enum tags.         :
| Aliasing            | Shared/mutable reference rules, exclusivity,           |
:                     : `UnsafeCell`, raw pointer interleavings, and no        :
:                     : invalid reference creation.                            :
| Reference creation  | Every produced reference or reference-like owner is    |
:                     : valid at creation; narrow creation is preferred but    :
:                     : not sufficient.                                        :
| Mutability          | No mutation through immutable/shared references except |
:                     : through `UnsafeCell`; no mutation of immutable bytes.  :
| Allocation identity | Whole range lies in one allocation when required;      |
:                     : allocator, layout, capacity, and alignment match when  :
:                     : reconstructing ownership.                              :
| Pointer arithmetic  | Same-allocation range, `isize` fit, no wraparound, no  |
:                     : out-of-bounds projection when the API requires         :
:                     : in-bounds.                                             :
| Temporal scope      | Each obligation states what event ends it. Do not infer |
:                     : that dropping a temporary reference, guard, iterator,  :
:                     : future, or `Pin<Ptr>` ends obligations attached to the :
:                     : underlying allocation, pointee, or async operation.    :
| Ownership           | Exactly one owner is responsible for                   |
:                     : drop/deallocation; ownership transfers are explicit.   :
| Drop / destructor   | No double drop, use-after-move, or drop of              |
: elision             : uninitialized storage. Safety must not depend on a     :
:                     : destructor running: safe code may use `mem::forget`,   :
:                     : leak a guard or proxy, or form reference cycles. A     :
:                     : leak may be acceptable; later safe access to invalid   :
:                     : state is not.                                          :
| Panic / unwind      | Treat every call to caller-controlled safe code as a   |
:                     : potential panic and reentrancy point. At each such     :
:                     : point, invariants are either fully restored or         :
:                     : protected so unwinding can leak but cannot expose UB,  :
:                     : double-drop, or invalid state.                         :
| FFI/ABI             | Correct ABI, FFI-safe representations, valid foreign   |
:                     : contracts, unwind behavior, ownership transfer,        :
:                     : retention behavior, callbacks, global state, and       :
:                     : target-platform assumptions.                           :
| Global state        | Global or process-wide state is assumed                |
:                     : concurrent/reentrant unless synchronization or an      :
:                     : explicit out-of-band guarantee proves otherwise.       :
| Configuration       | Every supported                                        |
: matrix              : cfg/feature/target/SIMD/allocator/debug/generated-code :
:                     : combination in scope is sound.                         :
| Concurrency         | No data races; atomics, locks, or other                |
:                     : synchronization justify shared mutation.               :
| Memory ordering /   | When atomics publish data or transfer ownership        |
: happens-before      : between threads, identify the precise synchronization  :
:                     : edge (e.g. Release store synchronizes-with Acquire     :
:                     : load), the data it orders, and why the chosen          :
:                     : orderings establish the needed happens-before          :
:                     : relationship.                                          :
| Mixed-size /        | When atomic and non-atomic accesses, or differently    |
: overlapping atomics : sized atomic accesses, may refer to overlapping bytes,  :
:                     : prove the access pattern is permitted by the           :
:                     : documented memory model. Do not infer safety merely    :
:                     : from each individual operation being atomic.           :
| Mutex poisoning     | Mutex and RwLock poisoning is advisory. If memory      |
:                     : safety depends on a lock-protected invariant, prove    :
:                     : the invariant is restored or inaccessible after a      :
:                     : panic without assuming poisoning always occurs or is   :
:                     : always checked.                                        :
| Generic wrapper     | For a type that logically borrows, owns, or may drop   |
: semantics           : data not represented by ordinary Rust fields, verify   :
:                     : that its inferred variance, `PhantomData` markers, and :
:                     : drop-check behavior match the real lifetime and        :
:                     : ownership contract.                                    :
| Reentrancy          | Caller-provided callbacks or trait methods cannot      |
:                     : observe or exploit broken intermediate invariants.     :
| Safe trait laws     | Unsafe code does not rely on caller-provided safe      |
:                     : trait implementations being semantically correct.      :
| Dependency trust    | Any reliance on safe dependency semantics is           |
:                     : deliberate, documented when proof-relevant, and does   :
:                     : not extend to caller-supplied code.                    :
| Traits              | Unsafe trait implementer obligations are satisfied and |
:                     : not silently strengthened.                             :
| Pinning             | Identify the pointee and the event that ends its        |
:                     : pinning guarantee—commonly destruction of the          :
:                     : pointee. Dropping a temporary `Pin<&mut T>` handle     :
:                     : alone does not make the pointee movable. Projection    :
:                     : and pinned-drop rules remain satisfied for the full    :
:                     : required duration.                                     :
| Layout/repr         | Any layout assumption is guaranteed by `repr`,         |
:                     : Reference, or std docs, not compiler accident.         :
| Nested layout /     | A direct representation guarantee for `A` and `B` does  |
: niches              : not automatically imply that `Outer<A>` and `Outer<B>` :
:                     : have the same layout, ABI, niches, or transmutability. :
:                     : Prove the enclosing representation from its own `repr` :
:                     : and documented guarantees. In particular, account for  :
:                     : niche suppression by `UnsafeCell`.                     :
| Padding / object    | When code reads, compares, hashes, serializes,          |
: representation      : transmutes, or attempts to preserve a value's raw      :
:                     : bytes, prove that every observed byte is permitted to  :
:                     : be read and that no claim depends on padding being     :
:                     : initialized or preserved unless an authoritative       :
:                     : contract guarantees it.                                :
| Niche/validity      | Non-null/aligned/reference validity assumptions are    |
: optimizations       : respected even when data length is zero.               :
| Integer arithmetic  | Size computations are checked for overflow and         |
:                     : documented as mathematical-integer facts where APIs    :
:                     : require that.                                          :
| Interior mutability | `UnsafeCell`, `Cell`, `RefCell`, atomics, locks, and   |
:                     : global state are accounted for.                        :

## Core axiom lookup discipline

When a proof relies on a Rust fact, trace it to the relevant Reference or std documentation.

### Undefined behavior and validity

Use the Rust Reference for:

-   the list of behavior considered undefined;
-   the fact that the UB list is not necessarily exhaustive;
-   dangling or misaligned place access;
-   breaking pointer aliasing rules;
-   mutating immutable bytes;
-   producing invalid values;
-   validity requirements for primitive types;
-   validity requirements for references and `Box`;
-   validity requirements for arrays, tuples, structs, and enums;
-   layout facts guaranteed by `repr` attributes.

Example proof phrasing:

```rust
// AXIOM: The Reference requires a `bool` value to be either `0` or `1`.
// Evidence: `b` was produced by comparing two integers, not by reading raw
// bytes as `bool`. Therefore `b` is a valid `bool`.
```

### Standard-library unsafe contracts

Use the std docs for exact contracts of standard-library unsafe APIs. Do not approximate.

Common APIs that require exact contract extraction:

-   `core::slice::from_raw_parts`
-   `core::slice::from_raw_parts_mut`
-   raw pointer `read`, `write`, `copy`, `copy_nonoverlapping`
-   raw pointer `add`, `sub`, `offset`, `offset_from`
-   `core::ptr::read_unaligned`
-   `core::mem::transmute`
-   `MaybeUninit::assume_init`
-   `Vec::set_len`
-   `Vec::from_raw_parts`
-   `Box::from_raw`
-   `CString::from_raw`
-   `Arc::from_raw`
-   `Rc::from_raw`
-   allocator APIs
-   `Pin::new_unchecked`
-   `Pin::map_unchecked` and related projection APIs
-   `NonNull::new_unchecked`
-   `str::from_utf8_unchecked`
-   unchecked indexing APIs
-   SIMD and target-feature APIs

For each such call, copy the contract into proof obligations and discharge them one by one.

## Reject patterns

The following patterns should fail review.

### 1. "Pointer is valid"

Reject:

```rust
// SAFETY: `ptr` is valid.
unsafe { ptr.read() }
```

Require:

```rust
// SAFETY:
// Contract from `ptr::read`: `ptr` must be properly aligned, valid for reads of
// `size_of::<T>()` bytes, and point to an initialized `T`.
// Evidence:
// - ...
```

For slices or ranges, require the full range:

```rust
// SAFETY:
// `ptr` is non-null, aligned for `T`, valid for reads of
// `len * size_of::<T>()` bytes, points to `len` initialized `T`s, and the full
// range lies in one live allocation.
```

### 2. "Caller guarantees it"

Reject:

```rust
// SAFETY: The caller guarantees this.
unsafe { callee(ptr, len) }
```

Require:

```rust
// SAFETY:
// Contract from `callee`: requires P, Q, and R.
// By this function's `# Safety` contract, the caller guarantees P and Q.
// Local check `len <= cap` plus invariant I imply R.
// No intervening code can invalidate P, Q, or R.
// Therefore all obligations of `callee` are satisfied.
unsafe { callee(ptr, len) }
```

### 3. "Miri passes"

Reject as proof:

```rust
// SAFETY: Miri passes.
unsafe { ... }
```

Miri, fuzzing, sanitizers, tests, model checking, and examples are bug-finding or confidence-building tools. They are not axioms and do not replace a proof.

Acceptable use:

```rust
// Not a proof premise: Miri tests cover this path. The proof is above.
```

### 4. "Zero length means null is fine"

Reject for slice references:

```rust
// SAFETY: `len == 0`, so null is okay.
let s = unsafe { core::slice::from_raw_parts(core::ptr::null(), 0) };
```

The standard-library slice constructors require non-null aligned pointers even for zero-length slices and ZSTs. Use a proper dangling-but-non-null aligned pointer where the API permits it.

### 5. Packed field address through intermediate reference

Reject:

```rust
let p = &packed.field as *const Field;
let value = unsafe { p.read_unaligned() };
```

Creating the intermediate reference to a packed field may itself violate alignment requirements. Use raw address-of syntax when forming a raw pointer for unaligned access:

```rust
let p = &raw const packed.field;
let value = unsafe { p.read_unaligned() };
```

### 6. "Transmute because same size"

Reject:

```rust
// SAFETY: Same size.
let b: B = unsafe { core::mem::transmute::<A, B>(a) };
```

Require proof that:

-   source and destination have the same size;
-   the source value is valid at type `A`;
-   the resulting bits are valid at type `B`;
-   alignment and layout assumptions are documented;
-   pointer/integer provenance assumptions are valid;
-   ownership and drop obligations are not duplicated or lost;
-   there is no safer conversion.

`transmute` is a last-resort operation. Same size is necessary but not sufficient.

#### Non-Compositionality of Niches and Outer Layouts

Never assume that layout equivalence of inner types composes to outer types:
- Although `UnsafeCell<T>` and `MaybeUninit<T>` have identical size and alignment to `T`, wrapping `T` inside them inhibits or changes niche optimizations for enclosing types.
- For example, `Option<core::ptr::NonNull<u8>>` is 8 bytes due to null-pointer niche optimization, whereas `Option<core::cell::UnsafeCell<core::ptr::NonNull<u8>>>` or `Option<core::mem::MaybeUninit<core::ptr::NonNull<u8>>>` may be 16 bytes.
- Transmuting between `Outer<T>` and `Outer<UnsafeCell<T>>` or `Outer<MaybeUninit<T>>` is unsound unless the layout of the entire outer type is explicitly proved.

#### Padding and Raw Byte Access

When code reads, compares, hashes, serializes, or transmutes raw struct bytes:
- Padding bytes are uninitialized by default and not preserved across typed moves/copies.
- Reading or hashing `size_of::<T>()` raw bytes behind `&T` is invalid whenever `T` contains uninitialized padding.
- Fieldwise operations should be preferred over whole-object raw byte operations.

### 7. "Vec owns this pointer"

Reject:

```rust
// SAFETY: This came from a Vec.
let v = unsafe { Vec::from_raw_parts(ptr, len, cap) };
```

Require proof of:

-   **When `size_of::<T>() != 0 && cap != 0`**:
    -   original allocator identity;
    -   exact allocation layout (`Layout::array::<T>(cap)`);
    -   alignment equality, not merely compatibility;
    -   capacity from the original allocation;
    -   allocation size constraints (`cap * size_of::<T>() <= isize::MAX as usize`);
-   **When `size_of::<T>() == 0 || cap == 0`**:
    -   `ptr` is non-null and suitably aligned for `T` (e.g. `NonNull::dangling()`);
    -   no heap allocation required;
-   **In all cases**:
    -   `len <= cap`;
    -   first `len` elements initialized;
    -   ownership transfer;
    -   no other owner will use or deallocate the allocation;
    -   no double-drop or use-after-free path.

#### Sequencing Ownership Transfer

Prefer a consuming standard-library or project API such as `into_raw` or `into_raw_parts` that ends the old ownership state while yielding the raw components.

When manual extraction is unavoidable, disable the old owner's automatic `Drop` (e.g. using `std::mem::ManuallyDrop`) before constructing any replacement owner. After the replacement owner exists, do not read, move, pass, forget, or otherwise use the invalidated old value. Audit every possible panic and early-return point: failure may leak, but must not create two destructors for the same resource or permit access through an invalid owner.

### 8. Safe trait law relied on for memory safety

Reject:

```rust
// SAFETY: `iter.len()` tells us exactly how many elements will be yielded.
unsafe {
    write_items_without_capacity_checks(iter, dst, iter.len());
}
```

A caller-provided safe trait implementation may lie unless the property is enforced by an unsafe trait contract, trusted dependency implementation, dynamic validation, or the type system.

Require:

```rust
// SAFETY:
// This proof does not rely on caller-provided `ExactSizeIterator::len` for
// memory safety. Capacity is checked before every write, and `set_len` is called
// only for the number of elements actually initialized.
```

### 9. Callback cannot panic or reenter

Reject:

```rust
// SAFETY: The callback just fills the buffer.
callback(&mut tmp);
unsafe { tmp.set_len(n) }
```

A caller-provided safe callback may panic, reenter, or mutate reachable state through safe mechanisms. If invariants are temporarily broken, use guards or avoid callbacks until invariants are restored.

### 10. Dependency trust confused with caller trust

Reject:

```rust
v.sort_by(caller_comparator);
// SAFETY: `Vec::sort_by` sorts the vector, so binary search invariants hold.
unsafe { rely_on_sortedness_for_memory_safety(&v) }
```

`Vec::sort_by` may be trusted as a std dependency, but the caller-provided comparator is not trusted for memory-safety-relevant semantic correctness. If sortedness is memory-safety-critical, validate it or require an unsafe contract.

## Safe dependency and caller-provided code review rules

### Rule A: Intentionally selected safe dependencies may be trusted as documented

When this crate intentionally uses a safe dependency API, the proof may assume the API behaves as documented.

Examples:

```rust
let mut v = vec![3, 1, 2];
v.sort();
// A proof may assume the standard library sort implementation performs its
// documented operation, subject to the behavior of the `Ord` implementation.
```

```rust
let n = trusted_dependency::parse_header(bytes)?;
// A proof may rely on `parse_header` returning the documented result if this
// crate has intentionally chosen and audited/trusted that dependency contract.
```

However, this is a project trust assumption. It should be explicit when proof-relevant and should be version-aware for third-party dependencies.

### Rule B: Caller-provided safe code is adversarial

Do not rely on caller-provided safe code for memory-safety-relevant semantics.

Examples of invalid assumptions:

```rust
// Invalid for safety: caller-provided `Ord` is a total order.
T: Ord
```

```rust
// Invalid for safety: caller-provided `Iterator::size_hint` is accurate.
iter.size_hint()
```

```rust
// Invalid for safety: caller-provided `Hash` is consistent with `Eq`.
T: Hash + Eq
```

```rust
// Invalid for safety: caller-provided `Clone` returns an equivalent value.
x.clone()
```

```rust
// Invalid for safety: caller-provided callback will not panic.
f()
```

```rust
// Invalid for safety: caller-provided `Drop` has no side effects.
drop(x)
```

### Rule C: Safe trait laws are not safety contracts

A safe trait's documentation may impose semantic laws, but violating those laws must not cause UB in your unsafe abstraction. If unsafe code must rely on a law, make the trait unsafe, use an existing unsafe trait with the required contract, validate dynamically, or constrain implementations to trusted types.

#### Sealed-trait reliance must be airtight

A sealed safe trait may be treated as trusted only if the proof establishes that all implementations are controlled by this crate or by a trusted opted-in dependency. "This trait is sealed" is itself a proof obligation, not a conclusion.

For a sealed-trait argument to discharge a memory-safety obligation, prove all of the following:

-   downstream crates cannot implement the trait directly;
-   downstream crates cannot implement the trait indirectly through a public
    supertrait, blanket impl, associated type escape hatch, marker type,
    macro-generated impl hook, feature-gated impl hook, re-exported private
    token, or type alias;
-   downstream safe code cannot construct, name, clone, deserialize, or otherwise
    obtain any sealing token through any safe public surface;
-   public fields, public constructors, re-exports, macros, proc macros, or
    generated code cannot create values that claim the sealed invariant without
    going through reviewed constructors;
-   every cfg and feature combination preserves sealing;
-   every existing implementation that can reach the unsafe code is reviewed and
    maintains the required invariant;
-   future implementations are forced through the same unsafe-code review gate,
    for example by being inside the crate or inside a reviewed trusted
    dependency;
-   future semver-compatible implementation additions, feature additions, or
    macro expansion changes cannot silently admit dishonest downstream behavior
    without forcing re-audit;
-   the semantic law being relied on is documented as an invariant of the sealed
    trait, even if the trait itself is safe;
-   the proof does not rely on caller-controlled generic parameters inside the
    implementation unless those parameters are constrained by an unsafe
    contract, dynamic checks, type-system facts, or trusted dependency
    implementations.

Do not require an abstraction to remain sound after downstream unsafe code forges an invalid token with `transmute` or otherwise violates an unsafe contract. A project may separately review robustness against hostile unsafe clients or corrupted FFI input, but that is not part of the ordinary safe-client sealing proof.

If sealing is not airtight, treat the implementation as caller-provided safe code. Then the law is not a valid memory-safety premise unless it is dynamically checked, moved into an unsafe trait contract, or avoided entirely.

A private trait is not automatically sealed for review purposes. Check macro expansion, feature gates, visibility boundaries, re-exports, blanket impls, and downstream extension points before relying on private or sealed status. A safe trait method with a default body is still caller-influenced if downstream code can implement the trait, override methods, choose associated types/constants, or provide values that the default method uses to establish a memory-safety-relevant fact.

### Rule D: Dependencies invoking caller code inherit caller-code distrust

If a trusted dependency calls a caller-provided closure, comparator, allocator, trait method, or callback, the dependency's trust does not make that caller-provided code trustworthy.

Proofs must separate:

```text
Trusted: dependency implementation follows its documented behavior.
Untrusted: caller-provided callback or trait implementation may behave arbitrarily within its safe type signature.
```

### Rule E: Safe code may be safe but still hostile to invariants

Safe caller-provided code cannot be assumed to preserve your undocumented invariants. It may observe or mutate through any safe capability you give it. Therefore:

-   Do not expose uninitialized or partially initialized storage to caller code as
    initialized `T`, `&T`, `&mut T`, `[T]`, or any other type whose validity
    requires initialization. Typed exposure as `MaybeUninit<T>` (e.g.
    `Vec::spare_capacity_mut`) may be sound when the API keeps initialized
    length/ownership metadata accurate and does not let safe caller actions cause
    uninitialized storage to be read, dropped, or otherwise treated as `T`.
-   Do not call callbacks while `Vec::len` is inconsistent with initialized
    elements.
-   Do not hold invalid references across calls to unknown code.
-   Do not assume locks, refcells, or globals remain unchanged across unknown
    calls.
-   Do not assume unknown `Drop` implementations are inert.
-   Do not assume unknown trait methods are deterministic.

## Reference creation is the unsafe operation

Creating a Rust reference-like value from raw parts is itself a safety assertion. The operation being justified is not merely the later load, store, slice access, or method call. The proof must establish that the reference-like value is valid at the exact moment it is created.

This applies to creating or reconstructing:

-   `&T`;
-   `&mut T`;
-   `&[T]`;
-   `&mut [T]`;
-   `&str`;
-   `&CStr`;
-   `Box<T>`;
-   `Pin<&mut T>` or `Pin<Box<T>>`;
-   trait-object references;
-   any other value whose type carries Rust reference, ownership, aliasing,
    lifetime, or validity guarantees.

The proof for reference creation must establish every relevant obligation at creation time:

-   non-nullness where the reference-like type requires it;
-   alignment for the referenced type;
-   all pointed-to bytes are in live allocations for the full referenced extent;
-   initialization and Rust value validity for the referenced type;
-   correct metadata for slices and trait objects;
-   no violation of shared-reference immutability rules;
-   no violation of mutable-reference exclusivity rules;
-   the referenced value outlives the produced lifetime;
-   the resulting reference does not overstate the real ownership, pinning,
    lifetime, or mutation permissions.

Prefer the narrowest reference possible, created as late as possible, and held for the shortest possible lifetime. Do not create a broad `&mut [T]` merely to access one element. Do not create a reference if raw pointer operations can express the actual invariant more honestly.

Narrowness is only an auditing discipline. A narrow reference must still be valid at the point of creation. A one-element `&mut T` is unsound if another live reference aliases that element. A zero-length slice reference may still need a non-null aligned pointer if the constructor's documented contract requires it. A short-lived reference to uninitialized, invalid, misaligned, dangling, or aliased memory is still UB.

Do not accept a proof that says only "the reference is as narrow as possible." That proves at most that the author reduced the size of the assertion. It does not prove that the assertion is true. The proof must still establish each validity, aliasing, lifetime, and metadata obligation at creation time.

`UnsafeCell` is not a general aliasing eraser. It permits interior mutation through shared references only for a pointed-to `UnsafeCell` value itself. A shared reference `&T` where `T` contains `UnsafeCell` allows mutating the cell contents safely (e.g. via `Cell::set`), but creating `&mut T` while a shared `&T` exists is still undefined behavior, even if no code reads or writes the `UnsafeCell`. Similarly, mutating a shared reference value directly without going through `UnsafeCell` is UB.
