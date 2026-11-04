import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    workspaceId: user.workspaceId,
    profile: { ...user.profile },
  };
}

export function signIn(store, email, password) {
  const user = [...store.users.values()].find((entry) => entry.email === email);
  if (!user || typeof password !== "string") return null;
  const actual = scryptSync(password, user.password.salt, 32);
  if (!timingSafeEqual(actual, Buffer.from(user.password.hash, "hex")))
    return null;
  const token = randomBytes(32).toString("hex");
  store.sessions.set(token, {
    userId: user.id,
    expiresAt: Date.now() + 8 * 60 * 60 * 1000,
  });
  return token;
}

export function sessionUser(store, cookie = "") {
  const token = cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("session="))
    ?.slice(8);
  const session = store.sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    store.sessions.delete(token);
    return null;
  }
  return store.users.get(session.userId) ?? null;
}

export function signOut(store, cookie = "") {
  const token = cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("session="))
    ?.slice(8);
  store.sessions.delete(token);
}

export function updateProfile(user, fields) {
  Object.assign(user.profile, fields);
  return publicUser(user);
}
