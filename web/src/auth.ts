export const credentialStorageKey = "portalis-credential";
const legacyPasswordStorageKey = "portalis-password";

export function readCredential(storage: Pick<Storage, "getItem">): string | null {
  return storage.getItem(credentialStorageKey) || storage.getItem(legacyPasswordStorageKey);
}

export function rememberCredential(storage: Pick<Storage, "setItem">, credential: string): void {
  storage.setItem(credentialStorageKey, credential);
}

export function forgetCredential(storage: Pick<Storage, "removeItem">): void {
  storage.removeItem(credentialStorageKey);
  storage.removeItem(legacyPasswordStorageKey);
}

export function authHeaders(credential: string | null): Record<string, string> {
  return credential
    ? { "Authorization": `Bearer ${credential}`, "x-portalis-password": credential }
    : {};
}
