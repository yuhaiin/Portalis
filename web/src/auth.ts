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

export function buildRequestHeaders(credential: string | null, initHeaders?: HeadersInit): Headers {
  const headers = new Headers(initHeaders);
  headers.set("content-type", "application/json");
  for (const [name, value] of Object.entries(authHeaders(credential))) {
    headers.set(name, value);
  }
  return headers;
}
