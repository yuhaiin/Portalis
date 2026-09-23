import assert from "node:assert/strict";
import {
  buildRequestHeaders,
  forgetCredential,
  readCredential,
  recoverCredential,
  waitForCredential,
} from "../src/auth.ts";

class MemoryStorage {
  values = new Map();

  getItem(key) {
    return this.values.get(key) ?? null;
  }

  setItem(key, value) {
    this.values.set(key, value);
  }

  removeItem(key) {
    this.values.delete(key);
  }
}

const headers = buildRequestHeaders("<REDACTED>", {
  "x-client-header": "preserved",
});
assert.equal(headers.get("authorization"), "Bearer <REDACTED>");
assert.equal(headers.get("x-portalis-password"), "<REDACTED>");
assert.equal(headers.get("x-client-header"), "preserved");
assert.equal(headers.get("content-type"), "application/json");

const noCredential = buildRequestHeaders(null);
assert.equal(noCredential.get("authorization"), null);

const storage = new MemoryStorage();
storage.setItem("portalis-credential", "new-credential");
forgetCredential(storage, "old-credential");
assert.equal(readCredential(storage), "new-credential");
forgetCredential(storage, "new-credential");
assert.equal(readCredential(storage), null);

let release;
let promptCalls = 0;
const recovery = recoverCredential(storage, async () => {
  promptCalls += 1;
  return new Promise((resolve) => {
    release = resolve;
  });
});
const waitingCredential = waitForCredential(storage);
await Promise.resolve();
assert.equal(promptCalls, 1);
release("recovered-credential");
assert.equal(await recovery, "recovered-credential");
assert.equal(await waitingCredential, "recovered-credential");
assert.equal(promptCalls, 1);

console.log("auth regression: ok");
