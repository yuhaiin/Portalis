import assert from "node:assert/strict";
import { buildRequestHeaders } from "../src/auth.ts";

const headers = buildRequestHeaders("<REDACTED>", { "x-client-header": "preserved" });
assert.equal(headers.get("authorization"), "Bearer <REDACTED>");
assert.equal(headers.get("x-portalis-password"), "<REDACTED>");
assert.equal(headers.get("x-client-header"), "preserved");
assert.equal(headers.get("content-type"), "application/json");

const noCredential = buildRequestHeaders(null);
assert.equal(noCredential.get("authorization"), null);

console.log("auth regression: ok");
