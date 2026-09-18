import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const source = readFileSync(resolve("src/auth.ts"), "utf8");
const mainSource = readFileSync(resolve("src/main.tsx"), "utf8");
assert.match(source, /"Authorization": `Bearer \$\{credential\}`/);
assert.match(source, /"x-portalis-password": credential/);
assert.match(source, /credential\s+\?/);
assert.match(source, /removeItem\(credentialStorageKey\)/);
assert.match(mainSource, /password or setup token/i);
assert.match(mainSource, /密码或 setup token/);
assert.match(mainSource, /!options\.retrying && options\.onPasswordRequired/);

console.log("auth regression: ok");
