// Tests for the TypeScript runner. Build first (npm run build), then: npm test
//
// The adapters under test are Python programs, so a python3 with `cryptography` and `jcs`
// must be on PATH (or named in $PYTHON).

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const CLI = path.join(ROOT, "runner", "ts", "dist", "cli.js");
const PY = process.env.PYTHON ?? "python3";
const REFERENCE = `${PY} ${path.join(ROOT, "adapters", "python-reference", "adapter.py")}`;
const FAULTY = path.join(ROOT, "runner", "test-adapters", "faulty.py");
const SKELETON_JS = path.join(ROOT, "adapters", "skeleton-js", "adapter.mjs");

const faulty = (mode) => `${PY} ${FAULTY} ${mode}`;

function run(impl, ...args) {
  const r = spawnSync(process.execPath, [CLI, "--impl", impl, ...args],
    { cwd: ROOT, encoding: "utf8", timeout: 300_000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

const summary = (out) => out.trim().split("\n").at(-1);

test("reference adapter passes all 83", () => {
  const report = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aae-")), "report.json");
  const { code, out } = run(REFERENCE, "--json", report);
  assert.equal(code, 0, out);
  assert.equal(summary(out), "83/83 passed");
  assert.match(out, /^native {3}15\/15 passed$/m);
  assert.match(out, /^enforce {2}26\/26 passed$/m);
  assert.match(out, /^resume {3}42\/42 passed$/m);
  const data = JSON.parse(fs.readFileSync(report, "utf8"));
  assert.equal(data.ok, true);
  assert.equal(data.runner, "typescript");
  assert.deepEqual(data.families, {
    native: { passed: 15, total: 15 }, enforce: { passed: 26, total: 26 },
    resume: { passed: 42, total: 42 },
  });
});

test("wrong answers fail every vector with exit 1", () => {
  const { code, out } = run(faulty("wrong-result"));
  assert.equal(code, 1);
  assert.equal(summary(out), "0/83 passed");
  assert.ok(out.includes('result "REJECT", expected "ACCEPT"'));
  assert.ok(out.includes('verdict "DENY", expected "PERMIT"'));
});

test("resume vectors fail as native and as enforce requests", () => {
  const { code, out } = run(faulty("wrong-result"), "--family", "resume");
  assert.equal(code, 1);
  assert.equal(summary(out), "0/42 passed");
  assert.ok(out.includes('verdict "PERMIT", expected "DENY"'));
  assert.ok(out.includes('result "ACCEPT", expected "REJECT"'));
});

test("a wrong digest fails every record", () => {
  const { code, out } = run(faulty("wrong-digest"), "--family", "enforce");
  assert.equal(code, 1);
  assert.equal(summary(out), "2/26 passed");
});

test("key-order dependence is caught", () => {
  const { code, out } = run(faulty("key-order"), "--family", "enforce");
  assert.equal(code, 1);
  assert.ok(out.includes("canonicalization is not RFC 8785"));
  assert.equal(summary(out), "5/26 passed");
});

for (const [mode, message] of [
  ["malformed", "stdout is not a single JSON value: this is not JSON"],
  ["empty", "stdout is empty"],
  ["not-object", "response is not a JSON object"],
  ["crash", "exited with status 3 (stderr: adapter blew up on purpose)"],
  ["error", "implementation returned an error: not implemented"],
]) {
  test(`protocol violation: ${mode}`, () => {
    const { code, out } = run(faulty(mode), "--vector", "aae-vector-01",
      "--vector", "aae-enforce-vector-01");
    assert.equal(code, 1);
    assert.equal(out.split(message).length - 1, 2, out);
    assert.equal(summary(out), "0/2 passed");
  });
}

test("a generic error is not a caller error", () => {
  const { code, out } = run(faulty("error"), "--vector", "24-", "--vector", "25-");
  assert.equal(code, 1);
  assert.equal(summary(out), "0/2 passed");
});

test("missing required members", () => {
  const { out } = run(faulty("missing-field"), "--vector", "aae-vector-01",
    "--vector", "aae-enforce-vector-01");
  assert.ok(out.includes("response.verification_step missing"));
  assert.ok(out.includes("response.core_digest missing"));
});

test("timeout", () => {
  const start = Date.now();
  const { code, out } = run(faulty("timeout"), "--vector", "aae-vector-01", "--timeout", "1");
  assert.ok(Date.now() - start < 20_000);
  assert.equal(code, 1);
  assert.ok(out.includes("timed out after 1s"));
});

test("missing executable", () => {
  const { code, out } = run("/nonexistent/aae-impl", "--vector", "aae-vector-01");
  assert.equal(code, 1);
  assert.ok(out.includes("could not start the implementation: No such file or directory"));
});

for (const [args, message] of [
  [["--vector", "no-such-vector"], "no vectors selected"],
  [["--timeout", "0"], "--timeout must be positive"],
  [["--vectors-root", "/nonexistent"], "--vectors-root"],
  [["--family", "composition"], "invalid choice"],
]) {
  test(`usage error: ${args.join(" ")}`, () => {
    const { code, err } = run(REFERENCE, ...args);
    assert.equal(code, 2);
    assert.ok(err.includes(message), err);
  });
}

test("unterminated quote is a usage error", () => {
  const { code, err } = run("python3 'unterminated");
  assert.equal(code, 2);
  assert.ok(err.includes("--impl"));
});

test("the JS skeleton fails cleanly", () => {
  const { code, out } = run(`${process.execPath} ${SKELETON_JS}`);
  assert.equal(code, 1);
  assert.equal(summary(out), "0/83 passed");
  assert.ok(out.includes("implementation returned an error: not implemented"));
  assert.ok(!out.includes("exited with status"));
});
