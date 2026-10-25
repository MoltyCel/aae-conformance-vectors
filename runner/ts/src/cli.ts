#!/usr/bin/env node
// TypeScript runner for the AAE conformance vectors.
//
// The protocol is specified in docs/RUNNER-PROTOCOL.md. In short: for every vector the
// runner starts the implementation under test once, writes one JSON request to its stdin,
// reads one JSON response from its stdout, and compares the fields the protocol names
// against the vector's `expected` object. Output and exit codes are identical to the
// Python runner under runner/python/.
//
// Node 20+, no runtime dependencies.

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const RUNNER_NAME = "typescript";
const RUNNER_VERSION = "1.0.0";
const PROTOCOL = "aae-conformance-runner/1";
const DEFAULT_TIMEOUT = 10;
const NAME_WIDTH = 58;

const NATIVE_RESULTS = ["ACCEPT", "REJECT"];
const VERDICTS = ["PERMIT", "DENY", "PENDING"];
const STATUSES = ["RATIFIED", "REJECTED"];

const EXIT_OK = 0;
const EXIT_FAIL = 1;
const EXIT_USAGE = 2;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };
type Family = "native" | "enforce";

interface Vector {
  id: string;
  section_ref: string;
  kernel?: string;
  kernel_version?: string;
  domain_tags?: JsonObject;
  input: JsonObject;
  expected: JsonObject;
}

interface Entry {
  family: Family;
  file: string;
  vector_id: string;
  kernel: string | null;
  status: "PASS" | "FAIL";
  outcome: string | null;
  failures: string[];
  expected: JsonObject;
  response: JsonObject | null;
  response_keys_reversed?: JsonObject | null;
}

class UsageError extends Error {}

// ------------------------------------------------------------------------- JSON helpers

function j(value: Json | undefined): string {
  return JSON.stringify(value === undefined ? null : value);
}

function isObject(x: unknown): x is JsonObject {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function has(obj: JsonObject, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function get(obj: JsonObject, key: string): Json {
  return has(obj, key) ? obj[key] : null;
}

/** Strict JSON equality: true is not 1, numbers compare by value, key order is ignored. */
function jsonEqual(a: Json, b: Json): boolean {
  if (typeof a === "boolean" || typeof b === "boolean") return a === b;
  if (typeof a === "number" || typeof b === "number") return a === b;
  if (a === null || b === null) return a === b;
  if (typeof a === "string" || typeof b === "string") return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length &&
      a.every((x, i) => jsonEqual(x, b[i]));
  }
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i]) &&
    ka.every((k) => jsonEqual(a[k], b[k]));
}

/** The same JSON value with every object's keys in reverse order (as the reference
 * verifier's `reordered`). An RFC 8785 implementation computes the same digest from it. */
function keysReversed(obj: Json): Json {
  if (Array.isArray(obj)) return obj.map(keysReversed);
  if (isObject(obj)) {
    const out: JsonObject = {};
    for (const k of Object.keys(obj).reverse()) out[k] = keysReversed(obj[k]);
    return out;
  }
  return obj;
}

// ------------------------------------------------------------------------- command line

/** Split a command like Python's shlex.split (POSIX rules, no expansion). */
function shellSplit(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inToken = false;
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (" \t\r\n".includes(c)) {
      if (inToken) {
        out.push(cur);
        cur = "";
        inToken = false;
      }
      i++;
      continue;
    }
    inToken = true;
    if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end < 0) throw new UsageError("--impl: No closing quotation");
      cur += s.slice(i + 1, end);
      i = end + 1;
    } else if (c === '"') {
      i++;
      let closed = false;
      while (i < s.length) {
        const d = s[i];
        if (d === '"') {
          closed = true;
          i++;
          break;
        }
        if (d === "\\" && i + 1 < s.length && (s[i + 1] === '"' || s[i + 1] === "\\")) {
          cur += s[i + 1];
          i += 2;
          continue;
        }
        cur += d;
        i++;
      }
      if (!closed) throw new UsageError("--impl: No closing quotation");
    } else if (c === "\\") {
      if (i + 1 >= s.length) throw new UsageError("--impl: No escaped character");
      cur += s[i + 1];
      i += 2;
    } else {
      cur += c;
      i++;
    }
  }
  if (inToken) out.push(cur);
  return out;
}

interface Args {
  impl: string;
  family: "native" | "enforce" | "all";
  json: string | null;
  timeout: number;
  vector: string[];
  vectorsRoot: string | null;
}

const USAGE = `usage: node runner/ts/dist/cli.js --impl CMD [--family {native,enforce,all}]
                     [--json REPORT] [--timeout SECONDS] [--vector PATTERN]
                     [--vectors-root DIR] [--version]

Run an AAE implementation against the conformance vectors (protocol ${PROTOCOL}).

options:
  --impl CMD            command that starts the implementation under test, split like a
                        POSIX shell (no shell expansion), e.g. "python3 my_adapter.py"
  --family {native,enforce,all}
  --json REPORT         also write a JSON report to this path
  --timeout SECONDS     per-invocation timeout (default ${DEFAULT_TIMEOUT})
  --vector PATTERN      only run vectors whose id equals PATTERN or whose file name
                        contains it; repeatable
  --vectors-root DIR    repository root holding vectors/ and testkeys/ (default: found
                        from the runner location, then the working directory)
  --version             show the version and exit`;

function parseArgs(argv: string[]): Args | number {
  const args: Args = {
    impl: "", family: "all", json: null, timeout: DEFAULT_TIMEOUT, vector: [],
    vectorsRoot: null,
  };
  let implSeen = false;
  let timeoutRaw: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    let flag = argv[i];
    let value: string | undefined;
    if (flag === "-h" || flag === "--help") {
      console.log(USAGE);
      return EXIT_OK;
    }
    if (flag === "--version") {
      console.log(`aae-conformance ${RUNNER_VERSION} (${RUNNER_NAME}), ${PROTOCOL}`);
      return EXIT_OK;
    }
    const eq = flag.indexOf("=");
    if (flag.startsWith("--") && eq > 0) {
      value = flag.slice(eq + 1);
      flag = flag.slice(0, eq);
    }
    const known = ["--impl", "--family", "--json", "--timeout", "--vector", "--vectors-root"];
    if (!known.includes(flag)) throw new UsageError(`unrecognized argument: ${argv[i]}`);
    if (value === undefined) {
      if (i + 1 >= argv.length) throw new UsageError(`argument ${flag}: expected one argument`);
      value = argv[++i];
    }
    switch (flag) {
      case "--impl": args.impl = value; implSeen = true; break;
      case "--family":
        if (value !== "native" && value !== "enforce" && value !== "all") {
          throw new UsageError(`argument --family: invalid choice: '${value}' ` +
            `(choose from 'native', 'enforce', 'all')`);
        }
        args.family = value;
        break;
      case "--json": args.json = value; break;
      case "--timeout": timeoutRaw = value; break;
      case "--vector": args.vector.push(value); break;
      case "--vectors-root": args.vectorsRoot = value; break;
    }
  }
  if (!implSeen) throw new UsageError("the following arguments are required: --impl");
  if (timeoutRaw !== null) {
    const t = Number(timeoutRaw);
    if (timeoutRaw.trim() === "" || Number.isNaN(t)) {
      throw new UsageError(`argument --timeout: invalid float value: '${timeoutRaw}'`);
    }
    args.timeout = t;
  }
  return args;
}

// ------------------------------------------------------------------------- vector loading

function isRoot(d: string): boolean {
  const dir = (p: string) => fs.existsSync(p) && fs.statSync(p).isDirectory();
  return dir(path.join(d, "vectors", "enforce")) && dir(path.join(d, "testkeys", "did-documents"));
}

function findRoot(explicit: string | null): string {
  if (explicit) {
    if (!isRoot(explicit)) {
      throw new UsageError(`--vectors-root ${explicit}: no vectors/enforce/ and ` +
        `testkeys/did-documents/ there`);
    }
    return fs.realpathSync(explicit);
  }
  const here = path.dirname(fileURLToPath(import.meta.url));
  for (const start of [here, process.cwd()]) {
    let d = fs.realpathSync(start);
    for (;;) {
      if (isRoot(d)) return d;
      const parent = path.dirname(d);
      if (parent === d) break;
      d = parent;
    }
  }
  throw new UsageError("cannot find the vector set; pass --vectors-root");
}

function loadJson(p: string): Json {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function jsonFiles(dir: string): string[] {
  return fs.readdirSync(dir)
    .filter((n) => n.endsWith(".json") && fs.statSync(path.join(dir, n)).isFile())
    .sort()
    .map((n) => path.join(dir, n));
}

function loadDidDocuments(root: string): JsonObject {
  const docs: JsonObject = {};
  for (const p of jsonFiles(path.join(root, "testkeys", "did-documents"))) {
    const doc = loadJson(p) as JsonObject;
    docs[doc.id as string] = doc;
  }
  return docs;
}

function loadVectors(root: string, family: Args["family"]): [Family, string, Vector][] {
  const out: [Family, string, Vector][] = [];
  if (family === "native" || family === "all") {
    for (const p of jsonFiles(path.join(root, "vectors"))) {
      out.push(["native", p, loadJson(p) as unknown as Vector]);
    }
  }
  if (family === "enforce" || family === "all") {
    for (const p of jsonFiles(path.join(root, "vectors", "enforce"))) {
      out.push(["enforce", p, loadJson(p) as unknown as Vector]);
    }
  }
  return out;
}

function selected(p: string, vector: Vector, patterns: string[]): boolean {
  if (patterns.length === 0) return true;
  const name = path.basename(p);
  return patterns.some((pat) => pat === vector.id || name.includes(pat));
}

function relFile(root: string, p: string): string {
  return path.relative(root, p).split(path.sep).join("/");
}

// ------------------------------------------------------------------------- requests

function nativeRequest(root: string, p: string, vector: Vector, didDocs: JsonObject): JsonObject {
  return {
    protocol: PROTOCOL,
    family: "native",
    vector_id: vector.id,
    vector_file: relFile(root, p),
    section_ref: vector.section_ref,
    input: vector.input,
    did_documents: didDocs,
    did_documents_dir: path.join(root, "testkeys", "did-documents"),
  };
}

function enforceRequest(root: string, p: string, vector: Vector, variant: string): JsonObject {
  let inp: JsonObject = vector.input;
  if (variant === "keys-reversed") {
    inp = { ...inp };
    for (const key of ["mandate", "transaction"]) {
      if (has(inp, key)) inp[key] = keysReversed(inp[key]);
    }
  }
  return {
    protocol: PROTOCOL,
    family: "enforce",
    vector_id: vector.id,
    vector_file: relFile(root, p),
    section_ref: vector.section_ref,
    kernel: vector.kernel ?? null,
    kernel_version: vector.kernel_version ?? null,
    domain_tags: vector.domain_tags ?? {},
    variant,
    input: inp,
  };
}

// ------------------------------------------------------------------------- invocation

function stderrTail(stderr: string): string {
  const lines = stderr.split(/\r\n|\r|\n/).map((l) => l.trim()).filter((l) => l);
  return lines.slice(-3).join(" | ");
}

function excerpt(text: string): string {
  const first = text.trim().split("\n")[0];
  return first.slice(0, 80) + (first.length > 80 ? "..." : "");
}

const ERRNO_TEXT: Record<string, string> = {
  ENOENT: "No such file or directory",
  EACCES: "Permission denied",
  ENOTDIR: "Not a directory",
};

type Invocation = [JsonObject | null, string | null];

function invoke(argv: string[], request: JsonObject, timeout: number): Promise<Invocation> {
  const data = JSON.stringify(request) + "\n";
  return new Promise((resolve) => {
    let settled = false;
    const finish = (r: Invocation) => {
      if (!settled) {
        settled = true;
        resolve(r);
      }
    };
    const posix = process.platform !== "win32";
    const child = spawn(argv[0], argv.slice(1), {
      stdio: ["pipe", "pipe", "pipe"],
      detached: posix,
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let timedOut = false;
    child.stdout.on("data", (b: Buffer) => out.push(b));
    child.stderr.on("data", (b: Buffer) => err.push(b));
    child.stdin.on("error", () => { /* the implementation stopped reading; not our failure */ });
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        if (posix && child.pid) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        /* already gone */
      }
    }, timeout * 1000);
    child.on("error", (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      const text = (e.code && ERRNO_TEXT[e.code]) || e.message;
      finish([null, `could not start the implementation: ${text}`]);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (timedOut) {
        finish([null, `timed out after ${timeout}s`]);
        return;
      }
      const stdout = Buffer.concat(out).toString("utf8");
      const stderr = Buffer.concat(err).toString("utf8");
      const status = code ?? (signal ? -(os.constants.signals[signal] ?? 0) : 0);
      if (status !== 0) {
        const tail = stderrTail(stderr);
        finish([null, `exited with status ${status}` + (tail ? ` (stderr: ${tail})` : "")]);
        return;
      }
      if (!stdout.trim()) {
        const tail = stderrTail(stderr);
        finish([null, "stdout is empty" + (tail ? ` (stderr: ${tail})` : "")]);
        return;
      }
      let response: Json;
      try {
        response = JSON.parse(stdout);
      } catch {
        finish([null, `stdout is not a single JSON value: ${excerpt(stdout)}`]);
        return;
      }
      if (!isObject(response)) {
        finish([null, "response is not a JSON object"]);
        return;
      }
      finish([response, null]);
    });
    child.stdin.end(data);
  });
}

// ------------------------------------------------------------------------- comparison

function need(resp: JsonObject, key: string, allowed: string[] | null = null,
  kind: "string" | "step" | null = null): string | null {
  if (!has(resp, key)) return `response.${key} missing`;
  const value = resp[key];
  if (allowed !== null && !(typeof value === "string" && allowed.includes(value))) {
    return `response.${key} must be one of ${allowed.join(", ")}, got ${j(value)}`;
  }
  if (kind === "string" && typeof value !== "string") {
    return `response.${key} must be a string, got ${j(value)}`;
  }
  if (kind === "step" && !(typeof value === "number" && Number.isInteger(value))) {
    return `response.${key} must be an integer, got ${j(value)}`;
  }
  return null;
}

function compare(resp: JsonObject, key: string, expected: Json): string | null {
  if (!jsonEqual(get(resp, key), expected)) {
    return `${key} ${j(get(resp, key))}, expected ${j(expected)}`;
  }
  return null;
}

function compact(xs: (string | null)[]): string[] {
  return xs.filter((x): x is string => x !== null);
}

/** Every named predicate must appear, in order, with the same result (and field, value,
 * bound where the vector states them). `reason_contains` is not compared. */
function checkTrace(expectedEntries: JsonObject[], produced: Json): string | null {
  if (!Array.isArray(produced)) return "response.trace must be an array";
  let cursor = 0;
  for (const want of expectedEntries) {
    let found = false;
    while (cursor < produced.length) {
      const got = produced[cursor];
      cursor++;
      if (!isObject(got) || get(got, "predicate") !== want.predicate) continue;
      if (get(got, "result") !== want.result) {
        return `trace: predicate ${want.predicate} result ${j(get(got, "result"))}, ` +
          `expected ${j(want.result)}`;
      }
      for (const key of ["field", "value", "bound"]) {
        if (has(want, key) && !jsonEqual(get(got, key), want[key])) {
          return `trace: predicate ${want.predicate} ${key} ${j(get(got, key))}, ` +
            `expected ${j(want[key])}`;
        }
      }
      found = true;
      break;
    }
    if (!found) return `trace: predicate ${want.predicate} (${want.result}) not in the trace`;
  }
  return null;
}

function reportedError(resp: JsonObject): string | null {
  if (has(resp, "error") && resp.error !== null) {
    const e = resp.error;
    return `implementation returned an error: ${typeof e === "string" ? e : j(e)}`;
  }
  return null;
}

function expectedTrace(exp: JsonObject): JsonObject[] | null {
  const t = exp.trace;
  return Array.isArray(t) && t.length > 0 ? (t as JsonObject[]) : null;
}

function checkNative(resp: JsonObject, exp: JsonObject): string[] {
  const problem = reportedError(resp);
  if (problem) return [problem];
  const fails = compact([need(resp, "result", NATIVE_RESULTS),
    need(resp, "verification_step", null, "step")]);
  if (fails.length) return fails;
  return compact([compare(resp, "result", exp.result),
    compare(resp, "verification_step", get(exp, "verification_step"))]);
}

function checkEnforceCheck(resp: JsonObject, exp: JsonObject): string[] {
  const problem = reportedError(resp);
  if (problem) return [problem];
  let fails = compact([need(resp, "verdict", VERDICTS), need(resp, "core_digest", null, "string")]);
  if (has(exp, "grant_index") && !has(resp, "grant_index")) fails.push("response.grant_index missing");
  if (fails.length) return fails;
  fails = compact([compare(resp, "verdict", exp.verdict),
    compare(resp, "core_digest", exp.core_digest)]);
  if (has(exp, "grant_index")) {
    const p = compare(resp, "grant_index", exp.grant_index);
    if (p) fails.push(p);
  }
  const trace = expectedTrace(exp);
  if (trace && has(resp, "trace")) {
    const p = checkTrace(trace, resp.trace);
    if (p) fails.push(p);
  }
  return fails;
}

function checkRatify(resp: JsonObject, exp: JsonObject): string[] {
  // A generic `error` means the implementation could not answer; it never stands in for
  // the caller error that vectors 24 and 25 expect, which has its own member.
  const problem = reportedError(resp);
  if (problem) return [problem];
  const hasCallerError = has(resp, "caller_error") && resp.caller_error !== null;
  if (has(exp, "error")) {
    if (!hasCallerError) {
      return [`expected a caller error (no record), got status ${j(get(resp, "status"))}`];
    }
    if (typeof resp.caller_error !== "string" || !resp.caller_error) {
      return ["response.caller_error must be a non-empty string"];
    }
    if (get(resp, "status") !== null) return ["response carries both caller_error and status"];
    return [];
  }
  if (hasCallerError) {
    return [`caller error ${j(resp.caller_error)}, expected status ${j(exp.status)}`];
  }
  let fails = compact([need(resp, "status", STATUSES), need(resp, "core_digest", null, "string"),
    need(resp, "ratifies", null, "string")]);
  if (has(exp, "authority") && !has(resp, "authority")) fails.push("response.authority missing");
  if (fails.length) return fails;
  fails = compact([compare(resp, "status", exp.status),
    compare(resp, "core_digest", exp.core_digest), compare(resp, "ratifies", exp.ratifies)]);
  if (has(exp, "authority")) {
    const p = compare(resp, "authority", exp.authority);
    if (p) fails.push(p);
  }
  const trace = expectedTrace(exp);
  if (trace && has(resp, "trace")) {
    const p = checkTrace(trace, resp.trace);
    if (p) fails.push(p);
  }
  return fails;
}

function outcomeText(family: Family, vector: Vector, resp: JsonObject): string {
  if (family === "native") {
    const text = `${resp.result} @ step ${resp.verification_step}`;
    const reason = resp.rejection_reason;
    return text + (typeof reason === "string" && reason ? ` (${reason})` : "");
  }
  if (vector.kernel === "enforce_check") return String(resp.verdict);
  if (has(vector.expected, "error")) return "caller error";
  return String(resp.status);
}

async function runVector(argv: string[], root: string, family: Family, p: string,
  vector: Vector, didDocs: JsonObject, timeout: number): Promise<Entry> {
  const exp = vector.expected;
  const entry: Entry = {
    family,
    file: relFile(root, p),
    vector_id: vector.id,
    kernel: vector.kernel ?? null,
    status: "FAIL",
    outcome: null,
    failures: [],
    expected: exp,
    response: null,
  };
  const request = family === "native"
    ? nativeRequest(root, p, vector, didDocs)
    : enforceRequest(root, p, vector, "as-committed");
  const [resp, err] = await invoke(argv, request, timeout);
  entry.response = resp;
  if (err || !resp) {
    entry.failures = [err ?? "no response"];
    return entry;
  }

  let fails: string[];
  if (family === "native") {
    fails = checkNative(resp, exp);
  } else if (vector.kernel === "enforce_check") {
    fails = checkEnforceCheck(resp, exp);
    if (fails.length === 0) {
      // Determinism: the same input with every object's keys reversed must produce the
      // same core digest, as examples/enforce-verify.py requires of itself.
      const [again, err2] = await invoke(argv, enforceRequest(root, p, vector, "keys-reversed"),
        timeout);
      entry.response_keys_reversed = again;
      if (err2 || !again) {
        fails = [`keys-reversed run: ${err2}`];
      } else if (typeof again.core_digest !== "string") {
        fails = ["keys-reversed run: response.core_digest missing"];
      } else if (again.core_digest !== resp.core_digest) {
        fails = [`core_digest depends on key order (${again.core_digest} with keys ` +
          `reversed): canonicalization is not RFC 8785`];
      }
    }
  } else {
    fails = checkRatify(resp, exp);
  }

  entry.failures = fails;
  if (fails.length === 0) {
    entry.status = "PASS";
    entry.outcome = outcomeText(family, vector, resp);
  }
  return entry;
}

// ------------------------------------------------------------------------- main

async function main(argv: string[]): Promise<number> {
  let args: Args;
  let implArgv: string[];
  let root: string;
  let vectors: [Family, string, Vector][];
  try {
    const parsed = parseArgs(argv);
    if (typeof parsed === "number") return parsed;
    args = parsed;
    implArgv = shellSplit(args.impl);
    if (implArgv.length === 0) throw new UsageError("--impl is empty");
    if (!(args.timeout > 0)) throw new UsageError("--timeout must be positive");
    root = findRoot(args.vectorsRoot);
    vectors = loadVectors(root, args.family).filter(([, p, v]) => selected(p, v, args.vector));
    if (vectors.length === 0) throw new UsageError("no vectors selected");
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`error: ${e.message}\n`);
      return EXIT_USAGE;
    }
    throw e;
  }

  const didDocs = loadDidDocuments(root);
  const print = (line = "") => process.stdout.write(line + "\n");
  print(`AAE conformance runner ${RUNNER_VERSION} (${RUNNER_NAME}), protocol ${PROTOCOL}`);
  print(`implementation: ${args.impl}`);
  print(`vectors: ${root}`);
  print();

  const results: Entry[] = [];
  for (const [family, p, vector] of vectors) {
    const entry = await runVector(implArgv, root, family, p, vector, didDocs, args.timeout);
    results.push(entry);
    const name = path.basename(p);
    if (entry.status === "PASS") {
      print(`PASS  ${family.padEnd(8)} ${name.padEnd(NAME_WIDTH)} ${entry.outcome}`);
    } else {
      print(`FAIL  ${family.padEnd(8)} ${name}`);
      for (const f of entry.failures) print(`        ${f}`);
    }
  }

  const families: Record<string, { passed: number; total: number }> = {};
  for (const fam of ["native", "enforce"]) {
    const rows = results.filter((r) => r.family === fam);
    if (rows.length) {
      families[fam] = { passed: rows.filter((r) => r.status === "PASS").length, total: rows.length };
    }
  }
  const passed = results.filter((r) => r.status === "PASS").length;
  const total = results.length;
  print();
  for (const [fam, c] of Object.entries(families)) {
    print(`${fam.padEnd(8)} ${c.passed}/${c.total} passed`);
  }
  print(`${passed}/${total} passed`);

  if (args.json) {
    const report = {
      runner: RUNNER_NAME,
      runner_version: RUNNER_VERSION,
      protocol: PROTOCOL,
      implementation: args.impl,
      vectors_root: root,
      families,
      passed,
      total,
      ok: passed === total,
      results,
    };
    fs.writeFileSync(args.json, JSON.stringify(report, null, 2) + "\n", "utf8");
  }
  return passed === total ? EXIT_OK : EXIT_FAIL;
}

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (e) => {
    process.stderr.write(`error: ${e instanceof Error ? e.stack ?? e.message : String(e)}\n`);
    process.exitCode = EXIT_USAGE;
  },
);
