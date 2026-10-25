#!/usr/bin/env node
// Adapter skeleton: copy this file and connect your AAE implementation.
//
// The runner starts this program once per vector, writes one JSON request to stdin and
// reads one JSON response from stdout (docs/RUNNER-PROTOCOL.md). Replace the three
// functions marked TODO with calls into your implementation. Until you do, every vector
// fails with "not implemented", which is the expected starting point.
//
//   node runner/ts/dist/cli.js --impl "node path/to/adapter.mjs"
//
// Write diagnostics to stderr, never to stdout: stdout must carry the one JSON response.
// Plain JavaScript so it runs without a build step; the JSDoc types work in TypeScript
// with checkJs, or rename to .mts and turn them into annotations.

class NotImplemented extends Error {}

/**
 * Native vectors (draft -00, Section 5).
 * @param {string} securedAae  the AAE as a compact JWS
 * @param {Record<string, unknown>} context  current_time, requested_action, action_context,
 *   subject_binding, consumed_ids, revocation_responses, delegation_chain (as present)
 * @param {Record<string, unknown>} didDocuments  DID -> DID document; resolve offline
 * @returns {{result: "ACCEPT" | "REJECT", verification_step: number, rejection_reason?: string | null}}
 */
function verifyNative(securedAae, context, didDocuments) {
  throw new NotImplemented("native verify"); // TODO
}

/**
 * Enforce vectors, kernel "enforce_check" (draft -02, enforce kernel 3.0).
 * @returns {{verdict: "PERMIT" | "DENY" | "PENDING", core_digest: string,
 *   grant_index: number | null, trace?: object[], reason?: string}}
 */
function enforceCheck(mandate, transaction, prevCoreDigest) {
  throw new NotImplemented("enforce_check"); // TODO
}

/**
 * Enforce vectors, kernel "ratify" (draft -02, Sections 6.3 and 6.4). When a guard
 * refuses the request (nothing to record), return {caller_error: "<message>"}.
 * @returns {{status: "RATIFIED" | "REJECTED", core_digest: string, ratifies: string,
 *   authority: string | null} | {caller_error: string}}
 */
function ratify(priorRecord, decision, authorityProof, prevCoreDigest) {
  throw new NotImplemented("ratify"); // TODO
}

function handle(req) {
  const inp = req.input;
  if (req.family === "native") {
    return verifyNative(inp.secured_aae, inp.context, req.did_documents);
  }
  if (req.kernel === "enforce_check") {
    return enforceCheck(inp.mandate, inp.transaction, inp.prev_core_digest ?? null);
  }
  return ratify(inp.prior_record, inp.decision, inp.authority_proof, inp.prev_core_digest ?? null);
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const req = JSON.parse(Buffer.concat(chunks).toString("utf8"));
let resp;
try {
  resp = handle(req);
} catch (err) {
  if (!(err instanceof NotImplemented)) throw err;
  resp = { error: `not implemented: ${err.message}` };
}
process.stdout.write(JSON.stringify(resp) + "\n");
