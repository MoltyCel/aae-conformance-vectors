#!/usr/bin/env python3
"""Reference verifier for the enforce vectors under vectors/enforce/.

Implements the enforce kernel of draft-kroehl-agentic-trust-aae-02 from the draft text:
Section 2.2.1 (grants), 2.2.2 (action binding and the type form), 2.2.3 (grant
evaluation), 2.5 (the closed constraint language and the predicate trace), 6.1 (the
verdict vocabulary) and 6.3/6.4 (ratification and its guards).

What it checks per vector: the verdict, the core digest recomputed from the input alone,
every predicate the vector names, and the substring the reason must contain. The digest is
the point. A verifier that returns the right verdict from the wrong core has not
reproduced the decision, only guessed its outcome.

No network, no clock, no stored state — by construction, because the kernel it verifies
has none either. Requires `jcs` (RFC 8785) and `cryptography` for the ratification
signature.

Exits non-zero on any failure.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import sys

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
VECTORS = os.path.join(ROOT, "vectors", "enforce")

PERMIT, DENY, PENDING = "PERMIT", "DENY", "PENDING"
PASS, FAIL = "PASS", "FAIL"
APPROVED, DISAPPROVED = "APPROVED", "DISAPPROVED"
RATIFIED, REJECTED = "RATIFIED", "REJECTED"

# Section 2.2.2 / 2.5.3 / 6.3 — the tag is part of the digest, so it is spelled out here
# rather than imported from anywhere.
TAG_ACTION = b"aae:enforce-action:v1\x00"
TAG_MANDATE = b"aae:enforce-mandate:v1\x00"
TAG_TRANSACTION = b"aae:enforce-transaction:v1\x00"
TAG_CORE = b"aae:enforce-core:v1\x00"
TAG_RATIFY_STATEMENT = b"aae:enforce-ratify-statement:v1\x00"
TAG_RATIFY_CORE = b"aae:enforce-ratify-core:v1\x00"

ENFORCE_VERSION = "2.0"
RATIFY_VERSION = "2.0"

DISPOSITIONS = ("allow", "hold", "forbid")
CONSTRAINT_TYPES = ("exact", "enum", "range")
TYPE_FIELD_VERB = "verb"

MAX_GRANTS = 256
MAX_CONSTRAINTS_PER_GRANT = 64
MAX_ENUM_MEMBERS = 512
MAX_TYPE_FIELDS = 32
MAX_FIELD_DEPTH = 8
MAX_ABS_INT = 10 ** 15


class RatifyError(Exception):
    """Caller error: the request does not line up, so there is no record to produce."""


# --------------------------------------------------------------------------- digests

def digest(tag: bytes, obj) -> str | None:
    try:
        payload = jcs.canonicalize(obj)
    except Exception:
        return None
    return "sha256:" + hashlib.sha256(tag + payload).hexdigest()


def pred(predicate, field, result, reason, value=None, bound=None) -> dict:
    return {"predicate": predicate, "field": field, "value": value,
            "bound": bound, "result": result, "reason": reason}


# ------------------------------------------------------------------ Section 2.5 predicates

def resolve_field(transaction, path):
    if not isinstance(path, str) or not path:
        return False, None
    segments = path.split(".")
    if len(segments) > MAX_FIELD_DEPTH or any(s == "" for s in segments):
        return False, None
    cur = transaction
    for seg in segments:
        if not isinstance(cur, dict) or seg not in cur:
            return False, None
        cur = cur[seg]
    return True, cur


def is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and abs(x) <= MAX_ABS_INT


def eval_exact(c, transaction):
    field, expected = c.get("field"), c.get("value")
    found, actual = resolve_field(transaction, field)
    if not isinstance(expected, str):
        return pred("exact", field, FAIL, "constraint value is not a string", None, expected)
    if not found:
        return pred("exact", field, FAIL, "field not present in transaction", None, expected)
    if not isinstance(actual, str):
        return pred("exact", field, FAIL, "transaction value is not a string", actual, expected)
    if actual == expected:
        return pred("exact", field, PASS, "exact match", actual, expected)
    return pred("exact", field, FAIL, "value does not match exactly", actual, expected)


def eval_enum(c, transaction):
    field, members = c.get("field"), c.get("values")
    found, actual = resolve_field(transaction, field)
    if not isinstance(members, list) or not members:
        return pred("enum", field, FAIL, "constraint values is not a non-empty array", None, members)
    if len(members) > MAX_ENUM_MEMBERS:
        return pred("enum", field, FAIL, "constraint values exceeds member cap", None, len(members))
    if not found:
        return pred("enum", field, FAIL, "field not present in transaction", None, members)
    if not isinstance(actual, str):
        return pred("enum", field, FAIL, "transaction value is not a string", actual, members)
    hits = sum(1 for m in members if actual == m)   # every member compared, no short circuit
    if hits:
        return pred("enum", field, PASS, "value in enumeration", actual, members)
    return pred("enum", field, FAIL, "value not in enumeration", actual, members)


def eval_range(c, transaction):
    field, lo, hi = c.get("field"), c.get("lo"), c.get("hi")
    bound = {"lo": lo, "hi": hi}
    found, actual = resolve_field(transaction, field)
    if not is_int(lo) or not is_int(hi):
        return pred("range", field, FAIL, "constraint bounds are not bounded integers", None, bound)
    if lo > hi:
        return pred("range", field, FAIL, "constraint bounds inverted (lo > hi)", None, bound)
    if not found:
        return pred("range", field, FAIL, "field not present in transaction", None, bound)
    if not is_int(actual):
        return pred("range", field, FAIL, "transaction value is not a bounded integer", actual, bound)
    if lo <= actual <= hi:
        return pred("range", field, PASS, "within range", actual, bound)
    return pred("range", field, FAIL, "outside range", actual, bound)


def eval_constraint(c, transaction):
    if not isinstance(c, dict):
        return pred("unknown", None, FAIL, "constraint is not an object")
    ctype = c.get("type")
    if ctype not in CONSTRAINT_TYPES:
        return pred(str(ctype), c.get("field"), FAIL, "unknown constraint type -> deny by default")
    return {"exact": eval_exact, "enum": eval_enum, "range": eval_range}[ctype](c, transaction)


# ------------------------------------------------------------- Section 2.2.1 grant shape

def type_fields_ok(tf) -> bool:
    if not isinstance(tf, list) or not tf or len(tf) > MAX_TYPE_FIELDS:
        return False
    if any(not isinstance(n, str) or not n for n in tf):
        return False
    if len(set(tf)) != len(tf):
        return False
    return TYPE_FIELD_VERB in tf


def grant_shape_ok(g) -> bool:
    if not isinstance(g, dict):
        return False
    ab = g.get("action_binding")
    if not isinstance(ab, str) or len(ab) != 71 or not ab.startswith("sha256:"):
        return False
    if any(ch not in "0123456789abcdef" for ch in ab[7:]):
        return False
    if g.get("disposition") not in DISPOSITIONS:
        return False
    if not type_fields_ok(g.get("type_fields")):
        return False
    cs = g.get("constraints")
    return isinstance(cs, list) and len(cs) <= MAX_CONSTRAINTS_PER_GRANT


def mandate_problem(mandate):
    if not isinstance(mandate, dict):
        return "mandate missing or not an object"
    grants = mandate.get("grants")
    if not isinstance(grants, list) or not grants:
        return "mandate.grants missing or empty"
    if len(grants) > MAX_GRANTS:
        return "mandate.grants exceeds cap"
    for i, g in enumerate(grants):
        if not grant_shape_ok(g):
            return (f"mandate.grants[{i}] malformed "
                    f"(action_binding/disposition/type_fields/constraints)")
    return None


def type_shape_problem(action, type_fields):
    if not isinstance(action, dict):
        return "action is not an object"
    have, want = set(action.keys()), set(type_fields)
    missing, extra = sorted(want - have), sorted(have - want)
    if missing and extra:
        return (f"action fields do not match type_fields "
                f"(missing {missing}, outside the type {extra})")
    if missing:
        return f"action is missing type_fields {missing}"
    if extra:
        return f"action carries fields outside type_fields {extra}"
    return None


# --------------------------------------------------------------- Section 2.2.3 / 6.1

def enforce_check(mandate, transaction, prev_core_digest=None) -> dict:
    trace, grant_index = [], None
    problem = mandate_problem(mandate)
    tx_ok = isinstance(transaction, dict)
    act_digest = digest(TAG_ACTION, transaction.get("action")) if tx_ok else None

    if problem is not None:
        verdict, reason = DENY, problem
        trace.append(pred("mandate_present", None, FAIL, problem))
    elif not tx_ok:
        verdict, reason = DENY, "transaction missing or not an object"
        trace.append(pred("transaction_present", None, FAIL, reason))
    elif act_digest is None:
        verdict, reason = DENY, "transaction.action missing or not canonicalizable"
        trace.append(pred("action_binding", "action", FAIL, reason))
    else:
        trace.append(pred("mandate_present", None, PASS, "mandate structurally valid"))
        grants = mandate["grants"]
        action = transaction.get("action")

        typed, first_problem = [], None
        for i, g in enumerate(grants):
            p = type_shape_problem(action, g["type_fields"])
            if p is None:
                typed.append(i)
            elif first_problem is None:
                first_problem = (i, p)

        if not typed:
            i, p = first_problem
            verdict, reason = DENY, f"grant[{i}]: {p}"
            trace.append(pred("type_fields", "action", FAIL, reason,
                              sorted(action.keys()) if isinstance(action, dict) else None,
                              list(grants[i]["type_fields"])))
        else:
            trace.append(pred("type_fields", "action", PASS,
                              f"action carries exactly the type_fields of grant(s) {typed}",
                              sorted(action.keys()), list(grants[typed[0]]["type_fields"])))
            matched = [i for i in typed if grants[i]["action_binding"] == act_digest]

            if not matched:
                verdict, reason = DENY, "unaddressed action: no grant binds this action digest"
                trace.append(pred("action_binding", "action", FAIL, reason, act_digest, None))
            else:
                trace.append(pred("action_binding", "action", PASS,
                                  f"bound by grant(s) {matched}", act_digest, act_digest))
                forbidden = [i for i in matched if grants[i]["disposition"] == "forbid"]
                if forbidden:
                    grant_index = forbidden[0]
                    verdict = DENY
                    reason = f"grant[{grant_index}] disposition=forbid"
                    trace.append(pred("disposition", None, FAIL, reason, "forbid", None))
                else:
                    verdict, reason = DENY, "no matching grant satisfied its constraints"
                    for i in matched:
                        preds = [eval_constraint(c, transaction)
                                 for c in grants[i]["constraints"]]
                        trace.extend(preds)
                        if all(p["result"] == PASS for p in preds):
                            grant_index = i
                            disp = grants[i]["disposition"]
                            verdict = PERMIT if disp == "allow" else PENDING
                            reason = (f"grant[{i}] matched, all constraints hold, "
                                      f"disposition={disp}")
                            trace.append(pred("disposition", None, PASS, reason, disp, None))
                            break

    core = {
        "enforce_version": ENFORCE_VERSION,
        "mandate_digest": digest(TAG_MANDATE, mandate),
        "transaction_digest": digest(TAG_TRANSACTION, transaction),
        "action_digest": act_digest,
        "verdict": verdict,
        "grant_index": grant_index,
        "reason": reason,
        "trace": trace,
        "prev_core_digest": prev_core_digest if isinstance(prev_core_digest, str) else None,
    }
    return {"verdict": verdict, "reason": reason, "grant_index": grant_index,
            "trace": trace, "core": core, "core_digest": digest(TAG_CORE, core)}


# ------------------------------------------------------------------- Section 6.3 / 6.4

def statement_bytes(prior_core_digest, decision, authority_did) -> bytes:
    return TAG_RATIFY_STATEMENT + jcs.canonicalize({
        "ratify_version": RATIFY_VERSION, "ratifies": prior_core_digest,
        "decision": decision, "authority": authority_did})


def mandate_authorities(mandate):
    if not isinstance(mandate, dict):
        return []
    out = []
    principal = mandate.get("principal")
    if isinstance(principal, dict):
        did, key = principal.get("did"), principal.get("public_key")
        if isinstance(did, str) and isinstance(key, str):
            out.append((did, key, "principal"))
    for entry in (mandate.get("ratification_authorities") or [])[:64]:
        if not isinstance(entry, dict):
            continue
        did, key = entry.get("did"), entry.get("public_key")
        if isinstance(did, str) and isinstance(key, str):
            role = entry.get("role")
            out.append((did, key, role if isinstance(role, str) else "named_authority"))
    return out


def ed25519_verify(public_key_hex, signature_hex, message) -> bool:
    if not isinstance(public_key_hex, str) or not isinstance(signature_hex, str):
        return False
    try:
        raw, sig = bytes.fromhex(public_key_hex), bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(raw) != 32 or len(sig) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, message)
        return True
    except Exception:
        return False


def ratify(prior_record, decision, authority_proof, prev_core_digest=None) -> dict:
    if decision not in (APPROVED, DISAPPROVED):
        raise RatifyError(f"decision must be APPROVED or DISAPPROVED, got {decision!r}")
    if not isinstance(prior_record, dict):
        raise RatifyError("prior_record missing or not an object")
    core, claimed = prior_record.get("core"), prior_record.get("core_digest")
    if not isinstance(core, dict) or not isinstance(claimed, str):
        raise RatifyError("prior_record.core or core_digest missing")
    if digest(TAG_CORE, core) != claimed:
        raise RatifyError("prior_record.core_digest does not match its own core")

    prior_verdict = core.get("verdict")
    if prior_verdict == PERMIT:                                     # Guard 2
        raise RatifyError("a PERMIT is not ratifiable — there is no status to change")
    if prior_verdict not in (DENY, PENDING):
        raise RatifyError(f"prior verdict {prior_verdict!r} is not ratifiable")
    if prev_core_digest is not None and prev_core_digest != claimed:  # Guard 3
        raise RatifyError(
            "prev_core_digest must equal the core_digest of the record being ratified "
            f"(ratifies {claimed}, got {prev_core_digest!r})")

    trace = [pred("prior_ratifiable", None, PASS,
                  f"prior verdict {prior_verdict} may be ratified", prior_verdict, None)]
    authority_did, status, reason = None, REJECTED, "authority not established"

    if not isinstance(authority_proof, dict):
        trace.append(pred("authority_proof", None, FAIL,
                          "authority_proof missing or not an object"))
        reason = "authority_proof missing or not an object"
    else:
        mandate = authority_proof.get("mandate")
        claimed_authority = authority_proof.get("authority")
        supplied = digest(TAG_MANDATE, mandate) if mandate is not None else None
        bound = supplied == core["mandate_digest"]
        trace.append(pred("mandate_binding", "mandate", PASS if bound else FAIL,
                          "supplied mandate is the one the prior record refers to" if bound
                          else "supplied mandate does not match prior_record.mandate_digest",
                          supplied, core["mandate_digest"]))
        if not bound:
            reason = "supplied mandate does not match the prior record"
        else:
            allowed = mandate_authorities(mandate)
            match = next((a for a in allowed if a[0] == claimed_authority), None)
            trace.append(pred("authority_in_mandate", "authority", PASS if match else FAIL,
                              f"authority derives from mandate as {match[2]}" if match
                              else "authority is not the issuing principal and not a role "
                                   "named in the mandate",
                              claimed_authority, [d for d, _k, _r in allowed]))
            if not match:
                reason = "authority does not derive from the mandate"
            else:
                did, key_hex, role = match
                ok = ed25519_verify(key_hex, authority_proof.get("signature"),
                                    statement_bytes(claimed, decision, did))
                trace.append(pred("authority_signature", "signature", PASS if ok else FAIL,
                                  "signature verifies against the mandate-held key" if ok
                                  else "signature does not verify against the "
                                       "mandate-held key"))
                if ok:
                    authority_did, status = did, RATIFIED
                    reason = f"ratified by {role} {did}: prior {prior_verdict} -> {decision}"
                else:
                    reason = "authority signature does not verify"

    rcore = {
        "ratify_version": RATIFY_VERSION,
        "ratifies": claimed,
        "prior_verdict": prior_verdict,
        "decision": decision,
        "status": status,
        "authority": authority_did,
        "mandate_digest": core["mandate_digest"],
        "reason": reason,
        "trace": trace,
        "prev_core_digest": prev_core_digest if isinstance(prev_core_digest, str) else claimed,
    }
    return {"status": status, "decision": decision, "ratifies": claimed,
            "authority": authority_did, "reason": reason, "trace": trace,
            "core": rcore, "core_digest": digest(TAG_RATIFY_CORE, rcore)}


# ------------------------------------------------------------------------ vector check

def trace_holds(expected_entries, produced) -> str | None:
    """Every named predicate must appear, in order, with the same result."""
    cursor = 0
    for want in expected_entries:
        while cursor < len(produced):
            got = produced[cursor]
            cursor += 1
            if got["predicate"] != want["predicate"]:
                continue
            if got["result"] != want["result"]:
                return (f"predicate {want['predicate']}: result {got['result']}, "
                        f"expected {want['result']}")
            for key in ("field", "value", "bound"):
                if key in want and got.get(key) != want[key]:
                    return (f"predicate {want['predicate']}: {key} {got.get(key)!r}, "
                            f"expected {want[key]!r}")
            if "reason_contains" in want and want["reason_contains"] not in got["reason"]:
                return (f"predicate {want['predicate']}: reason {got['reason']!r} does not "
                        f"contain {want['reason_contains']!r}")
            break
        else:
            return f"predicate {want['predicate']} ({want['result']}) not in the trace"
    return None


def reordered(obj):
    """The same JSON value with every object's keys in reverse order.

    JCS sorts keys, so a canonicalizing implementation must produce the identical digest
    from this and from the original. One that serialises in insertion order will not —
    which is the failure this catches.
    """
    if isinstance(obj, dict):
        return {k: reordered(obj[k]) for k in reversed(list(obj))}
    if isinstance(obj, list):
        return [reordered(v) for v in obj]
    return obj


def check_vector(vector) -> list:
    exp, inp = vector["expected"], vector["input"]
    fails = []

    if vector["kernel"] == "enforce_check":
        got = enforce_check(inp.get("mandate"), inp.get("transaction"),
                            inp.get("prev_core_digest"))
        # Determinism, on every vector rather than in one of its own: the same inputs with
        # their keys in the other order must land on the same 32 octets.
        again = enforce_check(reordered(inp.get("mandate")),
                              reordered(inp.get("transaction")),
                              inp.get("prev_core_digest"))
        if again["core_digest"] != got["core_digest"]:
            fails.append("core_digest depends on key order — canonicalization is not RFC 8785")
        if got["verdict"] != exp["verdict"]:
            fails.append(f"verdict {got['verdict']}, expected {exp['verdict']}")
        if got["core_digest"] != exp["core_digest"]:
            fails.append(f"core_digest {got['core_digest']}, expected {exp['core_digest']}")
        if got["core"]["enforce_version"] != vector["kernel_version"]:
            fails.append(f"enforce_version {got['core']['enforce_version']}, "
                         f"expected {vector['kernel_version']}")
        if "grant_index" in exp and got["grant_index"] != exp["grant_index"]:
            fails.append(f"grant_index {got['grant_index']}, expected {exp['grant_index']}")
    else:
        try:
            got = ratify(inp.get("prior_record"), inp.get("decision"),
                         inp.get("authority_proof"), inp.get("prev_core_digest"))
        except RatifyError as exc:
            if "error" not in exp:
                return [f"unexpected RatifyError: {exc}"]
            if exp.get("reason_contains") and exp["reason_contains"] not in str(exc):
                fails.append(f"error {str(exc)!r} does not contain "
                             f"{exp['reason_contains']!r}")
            return fails
        if "error" in exp:
            return [f"expected {exp['error']}, got status {got['status']}"]
        if got["status"] != exp["status"]:
            fails.append(f"status {got['status']}, expected {exp['status']}")
        if got["core_digest"] != exp["core_digest"]:
            fails.append(f"core_digest {got['core_digest']}, expected {exp['core_digest']}")
        if got["ratifies"] != exp["ratifies"]:
            fails.append(f"ratifies {got['ratifies']}, expected {exp['ratifies']}")
        if "authority" in exp and got["authority"] != exp["authority"]:
            fails.append(f"authority {got['authority']!r}, expected {exp['authority']!r}")
        if got["core"]["ratify_version"] != vector["kernel_version"]:
            fails.append(f"ratify_version {got['core']['ratify_version']}, "
                         f"expected {vector['kernel_version']}")

    if exp.get("reason_contains") and exp["reason_contains"] not in got["reason"]:
        fails.append(f"reason {got['reason']!r} does not contain "
                     f"{exp['reason_contains']!r}")
    if exp.get("trace"):
        problem = trace_holds(exp["trace"], got["trace"])
        if problem:
            fails.append(problem)
    return fails


def main() -> int:
    paths = sorted(glob.glob(os.path.join(VECTORS, "*.json")))
    if not paths:
        print("no enforce vectors to verify")
        return 0
    failed = 0
    for path in paths:
        with open(path) as fh:
            vector = json.load(fh)
        fails = check_vector(vector)
        name = os.path.basename(path)
        if fails:
            failed += 1
            print(f"FAIL  {name}")
            for f in fails:
                print(f"        {f}")
        else:
            outcome = vector["expected"].get("verdict") or \
                vector["expected"].get("status") or vector["expected"].get("error")
            print(f"PASS  {name:44s} {outcome}")
    total = len(paths)
    print(f"\n{total - failed}/{total} enforce vectors passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
