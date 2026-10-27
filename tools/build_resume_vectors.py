#!/usr/bin/env python3
"""Build the 42 resume vectors under vectors/resume/.

One vector per cell of scenarios/permission-to-retry/README.md: 14 resume schedules of
arXiv:2610.31916v1 times the provider profiles P1, P2, P3. Each vector is the presentation
that draft-kroehl-agentic-trust-aae-02 decides for that cell (the first admission, or the
replacement worker's repeat dispatch) with the result -02 gives for it. The history outcome
of the cell (D or NS) and the gaps it rests on travel along in the `cell` member; the
runner does not compare them.

The cell outcomes, the paper's reference outcomes and the gap lists are read from the two
scenario documents, not restated here, so the vectors cannot drift from the text. Every
expected result is computed by the reference verifiers and checked against the step the
matrix names.

Deterministic: the envelopes are signed with the committed test key, Ed25519 signatures
are deterministic, and no clock or network is read. CI rebuilds and diffs the directory.

THE TEST KEYS ARE PUBLIC AND FOR TESTING ONLY. DO NOT USE IN PRODUCTION.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
OUT = os.path.join(ROOT, "vectors", "resume")
SCEN = os.path.join(ROOT, "scenarios", "permission-to-retry")
SECTION = "draft-kroehl-agentic-trust-aae-02"
SOURCE = "arXiv:2610.31916v1 §2, §4.2, Figure 2"


def _load(name: str, relpath: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bv = _load("build_vectors", "tools/build_vectors.py")
pv = _load("python_verify", "examples/python-verify.py")
ev = _load("enforce_verify", "examples/enforce-verify.py")

PROFILES = ("P1", "P2", "P3")
OUTCOMES = {"C", "D", "U", "NS"}

# ------------------------------------------------------------------ scenario documents


def matrix_rows() -> dict:
    """Row id -> schedule label, per-profile outcome under -02, paper reference outcomes."""
    rows = {}
    with open(os.path.join(SCEN, "README.md"), encoding="utf-8") as fh:
        for line in fh:
            if not re.match(r"\| R\d\d \|", line):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            row, schedule, _text, _repeat, p1, p2, p3, paper = cells
            ref = [x.strip() for x in paper.split("/")]
            assert {p1, p2, p3} <= OUTCOMES and set(ref) <= OUTCOMES, line
            rows[row] = {"schedule": schedule, "outcome": dict(zip(PROFILES, (p1, p2, p3))),
                         "paper": dict(zip(PROFILES, ref))}
    assert sorted(rows) == [f"R{n:02d}" for n in range(1, 15)], sorted(rows)
    return rows


def expand(cells: str) -> list:
    """'R01, R07–R14' -> ['R01', 'R07', ..., 'R14']; text after a row id is ignored."""
    out = []
    for a, b in re.findall(r"R(\d\d)(?:\s*[–-]\s*R(\d\d))?", cells):
        out.extend(f"R{n:02d}" for n in range(int(a), int(b or a) + 1))
    return out


def gaps_by_row() -> dict:
    gaps = {}
    with open(os.path.join(SCEN, "LUECKEN.md"), encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"\| (L\d+) \|", line)
            if not m:
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")][-1]
            for row in expand(cells):
                gaps.setdefault(row, []).append(m.group(1))
    return gaps


# ------------------------------------------------------------------ the envelope profile

NOON = bv.NOON
AFTER_NOT_AFTER = "2026-05-20T17:00:00Z"
AMOUNT = 120
RECIPIENT = "0xABCDEF0123456789ABCDEF0123456789ABCDEF01"
REVOCATION_URI = "https://api.example.com/aae/revocation/{id}"


def envelope_id(row: str) -> str:
    return f"urn:uuid:00000000-0000-4000-8000-{100 + int(row[1:]):012d}"


def envelope(row: str) -> str:
    """One envelope per history: a single refund of a fixed amount, single use, with a
    revocation endpoint. It carries no grants, because the native reference verifier
    implements §5 of -00 and does not evaluate grants (-02 §2.2.1 requires a relying party
    that does not evaluate grants to reject an envelope carrying them). Instance pinning by
    grant is exercised separately, in the enforce-shaped R05 vectors."""
    aae = {
        "mandate": {
            "actions": ["pay"],
            "purpose": "Refund of one order",
            "scope": "payments",
            "principal_did": bv.PRINCIPAL,
        },
        "constraints": {"max_transaction_value": bv.max_tx(AMOUNT, "USD")},
        "validity": {
            "not_before": bv.NB,
            "not_after": bv.NA,
            "single_use": True,
            "revocation_check": REVOCATION_URI,
        },
    }
    return bv.sign_jws(bv.vc(envelope_id(row), bv.REGISTRY, bv.AGENT_001, aae), bv.REGISTRY_KEY)


def context(row: str, *, time=NOON, consumed=False, revoked=False) -> dict:
    ctx = {
        "current_time": time,
        "requested_action": "pay",
        "action_context": {"amount": AMOUNT, "currency": "USD"},
        "subject_binding": {"challenge_response_valid": True},
    }
    if consumed:
        ctx["consumed_ids"] = [envelope_id(row)]
    ctx["revocation_responses"] = {envelope_id(row): {"http_status": 200, "revoked": revoked}}
    return ctx


# Per row: what is presented, the facts the relying party holds at that moment, the step
# the matrix names for it, and why. Rows 07-14 are the replacement worker's repeat dispatch
# after a first presentation that succeeded, so the id is already recorded.
FIRST, REPEAT = "first admission", "repeat dispatch"
NATIVE_ROWS = {
    "R01": (REPEAT, dict(consumed=True), ("REJECT", 5),
            "The finished workflow is reopened and the envelope presented again. Its id was "
            "recorded by the first, successful presentation, so §2.4 single_use and §5 step 5 "
            "reject the repeat."),
    "R02": (FIRST, dict(revoked=True), ("REJECT", 8),
            "Authority is revoked before the first admission. The revocation response reports "
            "revoked: true, which §2.4 requires the relying party to reject at §5 step 8."),
    "R03": (FIRST, dict(), ("ACCEPT", 8),
            "The governing policy changed after issuance, but -02 has no policy-epoch member "
            "and the issuer did not revoke. The envelope passes every step through §5 step 8 "
            "and is accepted. §2.4 says the validity members bound the authorization in time "
            "and do not make it fresh; the paper's reference policy denies here (gap L7)."),
    "R04": (FIRST, dict(time=AFTER_NOT_AFTER), ("REJECT", 3),
            "The approval, expressed as not_after, has lapsed before the first admission. "
            "§2.4 and §5 step 3 reject an expired envelope."),
    "R06": (FIRST, dict(revoked=True), ("REJECT", 8),
            "The worker stopped before preparing the admission, so no presentation succeeded "
            "and no id was recorded. The replacement's presentation is the first one and "
            "meets the revocation at §5 step 8."),
    "R07": (REPEAT, dict(consumed=True), ("REJECT", 5),
            "The provider committed and the acknowledgement was lost. The replacement sends "
            "again; the id is recorded, so §5 step 5 rejects. -02 does not separate the repeat "
            "of an admitted action from a new one (L2) and defines no record that closes the "
            "history (L5)."),
    "R08": (REPEAT, dict(consumed=True, revoked=True), ("REJECT", 5),
            "As R07, and authority is revoked as well. Step 5 (single use) comes before step 8 "
            "(revocation), so the repeat stops at step 5."),
    "R09": (REPEAT, dict(consumed=True), ("REJECT", 5),
            "The first request is still in flight and a lookup came back empty. The replacement "
            "sends again and is rejected by single use at §5 step 5."),
    "R10": (REPEAT, dict(consumed=True), ("REJECT", 5),
            "The confirmation is already held, so no dispatch is needed. A dispatch, if "
            "attempted, is rejected by single use at §5 step 5."),
    "R11": (REPEAT, dict(consumed=True, revoked=True), ("REJECT", 5),
            "As R10, with authority revoked before settlement. Single use rejects at step 5, "
            "before the revocation check at step 8."),
    "R12": (REPEAT, dict(consumed=True), ("REJECT", 5),
            "Settlement was written; a dispatch, if attempted, is rejected by single use at "
            "§5 step 5."),
    "R13": (REPEAT, dict(consumed=True, revoked=True), ("REJECT", 5),
            "As R12, with authority revoked. Single use rejects at step 5."),
    "R14": (REPEAT, dict(consumed=True), ("REJECT", 5),
            "The replacement resends after the provider's deduplication horizon has passed. "
            "The relying party's single-use record has no horizon in -02, so §5 step 5 rejects; "
            "the idempotency key of §7.1 states none either (L8)."),
}
SECTION_REF = {
    3: f"{SECTION} §2.4 (not_after), §5 step 3",
    5: f"{SECTION} §2.4 (single_use), §5 step 5",
    8: f"{SECTION} §2.4 (revocation_check), §5 step 8",
}


def native_vector(row: str) -> dict:
    presentation, facts, (result, step), rationale = NATIVE_ROWS[row]
    jws = envelope(row)
    ctx = context(row, **facts)
    got = pv.verify(jws, ctx)
    assert (got["result"], got["verification_step"]) == (result, step), (row, got)
    return {
        "section_ref": SECTION_REF[step],
        "input": {"secured_aae": jws, "context": ctx},
        "expected": {"result": got["result"], "verification_step": got["verification_step"],
                     "rejection_reason": got["rejection_reason"]},
        "presentation": presentation,
        "rationale": rationale,
    }


PAY = {"verb": "transfer", "asset": "USDC", "chain": "base"}
TAGS_CHECK = {
    "action": "aae:enforce-action:v1",
    "mandate": "aae:enforce-mandate:v1",
    "transaction": "aae:enforce-transaction:v1",
    "core": "aae:enforce-core:v1",
}


def r05_vector() -> dict:
    """R05, action drift: the grant pins the instance (exact recipient, range with lo = hi
    on the amount); the action presented carries a different amount."""
    mandate = {"mandate_version": "1.0", "grants": [{
        "action_binding": ev.digest(ev.TAG_ACTION, PAY),
        "type_fields": ["verb", "asset", "chain"],
        "disposition": "allow",
        "constraints": [
            {"type": "exact", "field": "to", "value": RECIPIENT},
            {"type": "range", "field": "amount", "lo": AMOUNT, "hi": AMOUNT},
        ],
    }]}
    transaction = {"action": PAY, "to": RECIPIENT, "amount": AMOUNT + 30}
    got = ev.enforce_check(mandate, transaction)
    assert got["verdict"] == "DENY", got
    return {
        "section_ref": SECTION,
        "kernel": "enforce_check",
        "kernel_version": ev.ENFORCE_VERSION,
        "domain_tags": TAGS_CHECK,
        "input": {"mandate": mandate, "transaction": transaction},
        "expected": {"verdict": got["verdict"], "core_digest": got["core_digest"],
                     "trace": [{"predicate": "exact", "field": "to", "result": "PASS"},
                               {"predicate": "range", "field": "amount", "result": "FAIL"}]},
        "presentation": FIRST,
        "rationale": "The amount presented for admission differs from the approved one. The "
                     "grant pins the instance with exact on the recipient and range with lo = hi "
                     "on the amount, so §2.2.3 step 7 finds no matched grant whose constraints "
                     "all hold and the verdict is DENY. A grant without such constraints binds "
                     "only the action type (§2.2.2) and would permit the drifted amount.",
    }


# ------------------------------------------------------------------ assembly


def slug(text: str) -> str:
    return "-".join(re.findall(r"[a-z0-9]+", text.lower()))


def build() -> list:
    rows = matrix_rows()
    gaps = gaps_by_row()
    out = []
    for row, meta in rows.items():
        body = r05_vector() if row == "R05" else native_vector(row)
        for profile in PROFILES:
            outcome = meta["outcome"][profile]
            # A cell is D exactly where -02 rejects the first admission.
            denied = body["presentation"] == FIRST and (
                body["expected"].get("result") == "REJECT" or body["expected"].get("verdict") == "DENY")
            assert (outcome == "D") == denied, (row, profile, outcome)
            assert outcome in ("D", "NS"), (row, profile, outcome)
            v = {
                "id": f"aae-resume-{row}-{profile}",
                "name": f"{row} {meta['schedule']}, provider profile {profile}",
                "description": f"Resume schedule \"{meta['schedule']}\" ({SOURCE}) under provider "
                               f"profile {profile}: the {body['presentation']} as the relying "
                               f"party sees it.",
                "section_ref": body["section_ref"],
            }
            for key in ("kernel", "kernel_version", "domain_tags"):
                if key in body:
                    v[key] = body[key]
            v["input"] = body["input"]
            v["expected"] = body["expected"]
            v["cell"] = {
                "row": row,
                "schedule": meta["schedule"],
                "profile": profile,
                "presentation": body["presentation"],
                "history_outcome": outcome,
                "gaps": gaps.get(row, []),
                "paper_reference_outcome": meta["paper"][profile],
                "source": SOURCE,
            }
            v["rationale"] = body["rationale"]
            out.append((f"{row}-{profile}-{slug(meta['schedule'])}.json", v))
    return out


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    vectors = build()
    names = {name for name, _ in vectors}
    for stale in os.listdir(OUT):
        if stale.endswith(".json") and stale not in names:
            os.remove(os.path.join(OUT, stale))
    counts = {}
    for name, v in vectors:
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
            json.dump(v, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        key = v["cell"]["history_outcome"]
        counts[key] = counts.get(key, 0) + 1
    print(f"wrote {len(vectors)} resume vectors to {os.path.relpath(OUT, ROOT)}/ "
          f"(history outcome under -02: " + ", ".join(f"{k} {counts[k]}" for k in sorted(counts))
          + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
