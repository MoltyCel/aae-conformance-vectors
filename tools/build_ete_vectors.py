#!/usr/bin/env python3
"""Build and check the 56 Earn-then-Exploit vectors under vectors/ete/.

One vector per environment of the EtE benchmark (arXiv:2611.00725v1, Appendix A.1,
Table 4; benchmark doi:10.5281/zenodo.23598678): the mandate of the environment's task as
grants, the terminal action as the transaction, and the verdict the enforce kernel of
draft-kroehl-agentic-trust-aae-02 (§2.2.3) returns for it. Whether -02 decides the
scene (D) or leaves it open (NS), and the gaps it rests on, travel in the `scene` member,
which the reference verifier does not compare.

Inputs, all in this repository:

  scenarios/earn-then-exploit/scenes.json   task, terminal action, grants, outcome, gaps
  scenarios/earn-then-exploit/LUECKEN.md    the gaps and the scenes each one covers

Outputs, all generated and committed:

  vectors/ete/<scene>.json                                   56 enforce-shaped vectors
  scenarios/earn-then-exploit/MATRIX.md                      the 56-row matrix
  scenarios/earn-then-exploit/molcheck-run/aer/<scene>.json  one AER record per DENY
  scenarios/earn-then-exploit/molcheck-run/trust-list.json   key for the evidence items
  scenarios/earn-then-exploit/molcheck-run/RESULTS.md        the count

The MolCheck verifier run evaluates every vector with the published MolTrust kernel
(PyPI `moltrust-enforce`, pinned in REQUIRED_ENFORCE) and writes, for every refused
terminal action, an Attested-Evidence Replay record that `moltrust-verify` recomputes
offline. Its verdicts must equal the reference kernel of examples/enforce-verify.py.

    python3 tools/build_ete_vectors.py           # write everything
    python3 tools/build_ete_vectors.py --check   # rebuild in memory, compare, verify

--check exits 1 on any difference between the committed files and a fresh build, on any
vector the reference kernel does not reproduce, on any verdict where the two kernels
disagree, and on any AER record that fails V1 to V4.

Deterministic: no clock or network is read; the evidence items are signed with the
committed test key (Ed25519 signatures are deterministic).

THE TEST KEYS ARE PUBLIC AND FOR TESTING ONLY. DO NOT USE IN PRODUCTION.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
SCEN = os.path.join(ROOT, "scenarios", "earn-then-exploit")
OUT = os.path.join(ROOT, "vectors", "ete")
RUN = os.path.join(SCEN, "molcheck-run")
SECTION = "draft-kroehl-agentic-trust-aae-02"
SOURCE = "arXiv:2611.00725v1 Appendix A.1 Table 4; doi:10.5281/zenodo.23598678"

#: SHA-256 of EtE-Benchmark-20261023.zip, the file of the Zenodo record the scenes are read from.
BENCHMARK_SHA256 = "0031b95f89a639f8873db9561b92d51937ed3abf531836e3f31f442757f767da"
REQUIRED_ENFORCE = "0.7.1"
EVIDENCE_SOURCE = "did:web:example.com:registry#ete-scene"
EVIDENCE_KEY = os.path.join(ROOT, "testkeys", "issuer-test-key-1.json")
VALID_FROM = "2026-10-23T00:00:00Z"
VALID_UNTIL = "2027-10-23T00:00:00Z"
DECISION_TIMESTAMP = "2026-11-13T12:00:00Z"

TAGS = {
    "action": "aae:enforce-action:v1",
    "mandate": "aae:enforce-mandate:v1",
    "transaction": "aae:enforce-transaction:v1",
    "core": "aae:enforce-core:v1",
}
TYPE_FIELDS = ["verb", "object"]
CONSEQUENCES = {
    "Z1": "unauthorized capability or privilege grant",
    "Z2": "unauthorized information disclosure",
    "Z3": "untrusted artifact load or execution",
    "Z4": "unauthorized transaction or critical-state manipulation",
    "Z5": "protection or observability weakening",
    "Z6": "unauthorized external representation",
    "Z7": "unauthorized destruction or availability impact",
}
CONTEXTS = {
    "X1": "business transactions", "X2": "development supply chain", "X3": "IT operations",
    "X4": "application integration", "X5": "knowledge work",
    "X6": "communication and collaboration", "X7": "storage and backup",
    "X8": "personnel identity",
}
SECTION_REF = {
    ("D", 4): "§2.2.3 steps 3-4, §6.1",
    ("D", 7): "§2.2.3 step 7, §2.5.1",
    ("NS", None): "§2.2.3 step 6 under the profile; not specified",
}


def _load(name: str, relpath: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ev = _load("enforce_verify", "examples/enforce-verify.py")

# ------------------------------------------------------------------ inputs


def scenes() -> list:
    with open(os.path.join(SCEN, "scenes.json"), encoding="utf-8") as fh:
        data = json.load(fh)["scenes"]
    ids = [s["scene"] for s in data]
    expected = [f"X{x}-Z{z}-1" for x in range(1, 9) for z in range(1, 8)]
    assert ids == expected, "scenes.json must list X1-Z1-1 ... X8-Z7-1 in order"
    for s in data:
        assert (s["outcome"], s["step"]) in SECTION_REF, s["scene"]
    return data


def gaps_table() -> dict:
    """Gap id -> set of scenes, from the table in LUECKEN.md."""
    every = {f"X{x}-Z{z}-1" for x in range(1, 9) for z in range(1, 8)}
    out = {}
    with open(os.path.join(SCEN, "LUECKEN.md"), encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"\| (E\d) \|", line)
            if not m:
                continue
            cells = line.strip().strip("|").split("|")[-1]
            out[m.group(1)] = every if "all 56" in cells else set(
                re.findall(r"X\d-Z\d-1", cells))
    return out


# ------------------------------------------------------------------ vectors


def action(verb: str, obj: str) -> dict:
    return {"verb": verb, "object": obj}


def mandate_of(scene: dict) -> dict:
    return {"mandate_version": "1.0", "grants": [{
        "action_binding": ev.digest(ev.TAG_ACTION, action(g["verb"], g["object"])),
        "type_fields": list(TYPE_FIELDS),
        "disposition": "allow",
        "constraints": g["constraints"],
    } for g in scene["grants"]]}


def transaction_of(scene: dict) -> dict:
    req = dict(scene["request"])
    tx = {"action": action(req.pop("verb"), req.pop("object"))}
    tx.update(req)
    return tx


def trace_summary(trace: list) -> list:
    keep = []
    for t in trace:
        entry = {"predicate": t["predicate"]}
        if t.get("field") is not None:
            entry["field"] = t["field"]
        entry["result"] = t["result"]
        keep.append(entry)
    return keep


def vector(scene: dict) -> dict:
    sid = scene["scene"]
    mandate, tx = mandate_of(scene), transaction_of(scene)
    got = ev.enforce_check(mandate, tx)
    outcome, step = scene["outcome"], scene["step"]
    if outcome == "NS":
        assert got["verdict"] == "PERMIT", (sid, got["reason"])
    elif step == 4:
        assert got["verdict"] == "DENY" and got["reason"].startswith("unaddressed action"), \
            (sid, got["reason"])
    else:
        assert got["verdict"] == "DENY" and got["grant_index"] is None and any(
            t["result"] == "FAIL" and t["predicate"] in ("exact", "enum", "range")
            for t in got["trace"]), (sid, got["reason"])
    x, z = sid.split("-")[:2]
    expected = {"verdict": got["verdict"], "core_digest": got["core_digest"]}
    if got["verdict"] == "PERMIT":
        expected["grant_index"] = got["grant_index"]
    if step == 4:
        expected["reason_contains"] = "unaddressed action"
    expected["trace"] = trace_summary(got["trace"])
    if outcome == "NS":
        rationale = (f"{scene['derivation']} Under the profile the matched grant's constraints "
                     "hold and §2.2.3 step 6 returns PERMIT; -02 has no rule that refuses the "
                     "action, so the scene is not specified (gaps "
                     + ", ".join(scene["gaps"]) + ", see LUECKEN.md).")
    elif step == 4:
        rationale = (f"{scene['derivation']} No grant binds the action digest of the terminal "
                     "action, so §2.2.3 step 4 returns DENY; an unaddressed action never "
                     "yields PENDING (§6.1).")
    else:
        rationale = (f"{scene['derivation']} The grant binds the action type, a constraint "
                     "taken from the task text fails, and §2.2.3 step 7 returns DENY.")
    return {
        "id": f"aae-ete-{sid}",
        "name": f"{sid} {CONTEXTS[x]} x {CONSEQUENCES[z]}",
        "description": f"Earn-then-Exploit environment {sid}, {scene['application']}: the "
                       "terminal action presented against the mandate of the task.",
        "section_ref": SECTION,
        "kernel": "enforce_check",
        "kernel_version": ev.ENFORCE_VERSION,
        "domain_tags": TAGS,
        "input": {"mandate": mandate, "transaction": tx},
        "expected": expected,
        "scene": {
            "id": sid,
            "context": f"{x} {CONTEXTS[x]}",
            "consequence": f"{z} {CONSEQUENCES[z]}",
            "task": scene["task"],
            "terminal_action": scene["terminal"],
            "outcome_under_02": "D" if outcome == "D" else "not specified",
            "section_ref": SECTION_REF[(outcome, step)],
            "gaps": scene["gaps"],
            "source": SOURCE,
        },
        "rationale": rationale,
    }


# ------------------------------------------------------------------ matrix


def matrix(data: list, vectors: dict) -> str:
    counts = {"D4": 0, "D7": 0, "NS": 0}
    rows = []
    for s in data:
        v = vectors[s["scene"]]
        key = "NS" if s["outcome"] == "NS" else f"D{s['step']}"
        counts[key] += 1
        g = s["grants"]
        granted = ", ".join(f"`{x['verb']} {x['object']}`" for x in g)
        req = s["request"]
        rows.append(f"| {s['scene']} | {s['task']} | {s['terminal']} | {granted} | "
                    f"`{req['verb']} {req['object']}` | {v['expected']['verdict']} | "
                    f"{'NS' if s['outcome'] == 'NS' else 'D'} | "
                    f"{SECTION_REF[(s['outcome'], s['step'])]} | {', '.join(s['gaps'])} |")
    head = [
        "# Earn-then-Exploit matrix (generated)",
        "",
        "Generated by `tools/build_ete_vectors.py` from `scenes.json`; do not edit by hand.",
        "Task and terminal action are our summaries of the benchmark scenes (CC-BY-4.0,",
        "doi:10.5281/zenodo.23598678; arXiv:2611.00725v1 Table 4). Columns: the grants of",
        "the task mandate, the action type the terminal action is presented as, the kernel",
        "verdict under the profile, the outcome under -02 (D decided, NS not specified),",
        "the deciding section and the gaps of LUECKEN.md.",
        "",
        f"Totals: {counts['D4'] + counts['D7']} D ({counts['D4']} at §2.2.3 step 4, "
        f"{counts['D7']} at step 7), {counts['NS']} NS.",
        "",
        "| Scene | Task | Terminal action | Grants of the task mandate | Presented as | "
        "Kernel | Under -02 | Section | Gaps |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    return "\n".join(head + rows) + "\n"


# ------------------------------------------------------------------ MolCheck verifier run (AER)


def _enforce():
    try:
        import moltrust_enforce as me
        from importlib.metadata import version
    except ImportError:
        sys.exit("moltrust-enforce is required for the MolCheck verifier run: "
                 f"pip install moltrust-enforce=={REQUIRED_ENFORCE}")
    have = version("moltrust-enforce")
    if have != REQUIRED_ENFORCE:
        sys.exit(f"moltrust-enforce {have} installed, {REQUIRED_ENFORCE} required")
    return me


def _key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with open(EVIDENCE_KEY, encoding="utf-8") as fh:
        jwk = json.load(fh)["jwk"]
    raw = base64.urlsafe_b64decode(jwk["d"] + "=" * (-len(jwk["d"]) % 4))
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    pub = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    return priv, pub


def trust_list() -> dict:
    _priv, pub = _key()
    return {"trust_list_version": 1, "sources": {EVIDENCE_SOURCE: {"keys": [{
        "algorithm": "ed25519", "public_key": base64.b64encode(pub).decode("ascii"),
        "keyid": "issuer-test-key-1"}]}}}


def aer_record(me, sid: str, v: dict) -> dict:
    """Evidence: one signed statement that binds the decision to the scene of the archive."""
    priv, _pub = _key()
    mandate, tx = v["input"]["mandate"], v["input"]["transaction"]
    statement = me.make_statement(
        EVIDENCE_SOURCE,
        {"kind": "ete_scene", "scene_id": sid, "benchmark_sha256": BENCHMARK_SHA256},
        True, VALID_FROM, VALID_UNTIL, f"ete-{sid}")
    assert me.statement_problem(statement) is None
    payload = me.evidence_payload_bytes(statement)
    sig = priv.sign(me.pae(me.PAYLOAD_TYPE, payload))
    envelope = me.make_envelope(statement, [{"keyid": "issuer-test-key-1",
                                             "sig": base64.b64encode(sig).decode("ascii")}])
    bundle = me.build_bundle([envelope], mandate, tx, DECISION_TIMESTAMP)
    result = me.f_ext(mandate, tx, bundle)
    return {"record": {"core": result["core"], "core_digest": result["core_digest"]},
            "bundle": bundle, "mandate": mandate, "transaction": tx}


def molcheck_run(me, vectors: dict) -> tuple:
    records, refused, permitted = {}, [], []
    for sid, v in vectors.items():
        mandate, tx = v["input"]["mandate"], v["input"]["transaction"]
        mine = me.enforce_check(mandate, tx)
        assert mine["verdict"] == v["expected"]["verdict"], (sid, "kernels disagree")
        assert mine["core_digest"] == v["expected"]["core_digest"], (sid, "digests disagree")
        if mine["verdict"] == "DENY":
            rec = aer_record(me, sid, v)
            ext = rec["record"]["core"]
            assert ext["verdict"] == "DENY", sid
            records[sid] = rec
            refused.append((sid, mine["reason"], rec["record"]["core_digest"]))
        else:
            permitted.append((sid, mine["verdict"], v["scene"]["outcome_under_02"]))
    lines = [
        "# MolCheck verifier run over the 56 terminal actions (generated)",
        "",
        "Generated by `tools/build_ete_vectors.py`; do not edit by hand.",
        "",
        f"Kernel: the MolTrust enforce kernel as published on PyPI, `moltrust-enforce` "
        f"{REQUIRED_ENFORCE} (enforce kernel {ev.ENFORCE_VERSION}); records checked with its "
        "offline verifier `moltrust-verify`.",
        "Its verdicts and core digests equal the reference kernel of "
        "`examples/enforce-verify.py` on all 56 vectors.",
        "",
        f"**Refused: {len(refused)} of 56.** Permitted: {len(permitted)} of 56, all of them "
        "scenes that -02 leaves not specified.",
        "",
        "Every refusal has an Attested-Evidence Replay (AER) record in `aer/<scene>.json`:",
        "the verdict record, an evidence bundle with one signed statement binding the decision",
        "to the scene of the benchmark archive (SHA-256 `" + BENCHMARK_SHA256[:16] + "…`),",
        "the mandate and the transaction. Each record verifies offline:",
        "",
        "    moltrust-verify --input aer/X1-Z1-1.json --trust-list trust-list.json",
        "",
        "The evidence key is the repository's public test key; the records show the",
        "mechanism and carry no attestation by a real source.",
        "",
        "| Scene | Verdict | Reason | AER core digest |",
        "|---|---|---|---|",
    ]
    for sid, reason, digest in refused:
        lines.append(f"| {sid} | DENY | {reason} | `{digest}` |")
    lines += ["", "Permitted (no AER record; see LUECKEN.md):", "",
              "| Scene | Verdict | Under -02 |", "|---|---|---|"]
    for sid, verdict, under in permitted:
        lines.append(f"| {sid} | {verdict} | {under} |")
    return records, "\n".join(lines) + "\n"


# ------------------------------------------------------------------ assembly


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def build() -> dict:
    data = scenes()
    gaps = gaps_table()
    for s in data:
        for g in s["gaps"]:
            assert g in gaps, (s["scene"], g, "gap not in LUECKEN.md")
    for g, cells in gaps.items():
        users = {s["scene"] for s in data if g in s["gaps"]}
        assert users == cells, (g, sorted(users ^ cells))
    vectors = {s["scene"]: vector(s) for s in data}
    files = {os.path.join(OUT, f"{sid}.json"): dumps(v) for sid, v in vectors.items()}
    files[os.path.join(SCEN, "MATRIX.md")] = matrix(data, vectors)
    me = _enforce()
    records, results = molcheck_run(me, vectors)
    for sid, rec in records.items():
        files[os.path.join(RUN, "aer", f"{sid}.json")] = dumps(rec)
    files[os.path.join(RUN, "trust-list.json")] = dumps(trust_list())
    files[os.path.join(RUN, "RESULTS.md")] = results
    return files


def generated_dirs() -> list:
    return [OUT, os.path.join(RUN, "aer")]


def check(files: dict) -> int:
    problems = []
    for path, text in files.items():
        try:
            with open(path, encoding="utf-8") as fh:
                if fh.read() != text:
                    problems.append(f"differs from a fresh build: {os.path.relpath(path, ROOT)}")
        except FileNotFoundError:
            problems.append(f"missing: {os.path.relpath(path, ROOT)}")
    for d in generated_dirs():
        for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if os.path.join(d, name) not in files:
                problems.append(f"stale file: {os.path.relpath(os.path.join(d, name), ROOT)}")
    # The committed vectors, recomputed by the reference kernel.
    vec_ok = 0
    for name in sorted(os.listdir(OUT)):
        with open(os.path.join(OUT, name), encoding="utf-8") as fh:
            fails = ev.check_vector(json.load(fh))
        if fails:
            problems.append(f"vectors/ete/{name}: " + "; ".join(fails))
        else:
            vec_ok += 1
    # The committed AER records, verified V1-V4 against the committed trust list.
    me = _enforce()
    with open(os.path.join(RUN, "trust-list.json"), encoding="utf-8") as fh:
        trust = json.load(fh)
    aer_ok = 0
    aer_dir = os.path.join(RUN, "aer")
    for name in sorted(os.listdir(aer_dir)):
        with open(os.path.join(aer_dir, name), encoding="utf-8") as fh:
            rec = json.load(fh)
        res = me.verify_record(rec["record"], rec["bundle"], rec["mandate"],
                               rec["transaction"], trust)
        if res.ok and res.recomputed_verdict == "DENY":
            aer_ok += 1
        else:
            problems.append(f"aer/{name}: {res.failures} recomputed {res.recomputed_verdict}")
    for p in problems:
        print("FAIL", p)
    n_aer = len(os.listdir(aer_dir))
    print(f"{vec_ok}/{len(os.listdir(OUT))} ete vectors reproduced by the reference kernel; "
          f"{aer_ok}/{n_aer} AER records verify (V1-V4, recomputed DENY); "
          f"{len(files)} generated files {'match' if not problems else 'checked'}")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="rebuild in memory and compare with the committed files")
    args = ap.parse_args()
    files = build()
    if args.check:
        return check(files)
    for d in generated_dirs():
        os.makedirs(d, exist_ok=True)
        for name in os.listdir(d):
            if os.path.join(d, name) not in files:
                os.remove(os.path.join(d, name))
    for path, text in files.items():
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    n_deny = sum(1 for p in files if os.sep + "aer" + os.sep in p)
    print(f"wrote 56 ete vectors to vectors/ete/, MATRIX.md, and {n_deny} AER records "
          f"to {os.path.relpath(RUN, ROOT)}/aer/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
