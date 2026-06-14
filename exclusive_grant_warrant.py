#!/usr/bin/env python3
"""ExclusiveGrantWarrant: deterministic clearing + conflict-free allocation + per-grant
provenance warrant for a finite pool of mutually-exclusive rights.

One question, answered deterministically (no network, no system clock, no AI call):
  For this bidding round on a finite pool of mutually-exclusive rights, what is the
  conflict-free clearing allocation and clearing price, and is every granted right
  provenance-certified?

Reuses (recreate run 009): dauction (average-mechanism clearing price), Spectrum-Allocation
(set-disjoint exclusivity), ascending-auction (priority order), BlockChain-REC (per-grant
provenance certificate, redesigned from NFT to a stdlib hash-chain warrant).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


VERDICTS = ("cleared", "partial", "void")
BOUNDARY = "not an exchange, not a rights registry of record, not a regulator, and not a price oracle"


EXAMPLES: dict[str, dict[str, Any]] = {
    "cleared": {
        "round_id": "EGW-001",
        "rights_pool": ["band-A", "band-B", "band-C"],
        "bids": [
            {
                "bid_id": "b1",
                "holder": "acme",
                "rights": ["band-A", "band-B"],
                "price_per_unit": 12.0,
                "priority": 5,
                "provenance": {
                    "holder_id": "acme",
                    "evidence": ["license.pdf", "kyc.json"],
                    "attestation_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                },
            },
            {
                "bid_id": "b2",
                "holder": "globex",
                "rights": ["band-C"],
                "price_per_unit": 9.0,
                "priority": 3,
                "provenance": {
                    "holder_id": "globex",
                    "evidence": ["license.pdf"],
                    "attestation_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
                },
            },
        ],
    },
    "partial": {
        "round_id": "EGW-002",
        "rights_pool": ["lane-1", "lane-2"],
        "bids": [
            {
                "bid_id": "b1",
                "holder": "northwind",
                "rights": ["lane-1"],
                "price_per_unit": 10.0,
                "priority": 5,
                "provenance": {
                    "holder_id": "northwind",
                    "evidence": ["permit.pdf"],
                    "attestation_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
                },
            },
            {
                "bid_id": "b2",
                "holder": "umbrella",
                "rights": ["lane-1", "lane-2"],
                "price_per_unit": 8.0,
                "priority": 2,
                "provenance": {
                    "holder_id": "umbrella",
                    "evidence": ["permit.pdf"],
                    "attestation_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
                },
            },
        ],
    },
    "void": {
        "round_id": "EGW-003",
        "rights_pool": ["slot-X"],
        "bids": [
            {
                "bid_id": "b1",
                "holder": "initech",
                "rights": ["slot-X"],
                "price_per_unit": 10.0,
                "priority": 5,
                "provenance": {
                    "holder_id": "initech",
                    "evidence": [],
                    "attestation_sha256": "",
                },
            }
        ],
    },
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def normalize_round(round_obj: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(round_obj)
    normalized.setdefault("round_id", "unknown")
    normalized["round_id"] = str(normalized["round_id"])
    normalized["rights_pool"] = [str(item) for item in _list(normalized.get("rights_pool"))]

    bids = []
    for raw in _list(normalized.get("bids")):
        bid = _dict(raw)
        provenance = _dict(bid.get("provenance"))
        bids.append(
            {
                "bid_id": str(bid.get("bid_id", "")),
                "holder": str(bid.get("holder", "")),
                "rights": [str(item) for item in _list(bid.get("rights"))],
                "price_per_unit": _to_float(bid.get("price_per_unit", 0.0)),
                "priority": _to_int(bid.get("priority", 0)),
                "provenance": {
                    "holder_id": str(provenance.get("holder_id", "")),
                    "evidence": [str(item) for item in _list(provenance.get("evidence"))],
                    "attestation_sha256": str(provenance.get("attestation_sha256", "")).lower(),
                },
            }
        )
    normalized["bids"] = bids
    return normalized


def allocate(round_obj: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Set-disjoint priority allocation (Spectrum-Allocation x ascending-auction).

    Deterministic order: priority desc, price desc, bid_id asc. A bid is granted only if
    ALL its requested rights are still free (atomic exclusive grant) — no right twice.
    """
    pool = set(round_obj["rights_pool"])
    order = sorted(
        round_obj["bids"],
        key=lambda b: (-b["priority"], -b["price_per_unit"], b["bid_id"]),
    )
    granted: list[dict[str, Any]] = []
    unmet: list[dict[str, Any]] = []
    allocated: set[str] = set()
    for bid in order:
        req = bid["rights"]
        if not req:
            unmet.append({"bid": bid, "reason": "no rights requested"})
            continue
        if len(set(req)) != len(req):
            unmet.append({"bid": bid, "reason": "bid requests a right more than once"})
            continue
        outside = [r for r in req if r not in pool]
        if outside:
            unmet.append({"bid": bid, "reason": f"requests rights outside pool: {', '.join(outside)}"})
            continue
        conflict = [r for r in req if r in allocated]
        if conflict:
            unmet.append({"bid": bid, "reason": f"rights conflict with higher-priority grant: {', '.join(conflict)}"})
            continue
        granted.append(bid)
        allocated.update(req)
    return granted, unmet


def clearing_price(granted: list[dict[str, Any]], unmet: list[dict[str, Any]]) -> float | None:
    """Average-mechanism clearing price (dauction).

    Uniform price = lowest accepted bid. If a rejected bid sits below the lowest accepted
    (price-competition tension), the clearing price is the average of the two — the
    marginal price between highest rejected and lowest accepted.
    """
    if not granted:
        return None
    lowest_accepted = min(b["price_per_unit"] for b in granted)
    rejected_prices = [u["bid"]["price_per_unit"] for u in unmet if u["reason"].startswith("rights conflict")]
    if rejected_prices:
        highest_rejected = max(rejected_prices)
        if highest_rejected < lowest_accepted:
            return round((lowest_accepted + highest_rejected) / 2, 4)
    return round(lowest_accepted, 4)


def build_warrants(
    round_obj: dict[str, Any], granted: list[dict[str, Any]], price: float | None
) -> list[dict[str, Any]]:
    """Per-grant provenance warrant (BlockChain-REC redesigned to a stdlib hash)."""
    warrants = []
    for bid in granted:
        attestation = bid["provenance"]["attestation_sha256"]
        for right in bid["rights"]:
            body = {
                "round_id": round_obj["round_id"],
                "right": right,
                "holder": bid["holder"],
                "bid_id": bid["bid_id"],
                "clearing_price": price,
                "provenance_attestation_sha256": attestation,
            }
            warrants.append({**body, "warrant_sha256": sha256_text(canonical_json(body))})
    return warrants


def ok_check(score: float = 1.0) -> dict[str, Any]:
    return {"hard_fail": False, "warnings": [], "reasons": [], "score": score}


def check_exclusivity(
    round_obj: dict[str, Any], granted: list[dict[str, Any]], unmet: list[dict[str, Any]]
) -> dict[str, Any]:
    result = ok_check()
    if not round_obj["rights_pool"]:
        result["hard_fail"] = True
        result["reasons"].append("rights_pool is empty")
    if not granted:
        result["hard_fail"] = True
        result["reasons"].append("no bid could be granted (allocation impossible)")
    seen: set[str] = set()
    for bid in granted:
        for right in bid["rights"]:
            if right in seen:
                result["hard_fail"] = True
                result["reasons"].append(f"right {right} is granted more than once")
            seen.add(right)
    result["score"] = 0.0 if result["hard_fail"] else 1.0
    return result


def check_clearing(granted: list[dict[str, Any]], price: float | None) -> dict[str, Any]:
    result = ok_check()
    if price is None:
        result["hard_fail"] = True
        result["reasons"].append("no clearing price exists (no granted bids)")
    elif len(granted) == 1:
        result["warnings"].append("single grant — no price competition (degenerate clearing price)")
    result["score"] = 0.0 if result["hard_fail"] else 0.7 if result["warnings"] else 1.0
    return result


def check_allocation(granted: list[dict[str, Any]], unmet: list[dict[str, Any]]) -> dict[str, Any]:
    result = ok_check()
    for entry in unmet:
        result["warnings"].append(f"bid {entry['bid']['bid_id'] or '?'} unmet: {entry['reason']}")
    result["score"] = 0.75 if result["warnings"] else 1.0
    return result


def check_provenance(granted: list[dict[str, Any]], warrants: list[dict[str, Any]]) -> dict[str, Any]:
    result = ok_check()
    for bid in granted:
        attestation = bid["provenance"]["attestation_sha256"]
        if not is_sha256(attestation):
            result["hard_fail"] = True
            result["reasons"].append(
                f"granted bid {bid['bid_id'] or '?'} ({bid['holder'] or 'no-holder'}) "
                "has no valid provenance attestation"
            )
        elif not bid["provenance"]["evidence"]:
            result["warnings"].append(f"granted bid {bid['bid_id'] or '?'} has empty provenance evidence")
    result["score"] = 0.0 if result["hard_fail"] else 0.6 if result["warnings"] else 1.0
    return result


def reduce_verdict(checks: dict[str, dict[str, Any]]) -> str:
    if any(check["hard_fail"] for check in checks.values()):
        return "void"
    if any(check["warnings"] for check in checks.values()):
        return "partial"
    return "cleared"


def flatten_reasons(checks: dict[str, dict[str, Any]]) -> list[str]:
    reasons: list[str] = []
    for channel, check in checks.items():
        for reason in check["reasons"]:
            reasons.append(f"{channel}: {reason}")
        for warning in check["warnings"]:
            reasons.append(f"{channel}: {warning}")
    return reasons


def commitments(round_obj: dict[str, Any], verdict: dict[str, Any]) -> dict[str, str]:
    input_blob = canonical_json(round_obj)
    verdict_blob = canonical_json({k: v for k, v in verdict.items() if k not in {"commitments", "ledger_entry"}})
    return {
        "input_sha256": sha256_text(input_blob),
        "verdict_sha256": sha256_text(verdict_blob),
        "combined_sha256": sha256_text(input_blob + verdict_blob),
    }


def evaluate(round_obj: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_round(round_obj)
    granted, unmet = allocate(normalized)
    price = clearing_price(granted, unmet)
    warrants = build_warrants(normalized, granted, price)
    checks = {
        "exclusivity": check_exclusivity(normalized, granted, unmet),
        "clearing": check_clearing(granted, price),
        "allocation": check_allocation(granted, unmet),
        "provenance": check_provenance(granted, warrants),
    }
    verdict = reduce_verdict(checks)
    result = {
        "round_id": normalized["round_id"],
        "verdict": verdict,
        "clearing_price": price,
        "allocation": [
            {"bid_id": b["bid_id"], "holder": b["holder"], "rights": b["rights"], "price_per_unit": b["price_per_unit"]}
            for b in granted
        ],
        "unmet": [{"bid_id": u["bid"]["bid_id"], "reason": u["reason"]} for u in unmet],
        "warrants": warrants,
        "reasons": flatten_reasons(checks),
        "component_scores": {name: check["score"] for name, check in checks.items()},
        "boundary": BOUNDARY,
    }
    if not result["reasons"]:
        result["reasons"].append("all clearing, allocation, and provenance channels agree")
    result["commitments"] = commitments(normalized, result)
    return result


def read_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    entries = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"ledger line {line_number} is not valid JSON") from exc
    return entries


def ledger_entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_sha256"}
    return sha256_text(canonical_json(body))


def append_ledger(path: Path, result: dict[str, Any]) -> dict[str, Any]:
    entries = read_ledger(path)
    previous = entries[-1]["entry_sha256"] if entries else ""
    entry = {
        "index": len(entries) + 1,
        "previous_entry_sha256": previous,
        "round_id": result["round_id"],
        "verdict": result["verdict"],
        "clearing_price": result["clearing_price"],
        "warrant_count": len(result["warrants"]),
        "commitments": result["commitments"],
    }
    entry["entry_sha256"] = ledger_entry_hash(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(entry) + "\n")
    return entry


def verify_ledger(path: Path) -> dict[str, Any]:
    entries = read_ledger(path)
    reasons: list[str] = []
    previous = ""
    for expected_index, entry in enumerate(entries, start=1):
        if entry.get("index") != expected_index:
            reasons.append(f"entry {expected_index} has wrong index {entry.get('index')}")
        if entry.get("previous_entry_sha256") != previous:
            reasons.append(f"entry {expected_index} previous hash mismatch")
        stored_hash = entry.get("entry_sha256")
        actual_hash = ledger_entry_hash(entry)
        if stored_hash != actual_hash:
            reasons.append(f"entry {expected_index} hash mismatch")
        previous = stored_hash or ""
    return {
        "ledger": str(path),
        "entries": len(entries),
        "valid": not reasons,
        "reasons": reasons or ["ledger hash chain is valid"],
    }


def markdown_report(round_obj: dict[str, Any]) -> str:
    normalized = normalize_round(round_obj)
    result = evaluate(normalized)
    lines = [
        f"# ExclusiveGrantWarrant Report: {result['round_id']}",
        "",
        f"- verdict: **{result['verdict']}**",
        f"- clearing_price: {result['clearing_price']}",
        f"- rights_pool: {', '.join(normalized['rights_pool']) or '(empty)'}",
        "",
        "## Channels",
    ]
    for name, score in result["component_scores"].items():
        lines.append(f"- {name}: {score:.2f}")
    lines.extend(["", "## Allocation (granted, conflict-free)"])
    if result["allocation"]:
        for grant in result["allocation"]:
            lines.append(
                f"- {grant['bid_id']} ({grant['holder']}): {', '.join(grant['rights'])} "
                f"@ {grant['price_per_unit']}"
            )
    else:
        lines.append("- (none granted)")
    if result["unmet"]:
        lines.extend(["", "## Unmet"])
        lines.extend(f"- {u['bid_id']}: {u['reason']}" for u in result["unmet"])
    lines.extend(["", "## Reasons"])
    lines.extend(f"- {reason}" for reason in result["reasons"])
    lines.extend(["", "## Grant Warrants"])
    if result["warrants"]:
        for warrant in result["warrants"]:
            lines.append(f"- {warrant['right']} -> {warrant['holder']}: `{warrant['warrant_sha256']}`")
    else:
        lines.append("- (none issued)")
    lines.extend(
        [
            "",
            "## Commitments",
            f"- input_sha256: `{result['commitments']['input_sha256']}`",
            f"- verdict_sha256: `{result['commitments']['verdict_sha256']}`",
            f"- combined_sha256: `{result['commitments']['combined_sha256']}`",
            "",
            "## Boundary",
            f"> {result['boundary']}",
        ]
    )
    return "\n".join(lines) + "\n"


def ledger_report(path: Path) -> str:
    result = verify_ledger(path)
    lines = [
        f"# ExclusiveGrantWarrant Ledger Report: {path}",
        "",
        f"- entries: {result['entries']}",
        f"- valid: **{str(result['valid']).lower()}**",
        "",
        "## Reasons",
    ]
    lines.extend(f"- {reason}" for reason in result["reasons"])
    return "\n".join(lines) + "\n"


def load_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_sample(args: argparse.Namespace) -> int:
    if args.write:
        out_dir = Path(args.write)
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, round_obj in EXAMPLES.items():
            (out_dir / f"{name}.json").write_text(
                json.dumps(round_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
    print(json.dumps(EXAMPLES, indent=2, ensure_ascii=False))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    round_obj = load_json(args.input)
    result = evaluate(round_obj)
    if args.ledger:
        result["ledger_entry"] = append_ledger(Path(args.ledger), result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    if args.ledger and not args.input:
        print(ledger_report(Path(args.ledger)), end="")
        return 0
    if not args.input:
        raise SystemExit("report requires <input> unless --ledger is supplied")
    round_obj = load_json(args.input)
    print(markdown_report(round_obj), end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="exclusive_grant_warrant")
    sub = parser.add_subparsers(dest="command", required=True)

    sample = sub.add_parser("sample", help="emit cleared/partial/void example rounds")
    sample.add_argument("--write", help="write examples into this directory")
    sample.set_defaults(func=cmd_sample)

    run = sub.add_parser("run", help="emit machine JSON verdict")
    run.add_argument("input", help="input JSON bidding round")
    run.add_argument("--ledger", help="append result to a JSONL grant-warrant ledger")
    run.set_defaults(func=cmd_run)

    report = sub.add_parser("report", help="emit Markdown report or verify ledger")
    report.add_argument("input", nargs="?", help="input JSON bidding round")
    report.add_argument("--ledger", help="verify a JSONL grant-warrant ledger")
    report.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
