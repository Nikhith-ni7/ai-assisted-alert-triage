"""Typed evidence projection, draft validation, and benchmark scoring."""
import ipaddress
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from statistics import mean

VERDICTS = ("malicious", "benign", "needs_review")
TECHNIQUES = {
    "password_spray": ("T1110.003",),
    "mfa_push": ("T1621",),
    "new_country": ("T1078.004",),
    "impossible_travel": ("T1078.004",),
    "inbox_rule": ("T1114.003", "T1564.008"),
    "risky_signin": ("T1078.004",),
    "file_detection": ("T1204.002",),
    "unknown": (),
}
SEVERITIES = {"informational", "low", "medium", "high", "unknown"}
COUNTS = {"failed_attempts": 100_000, "distinct_accounts": 100_000, "failed_mfa": 100_000}
SIGNALS = ("successful_signin", "verified_change", "known_corporate_egress", "validated_malware")
HASH = re.compile(r"(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\Z", re.I)
ALERT_ID = re.compile(r"[a-zA-Z0-9_.-]{1,100}\Z")
PROVIDERS = {"vt_ip", "vt_hash", "abuseipdb"}
STATUSES = {"ok", "not_found", "rate_limited", "unavailable", "unauthorized", "forbidden",
            "tls_error", "network_error", "invalid_response"}


@dataclass(frozen=True)
class Alert:
    alert_id: str
    category: str
    severity: str
    counts: dict
    signals: dict
    ips: tuple
    hashes: tuple
    category_source: str


def indicators(values, kind):
    if not isinstance(values, (list, tuple)):
        return ()
    found = {}
    for value in values[:100]:
        if not isinstance(value, str) or len(value) > 64:
            continue
        if kind == "ip":
            try:
                parsed = ipaddress.ip_address(value)
                if getattr(parsed, "scope_id", None) or parsed.is_multicast:
                    continue
                value = str(parsed)
            except ValueError:
                continue
        elif not HASH.fullmatch(value):
            continue
        found[value.lower()] = None
        if len(found) == 8:
            break
    return tuple(found)


def normalize(raw, source="fixture"):
    if not isinstance(raw, dict):
        raise ValueError("Expected an alert object")
    alert_id = raw.get("id")
    if not isinstance(alert_id, str) or not ALERT_ID.fullmatch(alert_id):
        raise ValueError("Invalid alert ID")
    category, severity = raw.get("category"), raw.get("severity")
    return Alert(
        alert_id,
        category if isinstance(category, str) and category in TECHNIQUES else "unknown",
        severity if isinstance(severity, str) and severity in SEVERITIES else "unknown",
        {k: v for k, limit in COUNTS.items() if type(v := raw.get(k)) is int and 0 <= v <= limit},
        {k: raw[k] for k in SIGNALS if type(raw.get(k)) is bool},
        indicators(raw.get("ips"), "ip"),
        indicators(raw.get("hashes"), "hash"),
        source,
    )


def clean_reputation(rows):
    clean = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        provider, status = row.get("provider"), row.get("status")
        if not isinstance(provider, str) or provider not in PROVIDERS:
            continue
        if not isinstance(status, str) or status not in STATUSES:
            continue
        record = {"provider": provider, "status": status}
        if status == "ok":
            key = "score" if provider == "abuseipdb" else "malicious"
            maximum = 100 if key == "score" else 1000
            value = row.get(key)
            if type(value) is not int or not 0 <= value <= maximum:
                record["status"] = "unavailable"
            else:
                record[key] = value
        clean.append(record)
    return clean


def evidence(alert, reputation):
    # Project normalized inputs. The model only receives predefined keys,
    # enums, bounded numbers and booleans. Raw text and indicator values stay local.
    return {
        "category": alert.category,
        "category_source": alert.category_source,
        "severity": alert.severity,
        "counts": alert.counts,
        "signals": alert.signals,
        "indicator_counts": {"ips": len(alert.ips), "hashes": len(alert.hashes)},
        "reputation": clean_reputation(reputation),
        "allowed_techniques": list(TECHNIQUES[alert.category]),
    }


def validate_draft(result, allowed):
    if not isinstance(result, dict) or set(result) != {"summary", "verdict", "techniques"}:
        raise ValueError("Unexpected draft schema")
    summary, verdict, techniques = (result[k] for k in ("summary", "verdict", "techniques"))
    if not isinstance(summary, str) or not 1 <= len(summary.strip()) <= 1200:
        raise ValueError("Invalid draft summary")
    if verdict not in VERDICTS:
        raise ValueError("Invalid draft verdict")
    if not isinstance(techniques, list) or len(techniques) > len(allowed):
        raise ValueError("Invalid techniques")
    if any(not isinstance(t, str) or t not in allowed for t in techniques):
        raise ValueError("Unsupported technique")
    if len(set(techniques)) != len(techniques):
        raise ValueError("Duplicate techniques")
    return {"summary": summary, "verdict": verdict, "techniques": techniques}


def baseline(facts):
    """Deterministic reference classifier. No model call."""
    signal = facts["signals"]
    category = facts["category"]
    observed = facts["reputation"]
    confirmed = category == "file_detection" and signal.get("validated_malware")
    suspicious = any(item.get("score", 0) >= 90 or item.get("malicious", 0) >= 5 for item in observed)
    if confirmed:
        verdict, reason = "malicious", "Endpoint telemetry records a validated malware finding."
    elif signal.get("verified_change") or signal.get("known_corporate_egress"):
        verdict, reason = (
            ("needs_review", "Reported benign context conflicts with a reputation signal.")
            if suspicious
            else ("benign", "The supplied context identifies a verified change or corporate egress.")
        )
    else:
        verdict, reason = "needs_review", "Review source telemetry and corroborate the affected entity."
        if suspicious:
            reason = "Reputation flags an indicator. Verify its connection to this alert."
    return {"verdict": verdict, "summary": reason, "techniques": facts["allowed_techniques"]}


def read_jsonl(path):
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(iter(lambda: stream.readline(128_001), ""), 1):
            if len(line) > 128_000:
                raise ValueError(f"Input row {number} exceeds the size limit")
            if line.strip():
                yield json.loads(line)


def load_cases(path):
    cases = list(read_jsonl(path))
    if len(cases) != 50:
        raise ValueError("Benchmark requires exactly 50 labeled alerts")
    ids = set()
    for case in cases:
        alert = normalize(case["alert"])
        if alert.alert_id in ids or case["label"] not in VERDICTS:
            raise ValueError("Benchmark IDs must be unique and labels must be valid")
        ids.add(alert.alert_id)
    return cases


def score(cases, drafts):
    labels = {case["alert"]["id"]: case["label"] for case in cases}
    if set(drafts) != set(labels):
        raise ValueError("Draft IDs do not match the benchmark")
    confusion = {actual: dict.fromkeys(VERDICTS, 0) for actual in VERDICTS}
    for uid, label in labels.items():
        confusion[label][drafts[uid]["verdict"]] += 1
    correct = sum(confusion[label][label] for label in VERDICTS)
    return {"alerts": len(labels), "correct": correct, "accuracy": correct / len(labels),
            "confusion_actual_by_predicted": confusion, "labels": dict(Counter(labels.values()))}


def compare_reviews(cases, manual, assisted):
    labels = {case["alert"]["id"]: case["label"] for case in cases}
    paired = []
    for mode, rows in (("manual", manual), ("assisted", assisted)):
        indexed = {}
        for row in rows:
            uid = row["id"]
            seconds = row["elapsed_seconds"]
            if (row.get("mode") != mode or row.get("state") != "approved"
                    or uid not in labels or uid in indexed or row["verdict"] not in VERDICTS
                    or type(seconds) not in (float, int) or not math.isfinite(seconds) or seconds < 0):
                raise ValueError(f"Invalid {mode} review record")
            indexed[uid] = row
        paired.append(indexed)
    before, after = paired
    ids = sorted(before.keys() & after.keys())
    if not ids:
        raise ValueError("No alerts have approved reviews in both modes")
    manual_time = mean(before[uid]["elapsed_seconds"] for uid in ids)
    assisted_time = mean(after[uid]["elapsed_seconds"] for uid in ids)
    return {
        "paired_alerts": len(ids),
        "manual_seconds_per_alert": manual_time,
        "assisted_seconds_per_alert": assisted_time,
        "seconds_saved_per_alert": manual_time - assisted_time,
        "manual_final_accuracy": mean(before[uid]["verdict"] == labels[uid] for uid in ids),
        "assisted_final_accuracy": mean(after[uid]["verdict"] == labels[uid] for uid in ids),
    }
