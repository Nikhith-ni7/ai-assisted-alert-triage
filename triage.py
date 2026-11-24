"""Typed evidence projection, draft validation, and benchmark scoring."""
import ipaddress
import json
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
    "suspicious_process": ("T1059.001", "T1218.005", "T1218.011"),
    "credential_access": ("T1003.001",),
    "defense_evasion": ("T1562.001",),
    "inhibit_recovery": ("T1490",),
    "unknown": (),
}
SEVERITIES = {"informational", "low", "medium", "high", "unknown"}
COUNTS = {"failed_attempts": 100_000, "distinct_accounts": 100_000, "failed_mfa": 100_000,
          "distinct_countries": 50, "account_age_days": 36_500, "minutes_since_first_failure": 10_080}
SIGNALS = (
    "successful_signin",            # a sign-in succeeded in the alert window
    "success_account_was_targeted",  # the account that succeeded was one of the attacked accounts
    "mfa_satisfied",                # MFA was completed on the successful sign-in
    "new_device",                   # first sign-in from this device for the user
    "hosting_or_vpn_ip",            # source IP belongs to a hosting, VPN or anonymizer network
    "admin_account",                # the account holds a privileged role
    "external_forward",             # mailbox rule forwards or redirects outside the organization
    "hides_mail",                   # mailbox rule deletes, marks read or moves mail to RSS/Archive
    "verified_change",              # change matched to an approved ticket
    "known_corporate_egress",       # source IP is a documented corporate egress
    "user_confirmed_activity",      # account owner confirmed the activity out of band
    "validated_malware",            # endpoint analysis confirmed the file is malicious
)
# Parent -> child process patterns, derived locally from process paths. Paths never reach the model.
PROCESS_CHAINS = ("none", "office_to_script", "explorer_to_shell", "browser_to_shell",
                  "service_to_shell", "script_to_lolbin", "other")
STEPS = {
    "check_success_after_failures": "Check whether any targeted account signed in successfully from the same IP.",
    "review_mfa_outcomes": "Review MFA results for the user and confirm whether any request was approved.",
    "contact_user": "Contact the account owner out of band to confirm the activity.",
    "check_ip_ownership": "Check who owns the source IP (corporate egress, VPN, hosting, mobile carrier).",
    "review_device": "Review the device and browser used for the sign-in against the user's known devices.",
    "review_mailbox_rules": "List all mailbox rules for the user and check destinations and target folders.",
    "check_change_ticket": "Look for an approved change ticket that matches this activity.",
    "review_process_tree": "Review the parent and child processes and the full command line on the host.",
    "check_file_reputation": "Check the file hash reputation and where the file came from.",
    "isolate_host_pending_review": "Recommend host isolation to the incident lead if malicious activity is confirmed.",
    "reset_credentials_pending_review": "Recommend a password reset and session revocation if compromise is confirmed.",
    "check_backups": "Confirm backups and shadow copies are intact and check other hosts for the same command.",
}
CATEGORY_STEPS = {
    "password_spray": ("check_success_after_failures", "check_ip_ownership", "contact_user", "reset_credentials_pending_review"),
    "mfa_push": ("review_mfa_outcomes", "contact_user", "review_device", "reset_credentials_pending_review"),
    "new_country": ("check_ip_ownership", "review_device", "contact_user"),
    "impossible_travel": ("check_ip_ownership", "review_device", "contact_user"),
    "inbox_rule": ("review_mailbox_rules", "check_change_ticket", "contact_user", "reset_credentials_pending_review"),
    "risky_signin": ("review_device", "check_ip_ownership", "contact_user", "reset_credentials_pending_review"),
    "file_detection": ("check_file_reputation", "review_process_tree", "isolate_host_pending_review"),
    "suspicious_process": ("review_process_tree", "check_change_ticket", "isolate_host_pending_review"),
    "credential_access": ("review_process_tree", "check_change_ticket", "isolate_host_pending_review", "reset_credentials_pending_review"),
    "defense_evasion": ("review_process_tree", "check_change_ticket", "isolate_host_pending_review"),
    "inhibit_recovery": ("check_change_ticket", "check_backups", "isolate_host_pending_review"),
    "unknown": ("check_ip_ownership", "check_file_reputation"),
}
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
    process_chain: str = "none"


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
        chain if isinstance(chain := raw.get("process_chain"), str) and chain in PROCESS_CHAINS else "none",
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
        "process_chain": alert.process_chain,
        "indicator_counts": {"ips": len(alert.ips), "hashes": len(alert.hashes)},
        "reputation": clean_reputation(reputation),
        "allowed_techniques": list(TECHNIQUES[alert.category]),
        "allowed_steps": list(CATEGORY_STEPS[alert.category]),
    }


def validate_draft(result, allowed, allowed_steps=()):
    required = {"summary", "verdict", "techniques"}
    if not isinstance(result, dict) or not required <= set(result) <= required | {"steps"}:
        raise ValueError("Unexpected draft schema")
    steps = result.get("steps", [])
    if (not isinstance(steps, list) or len(steps) > 4
            or any(not isinstance(s, str) or s not in allowed_steps for s in steps)
            or len(set(steps)) != len(steps)):
        raise ValueError("Invalid investigation steps")
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
    return {"summary": summary, "verdict": verdict, "techniques": techniques, "steps": steps}


def baseline(facts):
    """Deterministic decision rules. No model call.

    Rules decide the verdict. Each rule needs a specific attack sequence, not a single
    signal; reputation alone never makes an alert malicious.
    """
    signal, counts = facts["signals"], facts["counts"]
    category, chain = facts["category"], facts.get("process_chain", "none")
    observed = facts["reputation"]
    flagged = any(item.get("score", 0) >= 90 or item.get("malicious", 0) >= 5 for item in observed)
    explained = (signal.get("verified_change") or signal.get("known_corporate_egress")
                 or signal.get("user_confirmed_activity"))

    attack = None
    if category == "file_detection" and signal.get("validated_malware"):
        attack = "Endpoint analysis confirmed the file is malicious."
    elif (category == "password_spray" and signal.get("successful_signin")
          and signal.get("success_account_was_targeted")):
        attack = "A sprayed account then signed in successfully."
    elif (category == "mfa_push" and counts.get("failed_mfa", 0) >= 3
          and signal.get("successful_signin") and signal.get("mfa_satisfied")):
        attack = "Repeated MFA denials were followed by an approved sign-in."
    elif category == "inbox_rule" and signal.get("external_forward"):
        attack = "A mailbox rule forwards mail outside the organization."
    elif category == "inbox_rule" and signal.get("hides_mail") and not signal.get("verified_change"):
        attack = "A mailbox rule hides incoming mail without an approved change."
    elif category == "suspicious_process" and chain == "office_to_script":
        attack = "An Office application started a script host."
    elif category == "credential_access" and chain != "none":
        attack = "A process accessed credential material on the host."
    elif category == "inhibit_recovery":
        attack = "Shadow copies or backups were deleted."

    if attack and explained:
        verdict, reason = "needs_review", f"{attack} Documented context conflicts with this; verify it."
        if category in {"credential_access", "inhibit_recovery", "suspicious_process", "inbox_rule"} \
                and signal.get("verified_change") and not signal.get("external_forward"):
            verdict, reason = "benign", "The activity matches an approved change ticket."
    elif attack:
        verdict, reason = "malicious", attack
    elif explained and flagged:
        verdict, reason = "needs_review", "Documented benign context conflicts with a reputation signal."
    elif explained:
        verdict, reason = "benign", "The activity matches a verified change, corporate egress or user confirmation."
    else:
        verdict, reason = "needs_review", "No confirmed attack sequence. Corroborate before deciding."
        if flagged:
            reason = "Reputation flags an indicator, but reputation alone is not proof. Verify the link."
    return {"verdict": verdict, "summary": reason, "techniques": facts["allowed_techniques"],
            "steps": facts["allowed_steps"][:2]}


def combine_hybrid_draft(rules, note):
    return {
        "verdict": rules["verdict"],
        "rule_reason": rules["summary"],
        "summary": note["summary"],
        "steps": note["steps"] or rules["steps"],
        "techniques": rules["techniques"],
        "model_verdict": note["verdict"],
        "disagreement": note["verdict"] != rules["verdict"],
    }


def read_jsonl(path):
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(iter(lambda: stream.readline(128_001), ""), 1):
            if len(line) > 128_000:
                raise ValueError(f"Input row {number} exceeds the size limit")
            if line.strip():
                yield json.loads(line)


def load_cases(path):
    cases = list(read_jsonl(path))
    if len(cases) < 10:
        raise ValueError("A benchmark needs at least 10 labeled alerts")
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
    by_category = {}
    for case in cases:
        uid, category = case["alert"]["id"], case["alert"].get("category", "unknown")
        entry = by_category.setdefault(category, {"alerts": 0, "correct": 0})
        entry["alerts"] += 1
        entry["correct"] += drafts[uid]["verdict"] == labels[uid]
    missed_malicious = sum(confusion["malicious"][v] for v in ("benign",))
    return {"alerts": len(labels), "correct": correct, "accuracy": correct / len(labels),
            "confusion_actual_by_predicted": confusion, "labels": dict(Counter(labels.values())),
            "malicious_closed_as_benign": missed_malicious,
            "by_category": dict(sorted(by_category.items()))}


def score_assist(cases, drafts):
    """How the model's own verdict compares with the rules in hybrid mode."""
    labels = {case["alert"]["id"]: case["label"] for case in cases}
    rows = [(labels[uid], d["verdict"], d["model_verdict"]) for uid, d in drafts.items()
            if d.get("model_verdict")]
    return {
        "model_accuracy": mean(m == label for label, _, m in rows) if rows else None,
        "disagreements": sum(r != m for _, r, m in rows),
        "model_right_rules_wrong": sum(r != label and m == label for label, r, m in rows),
        "rules_right_model_wrong": sum(r == label and m != label for label, r, m in rows),
    }
