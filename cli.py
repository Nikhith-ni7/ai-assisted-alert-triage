"""Human-reviewed alert triage and offline benchmark command line."""
import argparse
from datetime import datetime, timezone
from getpass import getpass
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from time import perf_counter

from services import Reputation, ServiceError, llm_draft, ollama_draft, sentinel_alerts, wazuh_alert, wazuh_docker_alerts
from triage import VERDICTS, baseline, clean_reputation, compare_reviews, evidence, load_cases, normalize, read_jsonl, score, score_assist

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "labeled_alerts.jsonl"
ENGINES = ("baseline", "ollama", "llm", "hybrid")


def model_key(args):
    if args.engine == "hybrid":
        if not args.model:
            raise ValueError("Provide --model for the hybrid engine (Ollama tag, or OpenAI model with --provider openai)")
        if getattr(args, "provider", "ollama") == "openai":
            if not os.getenv("OPENAI_API_KEY"):
                raise ValueError("Set OPENAI_API_KEY for --provider openai")
            return os.environ["OPENAI_API_KEY"]
        return None
    if args.engine == "ollama":
        if not args.model:
            raise ValueError("Provide --model with a locally installed Ollama model tag")
        return None
    if args.engine != "llm":
        return None
    if not args.model or not os.getenv("OPENAI_API_KEY"):
        raise ValueError("Provide --model and set OPENAI_API_KEY for the LLM engine")
    return os.environ["OPENAI_API_KEY"]


def hybrid_draft(args, facts, key):
    """Rules decide the verdict. The model writes the note, picks investigation steps and
    gives its own verdict, which is shown to the analyst only as a second opinion."""
    rules = baseline(facts)
    if getattr(args, "provider", "ollama") == "openai":
        note = llm_draft(facts, args.model, key)
    else:
        note = ollama_draft(facts, args.model)
    return {
        "verdict": rules["verdict"],
        "rule_reason": rules["summary"],
        "summary": note["summary"],
        "steps": note["steps"] or rules["steps"],
        "techniques": rules["techniques"],
        "model_verdict": note["verdict"],
        "disagreement": note["verdict"] != rules["verdict"],
    }


def draft_for(args, facts, key):
    if args.engine == "baseline":
        return baseline(facts)
    if args.engine == "hybrid":
        return hybrid_draft(args, facts, key)
    if args.engine == "ollama":
        return ollama_draft(facts, args.model)
    return llm_draft(facts, args.model, key)


def benchmark(args):
    key = model_key(args)
    cases = load_cases(args.fixtures)
    drafts = {}
    started = perf_counter()
    for case in cases:
        alert = normalize(case["alert"])
        drafts[alert.alert_id] = draft_for(args, evidence(alert, case.get("reputation", [])), key)
    report = score(cases, drafts)
    if args.engine == "hybrid":
        report["assist"] = score_assist(cases, drafts)
        report["provider"] = args.provider
    report["engine"] = args.engine
    if args.model and args.engine != "baseline":
        report["model"] = args.model
    report["average_draft_seconds"] = (perf_counter() - started) / len(cases)
    report["human_time_saved"] = None
    report["dataset"] = Path(args.fixtures).stem
    print(json.dumps(report, indent=2))


def source_alerts(args):
    if args.source == "fixture":
        cases = load_cases(args.fixtures)
        if args.reverse:
            cases.reverse()
        for case in cases[:args.limit]:
            yield normalize(case["alert"]), case.get("reputation", [])
    elif args.source == "wazuh":
        if not args.alerts:
            raise ValueError("Provide --alerts with a Wazuh alerts.json export")
        for index, row in enumerate(read_jsonl(args.alerts)):
            if index >= args.limit:
                break
            yield wazuh_alert(row), []
    elif args.source == "wazuh-docker":
        for alert in wazuh_docker_alerts(args.docker_context, args.wazuh_container, args.limit):
            yield alert, []
    else:
        token = os.getenv("AZURE_ACCESS_TOKEN")
        if not token or not all((args.subscription, args.resource_group, args.workspace)):
            raise ValueError("Sentinel requires AZURE_ACCESS_TOKEN and all three workspace arguments")
        for alert in sentinel_alerts(args.subscription, args.resource_group, args.workspace, token, args.limit):
            yield alert, []


def human_decision(draft):
    if draft:
        print("Draft for review:")
        # JSON escaping protects the terminal from model-supplied control characters.
        print(json.dumps(draft, ensure_ascii=True, indent=2))
        labels = "approve, " + ", ".join(VERDICTS)
    else:
        labels = ", ".join(VERDICTS)
    while True:
        answer = input(f"Decision ({labels}, skip, quit): ").strip().lower()
        if answer == "approve" and draft:
            return draft["verdict"]
        if answer in VERDICTS or answer in {"skip", "quit"}:
            return answer
        print("Enter one of the listed choices.")


def review(args):
    if not sys.stdin.isatty():
        raise ValueError("Review requires an interactive terminal")
    if not args.engine and args.mode == "assisted":
        raise ValueError("Choose --engine baseline, hybrid, ollama or llm for assisted review")
    if args.mode == "manual" and (args.engine or args.enrich):
        raise ValueError("Manual review does not use a draft engine or live enrichment")
    if args.enrich and args.source == "fixture":
        raise ValueError("Fixtures use recorded enrichment. Remove --enrich")
    key = model_key(args) if args.mode == "assisted" else None
    reputation = Reputation(args.lookup_budget) if args.enrich else None
    recorded = 0
    seen = set()
    # Exclusive creation prevents replacing or mixing two review sessions.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as log:
        for alert, fixture_reputation in source_alerts(args):
            if alert.alert_id in seen:
                continue
            seen.add(alert.alert_id)
            input("Press Enter when ready to review the next alert. ")
            started = perf_counter()
            facts = evidence(alert, reputation.enrich(alert) if reputation else fixture_reputation)
            print(json.dumps({"alert_id": alert.alert_id, **facts, "local_ips": alert.ips,
                              "local_hashes": alert.hashes}, ensure_ascii=True, indent=2))
            draft = draft_for(args, facts, key) if args.mode == "assisted" else None
            decision = human_decision(draft)
            elapsed = perf_counter() - started
            if decision == "quit":
                break
            if decision == "skip":
                continue
            log.write(json.dumps({
                "id": alert.alert_id, "mode": args.mode, "state": "approved",
                "verdict": decision, "draft_verdict": draft["verdict"] if draft else None,
                "engine": args.engine, "model": args.model if draft else None,
                "elapsed_seconds": round(elapsed, 4),
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
            }) + "\n")
            log.flush()
            recorded += 1
    print(f"Approved verdicts recorded: {recorded}")


def preview(args):
    key = model_key(args)
    if args.enrich and args.source == "fixture":
        raise ValueError("Fixtures use recorded enrichment. Remove --enrich")
    reputation = Reputation(args.lookup_budget) if args.enrich else None
    for alert, fixture_reputation in source_alerts(args):
        facts = evidence(alert, reputation.enrich(alert) if reputation else fixture_reputation)
        print(json.dumps({"id": alert.alert_id, "state": "pending_review",
                          "evidence": facts, "draft": draft_for(args, facts, key)}, ensure_ascii=True))


def metrics(args):
    print(json.dumps(compare_reviews(load_cases(args.fixtures), read_jsonl(args.manual),
                                     read_jsonl(args.assisted)), indent=2))


def check_enrichment(args):
    reputation = Reputation(budget=2)
    provider = args.provider
    if not reputation.keys[provider]:
        if not sys.stdin.isatty():
            raise ValueError("Set the API key in the environment or run this check in a terminal")
        key = getpass(f"{provider} API key: ").strip()
        if not key:
            raise ValueError("No API key entered")
        reputation.keys[provider] = key
    # Public, fixed probes. The hash is for empty bytes. No file is uploaded.
    probes = [("vt_ip", "1.1.1.1"), ("vt_hash", sha256(b"").hexdigest())] if provider == "vt" else [
        ("abuseipdb", "1.1.1.1"),
    ]
    results = clean_reputation(reputation.lookup(service, value) for service, value in probes)
    print(json.dumps(results, indent=2))
    # A 404 confirms that the key worked but the provider lacks the indicator.
    if any(result["status"] not in {"ok", "not_found"} for result in results):
        raise ValueError("One or more live checks failed; inspect the lookup statuses above")


def add_source_flags(command):
    command.add_argument("--source", choices=("wazuh", "wazuh-docker", "sentinel", "fixture"), required=True)
    command.add_argument("--engine", choices=ENGINES)
    command.add_argument("--model")
    command.add_argument("--provider", choices=("ollama", "openai"), default="ollama",
                         help="Model backend for --engine hybrid")
    command.add_argument("--fixtures", type=Path, default=FIXTURE)
    command.add_argument("--alerts", type=Path)
    command.add_argument("--docker-context", default="colima-wazuh")
    command.add_argument("--wazuh-container", default="single-node-wazuh.manager-1")
    command.add_argument("--subscription")
    command.add_argument("--resource-group")
    command.add_argument("--workspace")
    command.add_argument("--limit", type=int, choices=range(1, 51), default=10, metavar="1–50")
    command.add_argument("--reverse", action="store_true", help="Reverse the fixture order")
    command.add_argument("--enrich", action="store_true", help="Enable third-party indicator lookups")
    command.add_argument("--lookup-budget", type=int, choices=range(1, 5), default=4, metavar="1–4")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    evaluate = actions.add_parser("benchmark", help="Score draft verdicts on a labeled alert set")
    evaluate.add_argument("--engine", choices=ENGINES, default="baseline")
    evaluate.add_argument("--model")
    evaluate.add_argument("--provider", choices=("ollama", "openai"), default="ollama")
    evaluate.add_argument("--fixtures", type=Path, default=FIXTURE)
    evaluate.set_defaults(handler=benchmark)

    queue = actions.add_parser("review", help="Review and explicitly approve verdicts")
    add_source_flags(queue)
    queue.add_argument("--mode", choices=("manual", "assisted"), required=True)
    queue.add_argument("--output", type=Path, required=True)
    queue.set_defaults(handler=review)

    inspect = actions.add_parser("preview", help="Print pending drafts without approving any verdicts")
    add_source_flags(inspect)
    inspect.set_defaults(handler=preview, engine="baseline")

    report = actions.add_parser("metrics", help="Compare paired, approved manual and assisted reviews")
    report.add_argument("--fixtures", type=Path, default=FIXTURE)
    report.add_argument("--manual", type=Path, required=True)
    report.add_argument("--assisted", type=Path, required=True)
    report.set_defaults(handler=metrics)

    health = actions.add_parser("check-enrichment", help="Verify a reputation API key using public probes")
    health.add_argument("--provider", choices=("vt", "abuseipdb"), required=True)
    health.set_defaults(handler=check_enrichment)
    args = parser.parse_args()
    try:
        args.handler(args)
    except (ValueError, OSError, ServiceError, EOFError, KeyError, TypeError) as exc:
        if isinstance(exc, (KeyError, TypeError, json.JSONDecodeError)):
            print("Invalid input or service response shape", file=sys.stderr)
        else:
            print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nReview interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
