# AI-assisted alert triage

A Python CLI that reads Wazuh alerts and pulls Sentinel incident alerts, looks up indicator reputation, and drafts a verdict and MITRE ATT&CK mapping for an analyst to review. An analyst must explicitly approve or replace every recorded verdict. The tool makes no SIEM changes.

**Recommended lab source** is Wazuh. Its software is free and open source. This CLI reads the manager's `/var/ossec/logs/alerts/alerts.json` from the local Docker container or from a copied export. Sentinel is an optional alternative and requires access to an existing workspace. [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html) · [Wazuh alert files](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html) · [Sentinel alert endpoint](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-alerts?view=rest-securityinsights-2025-09-01)

## Run locally

Python 3.10+ with the standard library is enough. From this directory:

```sh
python3 dashboard_server.py
```

Open the printed loopback URL. Switch the alert source between the synthetic queue and the local Wazuh manager, filter alerts, inspect evidence, and explicitly approve a verdict. The dashboard can draft with your local `qwen3:1.7b` Ollama model and opt into public indicator lookups for an individual Wazuh alert. Approved verdicts are saved locally in `reviews/dashboard.sqlite3`. The Benchmarks view shows recorded verdict accuracy and draft latency. Use the CLI below to collect and compare paired analyst timings.

### Command-line tools

```sh
python3 -m unittest discover -s tests
python3 cli.py benchmark
mkdir -p reviews
python3 cli.py review --source wazuh --alerts fixtures/wazuh_sample.jsonl \
  --mode assisted --engine baseline --output reviews/wazuh-demo.jsonl
```

The included Wazuh sample is synthetic. Swap in a copied manager export when available. The local baseline is a transparent reference policy. Use `--engine llm --model "$TRIAGE_MODEL"` with an OpenAI chat model that supports JSON output and an `OPENAI_API_KEY` in the environment. Model calls may incur charges. The 50-alert fixture benchmark accepts the same model flags. [OpenAI API request options](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)

## Run against the local Wazuh manager

With the `wazuh` Colima profile and its Wazuh containers running, start Ollama on loopback if it is stopped and pull `qwen3:1.7b`. Then run:

```sh
python3 cli.py preview --source wazuh-docker --engine ollama --model qwen3:1.7b --limit 3
python3 cli.py review --source wazuh-docker --mode assisted --engine ollama \
  --model qwen3:1.7b --limit 3 --output reviews/wazuh-local.jsonl
python3 cli.py benchmark --engine ollama --model qwen3:1.7b
```

The preview prints pending drafts and records no approvals. Review requires a terminal. Set `--docker-context` and `--wazuh-container` if your local names differ. The Ollama adapter sends the same projected JSON as the OpenAI adapter to `127.0.0.1:11434`, with redirects and HTTP proxies disabled for that local endpoint. [Qwen model](https://ollama.com/library/qwen3)

For Sentinel, set `AZURE_ACCESS_TOKEN` to a short-lived Azure Resource Manager token with read access to the workspace and use:

```sh
python3 cli.py review --source sentinel --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" --workspace "$WORKSPACE" \
  --mode assisted --engine baseline --limit 5 --output reviews/sentinel.jsonl
```

Sentinel retrieves alerts for recent incidents. It uses incident-level indicators only where the incident contains a single alert. Wazuh uses an allowlist of known MITRE rule tags and Sentinel uses exact mappings for known lab rule titles. Unknown mappings remain empty and need analyst review.

## Reputation enrichment

Copy `.env.example` to `.env` in this directory and fill in `VT_API_KEY` and optionally `ABUSEIPDB_API_KEY`. The `.env` file is ignored by Git. Environment variables take precedence, and `VIRUSTOTAL_API_KEY` is also accepted as an alias. Add `--enrich` to a live-source assisted review to enable lookups. VirusTotal receives public IPs and validated file hashes as lookup identifiers. AbuseIPDB receives public IPs. Lookups are cached for the current session and capped at four per provider per invocation by default. Confirm your account quotas and data-sharing rules before enabling lookups. VirusTotal's public API is intended for permitted noncommercial use. [VirusTotal API terms and setup](https://docs.virustotal.com/reference/getting-started) · [AbuseIPDB API](https://docs.abuseipdb.com/)

From a terminal, run `python3 cli.py check-enrichment --provider vt` to test your VirusTotal key against a public IP and a file hash. If the key is absent from both `.env` and the environment, the command asks for it with input hidden. The check does not save a key or upload a file. Use `--provider abuseipdb` for an AbuseIPDB IP lookup check.

## Prompt-injection defense

The model input is a schema projection. Log messages, alert descriptions, evidence links, raw IPs, raw hashes, account names, arbitrary fields, and benchmark labels stay out of the model payload. Normalization admits known categories, bounded counts, booleans, and numeric reputation. Model output must pass a second validation step before it can be displayed as a draft. MITRE IDs must come from the mapping candidates supplied for that alert.

The model has no tools, SIEM write access, or authority to record a verdict. Interactive review can approve a draft, replace the verdict, skip it, or quit. Only an explicit decision writes a final verdict to a new local JSONL review file. Run reviews under an authorized analyst's OS account and keep review files out of Git.

## Measure accuracy and analyst time

The fixture has 50 labeled synthetic alerts built from ten scenario families with variation. Several log fields include instruction-like text for injection regression checks.

| Verified run | Result |
| --- | --- |
| Local Wazuh Docker → Ollama | Three real manager alerts produced three valid drafts, all pending human review. These were manager alerts, with no endpoint agent involved. |
| Public indicator enrichment → Ollama | A synthetic Wazuh-format alert returned successful VirusTotal IP and hash lookups and an AbuseIPDB IP lookup. The local model drafted `needs_review`, pending human approval. |
| Reference baseline | [35/50 (70%)](results/baseline-benchmark.json). It routed 15 of 20 malicious cases for human review. |
| Local Qwen3 1.7B | [24/50 (48%)](results/qwen3-1.7b-benchmark.json), about 1.21 seconds per draft. It flagged one benign alert as malicious and sent most benign alerts to review. |

The baseline scored higher on this fixture. Draft latency measures software runtime. Analyst time saved requires paired human review sessions.

To measure time saved, collect **two independent, blinded reviews** of the same alert IDs, one manual and one assisted. Use different analysts or counterbalance review order and avoid exposing the labels during review. The timer starts when an analyst opens a case and includes drafting and enrichment in assisted mode. Alert retrieval is outside the timer.

```sh
python3 cli.py review --source fixture --mode manual --limit 50 \
  --output reviews/manual.jsonl
python3 cli.py review --source fixture --mode assisted --engine ollama \
  --model qwen3:1.7b --limit 50 --reverse --output reviews/assisted.jsonl
python3 cli.py metrics --manual reviews/manual.jsonl --assisted reviews/assisted.jsonl
```

The paired report includes the number of completed pairs, mean seconds per alert in each mode, mean seconds saved, and final analyst verdict accuracy. Draft accuracy is a separate benchmark. No human timing result is included until the paired reviews have been collected.
