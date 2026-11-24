# Lab validation

Use this guide to collect Windows endpoint evidence, benchmark the hybrid model, and measure analyst time.

## 1. Verify Windows endpoint telemetry

Use an isolated Windows 11 VM, a matching Sysmon package, and an enrolled Wazuh Windows agent. Before enrollment, confirm the guest can reach the intended agent ports on a private lab network. The Mac's existing Wazuh install publishes only the dashboard on loopback.

Configure the agent to collect the Sysmon event channel:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Verify that an ordinary application launch appears in the Windows event channel. Confirm it arrives in Wazuh and inspect the assigned rule and MITRE tags if the event generated an alert. Use the synthetic Wazuh fixture to exercise the suspicious process mapping independently.

```sh
python3 cli.py preview --source wazuh-docker --engine hybrid --model qwen3:1.7b --limit 20
python3 cli.py preview --source wazuh --alerts fixtures/wazuh_sample.jsonl \
  --engine hybrid --model qwen3:1.7b --limit 3
```

Record the source, UTC timestamp, Wazuh rule ID, mapped category, and pending draft outcome. Label synthetic records separately and redact identifying fields before publishing evidence.

## 2. Run the hybrid benchmark

```sh
ollama pull qwen3:8b
python3 cli.py benchmark --fixtures fixtures/hard_alerts.jsonl --engine hybrid --model qwen3:8b \
  > results/hybrid-qwen3-8b-hard.json
python3 cli.py benchmark --fixtures fixtures/hard_alerts.jsonl --engine hybrid --model qwen3:1.7b \
  > results/hybrid-qwen3-1.7b-hard.json
```

Report `assist.model_right_rules_wrong` and `assist.rules_right_model_wrong` separately from final rules accuracy. The model's opinion never replaces the hybrid draft verdict.

## 3. Measure analyst time

Select 20 hard-set alerts before reviewing. Reviewer A reviews the first ten manually and the other ten with assistance. Reviewer B uses the opposite assignment. Keep reviewers blind to reference labels and to each other's answers. Each reviewer should write to a separate review file for each mode. Combine files within a mode only after checking that each alert was reviewed once in that mode.

Compare the two review logs with `python3 cli.py metrics --fixtures fixtures/hard_alerts.jsonl --manual <manual.jsonl> --assisted <assisted.jsonl>`. Report the paired count, mean seconds per alert in each mode, and each mode's final accuracy.
