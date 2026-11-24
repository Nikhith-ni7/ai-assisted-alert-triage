# Lab validation

Use this guide to collect Windows endpoint evidence, evaluate draft accuracy, and measure model latency.

## Completion status on November 24, 2026

| Lab item | Status | Evidence |
| --- | --- | --- |
| Windows agent, Sysmon, Atomic tests, and alert triage | Complete for the two documented tests | Two read-only Atomic test cases ran. The current-user test generated two Wazuh alerts and two hybrid drafts. The analyst approved both current-user alerts as benign lab activity. |
| Hybrid benchmark with both Qwen models | Complete | Each run produced 19 correct rule verdicts on 25 hard cases. Independent model opinions matched 10 labels with [1.7B](../results/hybrid-qwen3-1.7b-hard.json) and 11 with [8B](../results/hybrid-qwen3-8b-hard.json). |

## 1. Verify Windows endpoint telemetry

Use an isolated Windows 11 VM, a matching Sysmon package, and an enrolled Wazuh Windows agent. Before enrollment, confirm the guest can reach the intended agent ports on a private lab network. The dashboard listens on Mac loopback. In the verified UTM run, two temporary SSH forwards on the private UTM bridge carried agent traffic and enrollment to the manager on TCP 1514 and 1515.

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

### Windows endpoint results

On November 24, 2026, the Windows 11 ARM guest enrolled in the Wazuh manager. Microsoft Sysmon recorded process creation (event ID 1). During setup, the manager received a Sysmon alert for PowerShell launching SecEdit from the Windows SysWOW64 directory.

| Observation | Verified result |
| --- | --- |
| Manager rule | 92066, executable in a suspicious location |
| Alert ID | `1795552758.710364` |
| Dashboard category | `suspicious_process` |
| Rules / Qwen 3 1.7B second opinion | Both returned `needs_review` |
| First suggested investigation step | Inspect the parent process, child process, and command line |
| Human verdict | Pending at the time of capture |

This live case verifies collection and drafting. Its ground truth has not been independently established, so it is excluded from the accuracy benchmarks.

### Atomic test observations

On November 24, 2026, two Windows test commands were executed directly in the enrolled UTM guest. The current-user check ran with the upstream test's user-only argument. The clock check requested an ISO-formatted timestamp.

| Test | Observed evidence | Analyst disposition |
| --- | --- | --- |
| [T1033 current-user check](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml), GUID `aab580c7-cc30-4a7c-b5a9-46a29066b022` | At 20:49:08 UTC Wazuh recorded rules 92052 and 92032, alert IDs `1795553348.3114219` and `1795553348.3119797`. The dashboard rules and Qwen 1.7B each returned `needs_review` for both. | Both alerts approved by the analyst as benign lab activity at 21:20:30 UTC. |
| [T1124 PowerShell clock check](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.yaml), GUID `1d5711d6-655c-4a47-ae9c-6503c74fa877` | Sysmon process creation matched the clock command. No corresponding Wazuh alert was identified in the inspected window. | Telemetry observation only. |

## 2. Run the hybrid benchmark

```sh
ollama pull qwen3:8b
python3 cli.py benchmark --fixtures fixtures/hard_alerts.jsonl --engine hybrid --model qwen3:8b \
  > results/hybrid-qwen3-8b-hard.json
python3 cli.py benchmark --fixtures fixtures/hard_alerts.jsonl --engine hybrid --model qwen3:1.7b \
  > results/hybrid-qwen3-1.7b-hard.json
```

Report `assist.model_right_rules_wrong` and `assist.rules_right_model_wrong` separately from final rules accuracy. The model's opinion never replaces the hybrid draft verdict.
