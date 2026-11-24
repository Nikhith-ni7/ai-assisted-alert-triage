# Lab validation

Use this guide to collect Windows endpoint evidence, benchmark the hybrid model, and measure analyst time.

## Completion status on November 24, 2026

| Lab item | Status | Evidence |
| --- | --- | --- |
| Windows agent, Sysmon, Atomic tests, and alert triage | Complete for the two documented tests | Two read-only Atomic test cases ran. The current-user test generated two Wazuh alerts and two hybrid drafts. The analyst approved both current-user alerts as benign lab activity. |
| Hybrid benchmark with both Qwen models | Complete | Each run produced 19 correct rule verdicts on 25 hard cases. Independent model opinions matched 10 labels with [1.7B](../results/hybrid-qwen3-1.7b-hard.json) and 11 with [8B](../results/hybrid-qwen3-8b-hard.json). |
| Paired human timing study | Pending | The study requires two reviewers and 20 matched manual and assisted alert timings. Analyst time saved has not been measured. |

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

This live case verifies collection and drafting. Its ground truth has not been independently established, so it is excluded from the accuracy and timing studies.

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

## 3. Measure analyst time

Select 20 hard-set alerts before reviewing. Reviewer A reviews the first ten manually and the other ten with assistance. Reviewer B uses the opposite assignment. Use `--limit 10 --offset 0` for the first half and `--limit 10 --offset 10` for the second. Keep reviewers blind to reference labels and to each other's answers. Each reviewer should write to a separate review file for each mode. Combine files within a mode only after checking that each alert was reviewed once in that mode.

Compare the two review logs with `python3 cli.py metrics --fixtures fixtures/hard_alerts.jsonl --manual <manual.jsonl> --assisted <assisted.jsonl>`. Report the paired count, mean seconds per alert in each mode, and each mode's final accuracy.

### Reviewer sessions

Run the following from the repository root in an interactive terminal. Each reviewer completes their two assigned blocks privately. Press Enter only when ready to assess the next case. The CLI measures elapsed time through approval, including model latency in assisted mode.

```sh
# Reviewer A
python3 cli.py review --source fixture --fixtures fixtures/hard_alerts.jsonl --offset 0 --limit 10 --mode manual --output reviews/a-manual.jsonl
python3 cli.py review --source fixture --fixtures fixtures/hard_alerts.jsonl --offset 10 --limit 10 --mode assisted --engine hybrid --model qwen3:1.7b --output reviews/a-assisted.jsonl
```

```sh
# Reviewer B
python3 cli.py review --source fixture --fixtures fixtures/hard_alerts.jsonl --offset 0 --limit 10 --mode assisted --engine hybrid --model qwen3:1.7b --output reviews/b-assisted.jsonl
python3 cli.py review --source fixture --fixtures fixtures/hard_alerts.jsonl --offset 10 --limit 10 --mode manual --output reviews/b-manual.jsonl
```

After both reviewers finish, verify ten approved rows per file, combine the manual files and assisted files separately, and check that the metrics report includes all 20 pairs before publishing any time-saved claim.
