# SOC Incident Triage Lab | Python + Linux SSH logs

A defensive portfolio project for an entry-level SOC / cybersecurity internship. The project demonstrates how to parse Linux authentication logs, detect repeated SSH login failures, correlate a subsequent successful login, produce a JSON alert report, and document an L1 investigation.

**All included events are synthetic. No credentials, real customer data, or production logs are included.**

## What it demonstrates

- Linux `sshd` authentication log parsing
- SIEM-style detection logic with time windows and thresholds
- Event correlation and severity-based triage
- JSON output suitable for later integration with a SIEM or dashboard
- Incident documentation and escalation workflow
- Python unit tests and GitHub Actions CI

## Run

Requires Python 3.10+.

```bash
python -m soc_lab samples/auth.log
python -m soc_lab samples/auth.log --threshold 5 --window-minutes 10 --output reports/sample-report.json
```

## Test

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Detection rules

| Rule | Condition | Severity |
| --- | --- | --- |
| `SSH_BRUTE_FORCE` | At least 5 failures from one IP within 10 minutes | Medium |
| `SSH_SUCCESS_AFTER_FAILURES` | Success from a flagged IP after 5+ recent failures | High |

Threshold and window are configurable. One brute-force alert is emitted per IP per run to avoid alert flooding. These are demonstration heuristics, not verified production detections.

## Example output

The sample produces two alerts, one medium and one high. See `docs/INCIDENT_REPORT.md` for a complete analyst-style case note.

## Scope and security

Only process logs you own or are authorized to analyze. This project does not attack systems, scan networks, or attempt authentication. Addresses in the sample belong to documentation-only ranges (RFC 5737). A real SOC should validate false positives, timezone handling, log retention, identity context, and escalation procedures.

## Next improvements

- Add Windows Event ID 4625/4624 parsing and correlation
- Export Sigma detection rules and test them against synthetic fixtures
- Add a simple Streamlit incident dashboard
- Connect a local open-source SIEM in a disposable lab
- Add a human-reviewed LLM assistant for incident summaries without exposing sensitive logs
