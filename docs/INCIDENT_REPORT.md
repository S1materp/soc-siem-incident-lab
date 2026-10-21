# Incident triage: suspicious SSH activity

**Environment:** synthetic demonstration logs, not a real incident.

## Observation

The sample contains five failed SSH password attempts from `198.51.100.23` in four minutes, followed by a successful login from the same IP.

## Detection

- `SSH_BRUTE_FORCE`: five failures within ten minutes, medium severity.
- `SSH_SUCCESS_AFTER_FAILURES`: success after repeated failures, high severity.

## Initial analyst assessment

The sequence warrants investigation, but it does not prove account compromise. It may also reflect an authorized test or a shared IP address.

## Recommended L1 triage

1. Verify the source, timestamps, host, username and correlation with other logs.
2. Check whether the account owner recognizes the login and whether MFA was involved.
3. Check VPN, endpoint and identity-provider events for corroboration.
4. Preserve evidence and escalate to L2/L3 under the organization's incident procedure.
5. Document findings, uncertainties and actions. Do not block an address without authorization.

## ATT&CK context

Potential relationship to MITRE ATT&CK T1110 (Brute Force). Mapping is a hypothesis, not a confirmed attribution.

## Limitations

This is a teaching rule, not a SIEM platform or production detection. It does not parse all syslog formats, handle NAT attribution, correlate hosts, or determine malicious intent.
