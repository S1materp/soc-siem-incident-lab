"""Analyze synthetic Linux SSH authentication events for SOC triage."""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re

FAILED = re.compile(r"^(?P<time>\S+) \S+ sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>[\w.-]+) from (?P<ip>[\d.]+) port \d+")
ACCEPTED = re.compile(r"^(?P<time>\S+) \S+ sshd\[\d+\]: Accepted password for (?P<user>[\w.-]+) from (?P<ip>[\d.]+) port \d+")

def parse_line(line: str) -> dict | None:
    for kind, pattern in (("failed", FAILED), ("accepted", ACCEPTED)):
        match = pattern.match(line.strip())
        if match:
            try:
                stamp = datetime.fromisoformat(match['time'].replace('Z', '+00:00'))
            except ValueError:
                return None
            if stamp.tzinfo is None:
                return None
            return {"timestamp": stamp.astimezone(timezone.utc), "event": kind, "user": match['user'], "ip": match['ip']}
    return None

def analyze(lines: list[str], threshold: int = 5, window_minutes: int = 10) -> dict:
    if threshold < 1 or window_minutes < 1:
        raise ValueError('threshold and window_minutes must be positive')
    events = sorted((e for line in lines if (e := parse_line(line)) is not None), key=lambda e: e['timestamp'])
    failures = defaultdict(list)
    for event in events:
        if event['event'] == 'failed':
            failures[event['ip']].append(event)
    alerts = []
    flagged = set()
    window = timedelta(minutes=window_minutes)
    for ip, attempts in sorted(failures.items()):
        left = 0
        for right, event in enumerate(attempts):
            while event['timestamp'] - attempts[left]['timestamp'] > window:
                left += 1
            if right - left + 1 >= threshold:
                flagged.add(ip)
                alerts.append({"rule_id": "SSH_BRUTE_FORCE", "severity": "medium", "source_ip": ip,
                               "first_seen": attempts[left]['timestamp'].isoformat(),
                               "last_seen": event['timestamp'].isoformat(), "failure_count": right - left + 1,
                               "description": "Repeated SSH authentication failures within time window"})
                break
    for event in events:
        if event['event'] != 'accepted' or event['ip'] not in flagged:
            continue
        prior = [a for a in failures[event['ip']] if timedelta(0) <= event['timestamp'] - a['timestamp'] <= window]
        if len(prior) >= threshold:
            alerts.append({"rule_id": "SSH_SUCCESS_AFTER_FAILURES", "severity": "high", "source_ip": event['ip'],
                           "user": event['user'], "timestamp": event['timestamp'].isoformat(),
                           "failure_count": len(prior), "description": "Successful SSH login after repeated failures"})
    return {"summary": {"parsed_events": len(events), "failed_logins": sum(e['event'] == 'failed' for e in events),
                        "successful_logins": sum(e['event'] == 'accepted' for e in events), "alerts": len(alerts)},
            "alerts": alerts}

def main() -> None:
    parser = argparse.ArgumentParser(description='Defensive SSH SOC triage on synthetic or authorized logs')
    parser.add_argument('logfile', type=Path)
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window-minutes', type=int, default=10)
    parser.add_argument('--output', type=Path, help='Optional JSON report file')
    args = parser.parse_args()
    report = analyze(args.logfile.read_text(encoding='utf-8').splitlines(), args.threshold, args.window_minutes)
    result = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result + '\n', encoding='utf-8')
    print(result)

if __name__ == '__main__':
    main()
