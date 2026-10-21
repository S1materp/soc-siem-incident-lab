from soc_lab.analyzer import analyze, parse_line


def event(t, action='Failed', ip='198.51.100.23', user='admin'):
    return f'2026-10-20T10:{t:02d}:00Z host sshd[100]: {action} password for {user} from {ip} port 12345 ssh2'


def test_parse_failed():
    result = parse_line(event(0))
    assert result['event'] == 'failed' and result['ip'] == '198.51.100.23'


def test_parse_invalid_user():
    assert parse_line('2026-10-20T10:00:00Z host sshd[100]: Failed password for invalid user root from 192.0.2.1 port 12345 ssh2')['user'] == 'root'


def test_parse_ignores_noise_and_bad_date():
    assert parse_line('random') is None
    assert parse_line('not-a-date host sshd[100]: Failed password for root from 192.0.2.1 port 12345 ssh2') is None


def test_threshold_alert():
    report = analyze([event(i) for i in range(5)])
    assert report['summary']['alerts'] == 1
    assert report['alerts'][0]['rule_id'] == 'SSH_BRUTE_FORCE'


def test_below_threshold_no_alert():
    assert analyze([event(i) for i in range(4)])['alerts'] == []


def test_time_window_matters():
    lines = [f'2026-10-20T10:{i * 11:02d}:00Z host sshd[100]: Failed password for root from 192.0.2.1 port 12345 ssh2' for i in range(2)]
    assert analyze(lines, threshold=2, window_minutes=10)['alerts'] == []


def test_success_after_failures_is_high():
    report = analyze([event(i) for i in range(5)] + [event(5, 'Accepted', user='deploy')])
    assert [a['severity'] for a in report['alerts']] == ['medium', 'high']


def test_success_from_other_ip_not_flagged():
    report = analyze([event(i) for i in range(5)] + [event(5, 'Accepted', ip='192.0.2.2')])
    assert len(report['alerts']) == 1


def test_invalid_configuration():
    import pytest
    with pytest.raises(ValueError):
        analyze([], threshold=0)
