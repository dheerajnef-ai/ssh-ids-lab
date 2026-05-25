#!/usr/bin/env python3
"""SSH failed-login checker — reads auth logs and flags repeat failures."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# Fake Linux log for offline practice (not real traffic).
SAMPLE_AUTH_LOG = Path(__file__).resolve().parent / "sample_auth (sample).log"


_LINUX_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.I,
)
_LINUX_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.I,
)
_MAC_FAILED = re.compile(
    r"Failed to authenticate user (?P<user>\S+).*?(?P<ip>\d+\.\d+\.\d+\.\d+)?",
    re.I,
)
_MAC_PASSWORD_ATTEMPT = re.compile(
    r"Failed password attempt for user (?P<user>\S+)(?: from (?P<ip>\S+))?",
    re.I,
)
_MAC_AUTH_FAILURE = re.compile(
    r"authentication failure(?:.*?(?:for|user)[:\s]+[\"']?(?P<user>[^\"'\s,]+)[\"']?)?",
    re.I,
)
_MAC_PAM_ERROR = re.compile(
    r"PAM: authentication error for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.I,
)
_TS_MAC = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_TS_LINUX = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_GENERIC_IP = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
_IPV6_LOOPBACK = re.compile(r"::1")
_GENERIC_FAILED = re.compile(
    r"Failed (?:password|to authenticate)|authentication failure|Failed password attempt",
    re.I,
)


def _extract_ip(line: str) -> str:
    m = _GENERIC_IP.search(line)
    if m:
        return m.group("ip")
    if _IPV6_LOOPBACK.search(line) or "127.0.0.1" in line:
        return "127.0.0.1"
    return "127.0.0.1"


def _extract_ts(line: str) -> str | None:
    m = _TS_MAC.search(line) or _TS_LINUX.search(line)
    return m.group("ts") if m else None


@dataclass(frozen=True)
class FailureEvent:
    user: str
    ip: str
    raw: str
    ts: str | None = None


def parse_line(line: str) -> FailureEvent | None:
    line = line.strip()
    if not line:
        return None
    ts = _extract_ts(line)

    for pat in (_LINUX_FAILED, _LINUX_INVALID):
        m = pat.search(line)
        if m:
            return FailureEvent(user=m.group("user"), ip=m.group("ip"), raw=line, ts=ts)

    m = _MAC_PAM_ERROR.search(line)
    if m:
        return FailureEvent(user=m.group("user"), ip=m.group("ip"), raw=line, ts=ts)

    m = _MAC_FAILED.search(line)
    if m:
        ip = m.group("ip") or _extract_ip(line)
        return FailureEvent(user=m.group("user"), ip=ip, raw=line, ts=ts)

    m = _MAC_PASSWORD_ATTEMPT.search(line)
    if m:
        ip = (m.group("ip") or _extract_ip(line)).strip("[]")
        return FailureEvent(user=m.group("user"), ip=ip, raw=line, ts=ts)

    m = _MAC_AUTH_FAILURE.search(line)
    if m and _GENERIC_FAILED.search(line):
        user = (m.group("user") or "unknown").strip()
        if user != "unknown" or "sshd" in line.lower() or "ssh" in line.lower():
            return FailureEvent(user=user, ip=_extract_ip(line), raw=line, ts=ts)

    if _GENERIC_FAILED.search(line) and ("ssh" in line.lower() or "sshd" in line.lower()):
        user = "unknown"
        for pat in (
            r"user[=\s\"']+(?P<u>[^\"'\s,]+)",
            r"for (?P<u>\S+) from",
            r"invalid user (?P<u>\S+)",
        ):
            user_m = re.search(pat, line, re.I)
            if user_m:
                user = user_m.group("u")
                break
        return FailureEvent(user=user, ip=_extract_ip(line), raw=line, ts=ts)

    return None


def iter_lines_from_file(path: str) -> Iterable[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        yield from f


def iter_lines_live_mac(minutes: int) -> Iterable[str]:
    cmd = [
        "/usr/bin/log",
        "show",
        "--style",
        "syslog",
        "--last",
        f"{minutes}m",
        "--predicate",
        'process == "sshd" AND (eventMessage CONTAINS "authentication error" OR '
        'eventMessage CONTAINS "Failed password" OR eventMessage CONTAINS "authentication failure")',
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    except FileNotFoundError:
        print("error: /usr/bin/log not found (macOS only for --live)", file=sys.stderr)
        sys.exit(2)
    if proc.returncode != 0 and not proc.stdout:
        print(proc.stderr or "error: log show failed", file=sys.stderr)
        sys.exit(2)
    yield from proc.stdout.splitlines()


def collect_events(lines: Iterable[str]) -> list[FailureEvent]:
    return [ev for line in lines if (ev := parse_line(line))]


@dataclass
class GroupSummary:
    ip: str
    user: str
    count: int
    first_seen: str | None
    last_seen: str | None


def summarize_groups(events: list[FailureEvent], threshold: int) -> tuple[list[GroupSummary], list[GroupSummary]]:
    buckets: dict[tuple[str, str], list[FailureEvent]] = defaultdict(list)
    for ev in events:
        buckets[(ev.ip, ev.user)].append(ev)

    out: list[GroupSummary] = []
    for (ip, user), group in buckets.items():
        times = [g.ts for g in group if g.ts]
        out.append(
            GroupSummary(
                ip=ip,
                user=user,
                count=len(group),
                first_seen=min(times) if times else None,
                last_seen=max(times) if times else None,
            )
        )
    out.sort(key=lambda g: -g.count)
    return [g for g in out if g.count >= threshold], out


def append_alert_log(
    path: str,
    alerts: list[GroupSummary],
    threshold: int,
    *,
    minutes: int | None,
    source: str,
) -> None:
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    checked_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    window = f"minutes={minutes}" if minutes is not None else "source=file"
    with log_path.open("a", encoding="utf-8") as f:
        for g in alerts:
            first = g.first_seen or ""
            last = g.last_seen or ""
            f.write(
                f"{checked_at}\tALERT\t{window}\tthreshold={threshold}\t"
                f"ip={g.ip}\tuser={g.user}\tcount={g.count}\t"
                f"first={first}\tlast={last}\tsrc={source}\n"
            )


def print_report(
    events: list[FailureEvent],
    threshold: int,
    timeline: bool,
    alert_log: str | None,
    minutes: int | None,
    source: str,
) -> int:
    alerts, all_groups = summarize_groups(events, threshold)

    print(f"Parsed {len(events)} failed SSH login(s).\n")

    if not events:
        sample = SAMPLE_AUTH_LOG
        print(f"Nothing matched. Try --file \"{sample}\" or wrong passwords + --live.")
        return 0

    if timeline:
        print("Timeline:")
        for ev in sorted(events, key=lambda e: e.ts or ""):
            t = ev.ts or "?"
            print(f"  {t}  {ev.ip}  {ev.user}")
        print()

    print(f"{'IP':<16} {'USER':<18} {'COUNT':>5}  {'FIRST':<20} {'LAST':<20}")
    print("-" * 85)
    for g in all_groups:
        flag = "  ALERT" if g.count >= threshold else ""
        first = g.first_seen or "—"
        last = g.last_seen or "—"
        print(f"{g.ip:<16} {g.user:<18} {g.count:>5}  {first:<20} {last:<20}{flag}")

    if alerts:
        print(f"\n*** {len(alerts)} alert(s) (threshold {threshold}) ***")
        for g in alerts:
            window = ""
            if g.first_seen and g.last_seen:
                window = f" between {g.first_seen} and {g.last_seen}"
            print(f"  {g.ip} tried user '{g.user}' {g.count} times{window}")
        if alert_log:
            append_alert_log(alert_log, alerts, threshold, minutes=minutes, source=source)
            print(f"\nWrote {len(alerts)} line(s) to {alert_log}")
        return 1

    print(f"\nNo alerts at threshold {threshold}.")
    return 0


def print_json(events: list[FailureEvent], threshold: int) -> int:
    _, all_groups = summarize_groups(events, threshold)
    payload = {
        "event_count": len(events),
        "threshold": threshold,
        "events": [asdict(e) for e in events],
        "groups": [asdict(g) for g in all_groups],
        "alerts": [asdict(g) for g in all_groups if g.count >= threshold],
    }
    print(json.dumps(payload, indent=2))
    return 1 if payload["alerts"] else 0


def main() -> None:
    sample_default = str(SAMPLE_AUTH_LOG)
    p = argparse.ArgumentParser(description="SSH failed-login checker from auth logs")
    p.add_argument("--file", "-f", help=f"Log file (default sample: {sample_default})")
    p.add_argument("--live", action="store_true", help="macOS: read recent sshd logs")
    p.add_argument("--minutes", type=int, default=30, help="With --live, minutes of history")
    p.add_argument("--threshold", type=int, default=5, help="Alert when count >= this")
    p.add_argument("--timeline", action="store_true", help="Print each failure with timestamp")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p.add_argument("--alert-log", metavar="FILE", default=None, help="Append alert lines to FILE")
    args = p.parse_args()

    if args.file and args.live:
        print("error: use --file or --live, not both", file=sys.stderr)
        sys.exit(2)

    if args.file:
        lines = iter_lines_from_file(args.file)
    elif args.live:
        lines = iter_lines_live_mac(args.minutes)
    elif not sys.stdin.isatty():
        lines = sys.stdin
    else:
        p.print_help()
        print(f'\nExample: python3 ssh_ids.py --file "{sample_default}"', file=sys.stderr)
        sys.exit(2)

    events = collect_events(lines)
    source = "live" if args.live else "file" if args.file else "stdin"
    minutes = args.minutes if args.live else None
    if args.json:
        code = print_json(events, args.threshold)
        if code and args.alert_log:
            _, all_groups = summarize_groups(events, args.threshold)
            alert_groups = [g for g in all_groups if g.count >= args.threshold]
            append_alert_log(
                args.alert_log, alert_groups, args.threshold, minutes=minutes, source=source
            )
        sys.exit(code)
    sys.exit(
        print_report(
            events,
            args.threshold,
            args.timeline,
            args.alert_log,
            minutes,
            source,
        )
    )


if __name__ == "__main__":
    main()
