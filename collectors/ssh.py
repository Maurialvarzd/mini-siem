import re
from datetime import datetime
from typing import Iterator

from models import Event

# Failed password for [invalid user] USUARIO from IP port ...
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port"
)

# Accepted password/publickey for USUARIO from IP port ...
ACCEPTED_RE = re.compile(
    r"Accepted \w+ for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port"
)


def parse_timestamp(line: str, year: int) -> datetime:
   
    return datetime.strptime(f"{year} {line[:15]}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int):
   
    match = FAILED_RE.search(line)
    if match:
        event_type = "login_failed"
    else:
        match = ACCEPTED_RE.search(line)
        if match:
            event_type = "login_success"
        else:
            return None

    return Event(
        timestamp=parse_timestamp(line, year),
        source="ssh",
        event_type=event_type,
        src_ip=match.group("ip"),
        username=match.group("user"),
        raw=line.strip(),
    )


def collect(path: str, year: int = None) -> Iterator[Event]:
    
    if year is None:
        year = datetime.now().year

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line, year)
            if event is not None:
                yield event