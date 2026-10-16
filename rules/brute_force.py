from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable, List

from models import Alert, Event


class BruteForceRule:
    name = "brute_force_ssh"

    def __init__(self, threshold: int = 3, window_seconds: int = 60):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events: Iterable[Event]) -> List[Alert]:
        alerts: List[Alert] = []
        recent = defaultdict(deque)  # ip -> [(timestamp, usuario), ...]

        for event in events:
            if event.event_type != "login_failed" or event.src_ip is None:
                continue

            attempts = recent[event.src_ip]
            attempts.append((event.timestamp, event.username))

            
            while event.timestamp - attempts[0][0] > self.window:
                attempts.popleft()

            if len(attempts) >= self.threshold:
                users = sorted({user for _, user in attempts})
                alerts.append(
                    Alert(
                        timestamp=event.timestamp,
                        rule=self.name,
                        severity="high",
                        src_ip=event.src_ip,
                        description=(
                            f"{len(attempts)} intentos fallidos en "
                            f"{int(self.window.total_seconds())}s "
                            f"(usuarios probados: {', '.join(users)})"
                        ),
                    )
                )
                attempts.clear() 

        return alerts