import time
import random
import logging
from datetime import datetime

log = logging.getLogger("phantom.core.scheduler")


class Scheduler:
    """Beacon timing control with jitter and kill date."""

    def __init__(self, sleep_time: float = 5.0, jitter_percent: float = 20.0,
                 kill_date: str | None = None):
        self.sleep_time = sleep_time
        self.jitter_percent = jitter_percent
        self._kill_date = self._parse_date(kill_date) if kill_date else None

    def wait(self):
        """Sleep for configured interval with random jitter."""
        jitter = self.sleep_time * (self.jitter_percent / 100.0)
        actual = self.sleep_time + random.uniform(-jitter, jitter)
        actual = max(0.1, actual)
        log.debug(f"Sleeping {actual:.1f}s (base={self.sleep_time}, jitter={self.jitter_percent}%)")
        time.sleep(actual)

    def check_kill_date(self) -> bool:
        """Returns True if agent should self-destruct."""
        if not self._kill_date:
            return False
        return datetime.utcnow() >= self._kill_date

    def update_config(self, sleep: float | None = None, jitter: float | None = None,
                      kill_date: str | None = None):
        if sleep is not None:
            self.sleep_time = max(0.1, sleep)
        if jitter is not None:
            self.jitter_percent = max(0.0, min(100.0, jitter))
        if kill_date is not None:
            self._kill_date = self._parse_date(kill_date)
        log.info(f"Config updated: sleep={self.sleep_time}s, jitter={self.jitter_percent}%")

    @staticmethod
    def _parse_date(date_str: str) -> datetime | None:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        return None
