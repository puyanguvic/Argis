"""Submission and event queues for the engine protocol."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Iterable

from protocol.events import EventMsg
from protocol.op import Op


@dataclass
class QueuePair:
    submissions: Deque[Op] = field(default_factory=deque)
    events: Deque[EventMsg] = field(default_factory=deque)

    def submit(self, op: Op) -> None:
        self.submissions.append(op)

    def has_submissions(self) -> bool:
        return bool(self.submissions)

    def pop_submission(self) -> Op:
        return self.submissions.popleft()

    def emit(self, event: EventMsg) -> None:
        self.events.append(event)

    def drain_events(self) -> Iterable[EventMsg]:
        while self.events:
            yield self.events.popleft()
