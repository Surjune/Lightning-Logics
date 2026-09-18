"""In-memory alert store with live subscribers, plus the hash-chained evidence log."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import OrderedDict
from pathlib import Path
from typing import Any

from enclave.core.constants import ALERT_STORE_MAX
from enclave.schema.alert import Alert, Custody

GENESIS_HASH = "0" * 64
SUBSCRIBER_QUEUE_MAX = 1_000


def canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class HashChainLog:
    """Append-only JSONL. Each line's hash covers the previous hash plus the record."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.head = self._recover_head()
        self.height = 0

    def _recover_head(self) -> str:
        if not self.path.is_file():
            return GENESIS_HASH
        head = GENESIS_HASH
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    head = json.loads(line)["hash"]
        return head

    def append(self, kind: str, record: dict[str, Any]) -> tuple[str, str]:
        prev = self.head
        digest = hashlib.sha256((prev + canonical(record)).encode("utf-8")).hexdigest()
        line = {"kind": kind, "prev": prev, "hash": digest, "record": record}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, default=str) + "\n")
        self.head = digest
        self.height += 1
        return prev, digest


def verify_chain(path: Path) -> tuple[bool, int]:
    """Recompute every hash; returns (intact, lines checked)."""
    prev = GENESIS_HASH
    count = 0
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            entry = json.loads(line)
            expected = hashlib.sha256((prev + canonical(entry["record"])).encode("utf-8")).hexdigest()
            if entry["prev"] != prev or entry["hash"] != expected:
                return False, count
            prev = entry["hash"]
            count += 1
    return True, count


class AlertStore:
    def __init__(self, chain: HashChainLog | None, source_ref: str) -> None:
        self.chain = chain
        self.source_ref = source_ref
        self._alerts: OrderedDict[str, Alert] = OrderedDict()
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def publish(self, alert: Alert, is_new: bool) -> None:
        if self.chain is not None:
            if is_new:
                body = alert.model_dump(mode="json", exclude={"custody"})
                prev, digest = self.chain.append("alert", body)
                alert.custody = Custody(source_ref=self.source_ref, prev_alert_hash=prev, alert_hash=digest)
            else:
                self.chain.append("update", {"alert_id": alert.alert_id, "events_merged": alert.events_merged,
                                             "event_end": alert.event_end.isoformat(),
                                             "confidence": alert.confidence})
        self._alerts[alert.alert_id] = alert
        self._alerts.move_to_end(alert.alert_id)
        while len(self._alerts) > ALERT_STORE_MAX:
            self._alerts.popitem(last=False)
        message = {"type": "alert" if is_new else "update", "alert": alert.model_dump(mode="json")}
        for queue in list(self._subscribers):
            if queue.full():
                continue
            queue.put_nowait(message)

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_MAX)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)

    def get(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    def list(self, limit: int, severity: str | None = None, threat_class: str | None = None) -> list[Alert]:
        out: list[Alert] = []
        for alert in reversed(self._alerts.values()):
            if severity and alert.severity.value != severity:
                continue
            if threat_class and alert.threat_class.value != threat_class:
                continue
            out.append(alert)
            if len(out) >= limit:
                break
        return out

    def all(self) -> list[Alert]:
        return list(self._alerts.values())
