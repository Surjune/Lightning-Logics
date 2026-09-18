"""Bounded per-entity state so spoofed-source floods cannot exhaust memory."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterator
from typing import Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class BoundedDict(Generic[K, V]):
    def __init__(self, max_size: int, factory: Callable[[], V]) -> None:
        self._data: OrderedDict[K, V] = OrderedDict()
        self._max = max_size
        self._factory = factory
        self.evicted = 0

    def get_or_create(self, key: K) -> V:
        value = self._data.get(key)
        if value is None:
            value = self._factory()
            self._data[key] = value
            if len(self._data) > self._max:
                self._data.popitem(last=False)
                self.evicted += 1
        else:
            self._data.move_to_end(key)
        return value

    def set(self, key: K, value: V) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        if len(self._data) > self._max:
            self._data.popitem(last=False)
            self.evicted += 1

    def get(self, key: K) -> V | None:
        return self._data.get(key)

    def pop(self, key: K) -> V | None:
        return self._data.pop(key, None)

    def items(self) -> Iterator[tuple[K, V]]:
        return iter(list(self._data.items()))

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, key: object) -> bool:
        return key in self._data
