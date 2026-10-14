"""Policy information points (PIPs): authoritative entity attributes, with caching.

A PIP answers "what are the attributes of resource X?" (owner, department,
classification, quarantine flag...) so policies do not have to trust what the
calling gateway claims. Lookups are cached per entity with:

* a freshness TTL;
* negative caching (unknown entities are cached as not found);
* single flight: concurrent lookups of one entity share one fetch;
* bounded stale-if-error: when the source fails, a cached value no older than
  ``ttl + stale`` is served and marked stale; otherwise the error propagates
  and the decision fails closed;
* an LRU bound on the number of entries.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import yaml

from runtime_authorization_platform.domain.errors import PipUnavailableError
from runtime_authorization_platform.domain.ports import AttributeSource

TokenProvider = Callable[[], Awaitable[str]]


class HttpAttributeSource:
    """GET ``url_template`` with ``{type}`` and ``{id}`` substituted (percent-encoded).

    The response is a JSON object of attributes, optionally wrapped as
    ``{"attributes": {...}}``. HTTP 404 means the entity does not exist.
    """

    def __init__(
        self,
        name: str,
        url_template: str,
        *,
        http: httpx.AsyncClient,
        token_provider: TokenProvider | None = None,
    ) -> None:
        if "{id}" not in url_template:
            raise ValueError("PIP url template must contain {id}")
        self.name = name
        self._template = url_template
        self._http = http
        self._token_provider = token_provider

    def url_for(self, entity_type: str, entity_id: str) -> str:
        # safe="" encodes "/", "?", "#" and "..": an id cannot change the path or host.
        return self._template.replace("{type}", quote(entity_type, safe="")).replace(
            "{id}", quote(entity_id, safe="")
        )

    async def fetch(self, entity_type: str, entity_id: str) -> dict[str, Any] | None:
        headers = {"Accept": "application/json"}
        if self._token_provider is not None:
            headers["Authorization"] = f"Bearer {await self._token_provider()}"
        try:
            response = await self._http.get(
                self.url_for(entity_type, entity_id), headers=headers, follow_redirects=False
            )
        except httpx.HTTPError as exc:
            raise PipUnavailableError(f"{self.name}: {type(exc).__name__}") from exc
        if response.status_code == 404:
            return None
        if response.status_code >= 300:
            raise PipUnavailableError(f"{self.name} returned HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise PipUnavailableError(f"{self.name} returned a non-JSON body") from exc
        attributes = body.get("attributes", body) if isinstance(body, dict) else None
        if not isinstance(attributes, dict):
            raise PipUnavailableError(f"{self.name} returned a non-object document")
        return attributes


class StaticAttributeSource:
    """Attributes from a reviewed YAML file: ``{entity_type: {entity_id: {attr: value}}}``."""

    def __init__(self, name: str, data: Mapping[str, Mapping[str, Mapping[str, Any]]]) -> None:
        self.name = name
        self._data = {t: {i: dict(a) for i, a in ids.items()} for t, ids in data.items()}

    @classmethod
    def from_file(cls, path: Path) -> StaticAttributeSource:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict) or not all(
            isinstance(ids, dict) and all(isinstance(a, dict) for a in ids.values())
            for ids in loaded.values()
        ):
            raise ValueError(f"{path}: expected {{entity_type: {{id: {{attribute: value}}}}}}")
        return cls(f"static:{path.name}", loaded)

    def entity_types(self) -> frozenset[str]:
        return frozenset(self._data)

    async def fetch(self, entity_type: str, entity_id: str) -> dict[str, Any] | None:
        found = self._data.get(entity_type, {}).get(entity_id)
        return dict(found) if found is not None else None


class CacheOutcome(StrEnum):
    HIT = "hit"
    MISS = "miss"
    STALE = "stale"


@dataclass(frozen=True)
class Lookup:
    attributes: dict[str, Any] | None
    source: str
    outcome: CacheOutcome

    @property
    def found(self) -> bool:
        return self.attributes is not None


@dataclass
class _Entry:
    value: dict[str, Any] | None
    fetched_at: float


class AttributeCache:
    def __init__(
        self,
        source: AttributeSource,
        *,
        ttl_s: float = 60.0,
        stale_s: float = 300.0,
        max_entries: int = 10_000,
        monotonic: Callable[[], float] = time.monotonic,
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        self._source = source
        self._ttl = ttl_s
        self._stale = stale_s
        self._max = max_entries
        self._clock = monotonic
        self._on_event = on_event or (lambda _: None)
        self._entries: OrderedDict[tuple[str, str], _Entry] = OrderedDict()
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}

    @property
    def source_name(self) -> str:
        return self._source.name

    def __len__(self) -> int:
        return len(self._entries)

    def _fresh(self, key: tuple[str, str]) -> _Entry | None:
        entry = self._entries.get(key)
        if entry is not None and self._clock() - entry.fetched_at < self._ttl:
            self._entries.move_to_end(key)
            return entry
        return None

    async def get(self, entity_type: str, entity_id: str) -> Lookup:
        key = (entity_type, entity_id)
        entry = self._fresh(key)
        if entry is not None:
            self._on_event("hit")
            return Lookup(entry.value, self._source.name, CacheOutcome.HIT)
        lock = self._locks.setdefault(key, asyncio.Lock())
        try:
            async with lock:
                entry = self._fresh(key)  # another task may have filled it while we waited
                if entry is not None:
                    self._on_event("hit")
                    return Lookup(entry.value, self._source.name, CacheOutcome.HIT)
                return await self._load(key)
        finally:
            if not lock.locked():
                self._locks.pop(key, None)

    async def _load(self, key: tuple[str, str]) -> Lookup:
        try:
            value = await self._source.fetch(*key)
        except PipUnavailableError:
            previous = self._entries.get(key)
            if previous is not None and self._clock() - previous.fetched_at < (
                self._ttl + self._stale
            ):
                self._on_event("stale")
                return Lookup(previous.value, self._source.name, CacheOutcome.STALE)
            self._on_event("error")
            raise
        self._entries[key] = _Entry(value, self._clock())
        self._entries.move_to_end(key)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)
        self._on_event("miss" if value is not None else "not_found")
        return Lookup(value, self._source.name, CacheOutcome.MISS)

    def invalidate(self, entity_type: str, entity_id: str) -> None:
        self._entries.pop((entity_type, entity_id), None)


class AttributeResolver:
    """Routes lookups to the cache configured for each entity type."""

    def __init__(self, caches: Mapping[str, AttributeCache] | None = None) -> None:
        self._caches = dict(caches or {})

    def configured(self, entity_type: str) -> bool:
        return entity_type in self._caches

    @property
    def entity_types(self) -> frozenset[str]:
        return frozenset(self._caches)

    async def resolve(self, entity_type: str, entity_id: str) -> Lookup | None:
        cache = self._caches.get(entity_type)
        if cache is None:
            return None
        return await cache.get(entity_type, entity_id)
