"""Policy information points and their cache."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest

from runtime_authorization_platform.domain.errors import PipUnavailableError
from runtime_authorization_platform.integrations.pip import (
    AttributeCache,
    AttributeResolver,
    CacheOutcome,
    HttpAttributeSource,
    StaticAttributeSource,
)
from tests.conftest import FakeTicker


def http_source(handler: Any, **kw: Any) -> HttpAttributeSource:
    return HttpAttributeSource(
        "http:document",
        "https://pip.corp.test/{type}/{id}",
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **kw,
    )


async def test_http_source_wire_format() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.raw_path.endswith(b"wrapped"):
            return httpx.Response(200, json={"attributes": {"owner": "a"}})
        if request.url.raw_path.endswith(b"gone"):
            return httpx.Response(404)
        return httpx.Response(200, json={"owner": "b"})

    async def token() -> str:
        return "pip-access-token"

    source = http_source(handler, token_provider=token)
    assert await source.fetch("document", "wrapped") == {"owner": "a"}
    assert await source.fetch("document", "plain") == {"owner": "b"}
    assert await source.fetch("document", "gone") is None
    assert seen[0].headers["authorization"] == "Bearer pip-access-token"
    assert seen[0].headers["accept"] == "application/json"


def test_http_source_encodes_ids() -> None:
    source = http_source(lambda _: httpx.Response(200, json={}))
    url = source.url_for("doc type", "../../admin?x=1#frag")
    assert url == "https://pip.corp.test/doc%20type/..%2F..%2Fadmin%3Fx%3D1%23frag"
    with pytest.raises(ValueError, match=r"\{id\}"):
        HttpAttributeSource("x", "https://pip/none", http=httpx.AsyncClient())


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500),
        httpx.Response(302, headers={"Location": "https://elsewhere.test/"}),
        httpx.Response(200, content=b"<html>"),
        httpx.Response(200, json=["list"]),
        httpx.Response(200, json={"attributes": "nope"}),
    ],
)
async def test_http_source_failures(response: httpx.Response) -> None:
    with pytest.raises(PipUnavailableError):
        await http_source(lambda _: response).fetch("document", "x")


async def test_http_source_transport_failure() -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(PipUnavailableError, match="ReadTimeout"):
        await http_source(broken).fetch("document", "x")


async def test_static_source(tmp_path: Path) -> None:
    path = tmp_path / "a.yaml"
    path.write_text("document:\n  d1: {owner: a}\n", encoding="utf-8")
    source = StaticAttributeSource.from_file(path)
    assert source.entity_types() == frozenset({"document"})
    assert await source.fetch("document", "d1") == {"owner": "a"}
    assert await source.fetch("document", "d2") is None
    assert await source.fetch("other", "d1") is None
    bad = tmp_path / "bad.yaml"
    bad.write_text("document: [1, 2]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="expected"):
        StaticAttributeSource.from_file(bad)
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    assert StaticAttributeSource.from_file(empty).entity_types() == frozenset()


class FakeSource:
    name = "fake"

    def __init__(self) -> None:
        self.calls = 0
        self.fail = False
        self.delay = 0.0
        self.data: dict[str, dict[str, Any]] = {"d1": {"owner": "a"}}

    async def fetch(self, entity_type: str, entity_id: str) -> dict[str, Any] | None:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise PipUnavailableError("down")
        return self.data.get(entity_id)


async def test_cache_hit_miss_negative_and_stale() -> None:
    source, ticker, events = FakeSource(), FakeTicker(), []
    cache = AttributeCache(
        source, ttl_s=10, stale_s=20, max_entries=100, monotonic=ticker, on_event=events.append
    )
    first = await cache.get("document", "d1")
    assert (first.outcome, first.found, first.source) == (CacheOutcome.MISS, True, "fake")
    assert (await cache.get("document", "d1")).outcome is CacheOutcome.HIT
    missing = await cache.get("document", "nope")
    assert missing.found is False
    assert (await cache.get("document", "nope")).outcome is CacheOutcome.HIT
    assert source.calls == 2

    ticker.advance(15)
    source.fail = True
    stale = await cache.get("document", "d1")
    assert stale.outcome is CacheOutcome.STALE
    assert stale.attributes == {"owner": "a"}

    ticker.advance(20)  # beyond ttl + stale
    with pytest.raises(PipUnavailableError):
        await cache.get("document", "d1")
    with pytest.raises(PipUnavailableError):
        await cache.get("document", "never-seen")
    assert events == ["miss", "hit", "not_found", "hit", "stale", "error", "error"]


async def test_cache_lru_bound_and_invalidate() -> None:
    source = FakeSource()
    source.data = {f"d{i}": {"i": i} for i in range(20)}
    cache = AttributeCache(source, max_entries=10)
    for i in range(20):
        await cache.get("document", f"d{i}")
    assert len(cache) == 10
    assert cache.source_name == "fake"
    calls = source.calls
    await cache.get("document", "d19")
    assert source.calls == calls
    cache.invalidate("document", "d19")
    await cache.get("document", "d19")
    assert source.calls == calls + 1


async def test_cache_single_flight() -> None:
    source = FakeSource()
    source.delay = 0.05
    cache = AttributeCache(source)
    results = await asyncio.gather(*(cache.get("document", "d1") for _ in range(25)))
    assert source.calls == 1
    assert {r.outcome for r in results} == {CacheOutcome.MISS, CacheOutcome.HIT}


async def test_resolver_routes_by_type() -> None:
    resolver = AttributeResolver({"document": AttributeCache(FakeSource())})
    assert resolver.configured("document")
    assert not resolver.configured("ticket")
    assert resolver.entity_types == frozenset({"document"})
    assert await resolver.resolve("ticket", "t1") is None
    found = await resolver.resolve("document", "d1")
    assert found is not None
    assert found.attributes == {"owner": "a"}
