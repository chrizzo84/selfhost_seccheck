from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from seccheck.core.context import ScanContext
from seccheck.core.registry import get_app, load_plugins
from seccheck.core.target import parse_target

load_plugins()


@pytest.fixture
def make_ctx() -> Callable[..., ScanContext]:
    """Build a ScanContext whose HTTP traffic is answered by ``handler``."""

    def factory(
        handler: Callable[[httpx.Request], httpx.Response],
        url: str = "https://cloud.example.com",
        app: str = "generic",
    ) -> ScanContext:
        profile = get_app(app)
        assert profile is not None
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return ScanContext(parse_target(url), profile, client)

    return factory
