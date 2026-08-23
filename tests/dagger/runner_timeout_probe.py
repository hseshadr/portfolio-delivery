"""Execute one real pinned-container deadline probe inside an active Dagger session."""

from __future__ import annotations

import asyncio
import secrets
from typing import Final

import dagger
from dagger import dag
from portfolio_delivery_dagger.oras import ORAS_IMAGE, DaggerOrasRunner

from portfolio_delivery.domain.stages import OrasInvocation, OrasOutcome

WRITE_MARKER: Final = "/tmp/portfolio-delivery-write-observed"  # noqa: S108


async def _probe() -> None:
    await dagger.connect()
    try:
        await _assert_before_write_timeout()
        await _assert_after_write_timeout()
    finally:
        await dagger.close()


async def _assert_before_write_timeout() -> None:
    runner = DaggerOrasRunner(dag, "registry.example/repo", execution_deadline_seconds=1)
    attempt_id = _attempt("before-write")
    result = await runner.run(OrasInvocation(("/bin/sh", "-c", "sleep 3")), attempt_id)
    assert result.outcome is OrasOutcome.TIMEOUT
    assert result.exported_file_bytes is None
    assert runner.observations[0].attempt_id == attempt_id


async def _assert_after_write_timeout() -> None:
    runner = _scripted_push_runner()
    invocation = OrasInvocation(_scripted_push_argv())
    result = await runner.run(invocation, _attempt("after-write"))
    assert result.outcome is OrasOutcome.TIMEOUT
    assert result.exported_file_bytes is None
    assert runner.previous_container is not None
    assert await runner.previous_container.exists(WRITE_MARKER)


def _scripted_push_runner() -> DaggerOrasRunner:
    script = '#!/bin/sh\nprintf \'{"written":true}\' > "$3"\ntouch "$4"\nsleep 3\n'
    container = (
        dag.container()
        .from_(ORAS_IMAGE)
        .with_new_file("/usr/local/bin/provider-push", contents=script, permissions=0o755)
    )
    return DaggerOrasRunner(
        dag, "registry.example/repo", execution_deadline_seconds=1, previous_container=container
    )


def _scripted_push_argv() -> tuple[str, ...]:
    return (
        "/usr/local/bin/provider-push",
        "push",
        "--export-manifest",
        "manifest.json",
        WRITE_MARKER,
    )


def _attempt(kind: str) -> str:
    return f"attempt-{kind}-timeout-{secrets.token_hex(8)}"


if __name__ == "__main__":
    asyncio.run(_probe())
