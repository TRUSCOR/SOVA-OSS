# SPDX-License-Identifier: Apache-2.0
"""Provider settings, credential handling, pacing, retries, and budget."""

from __future__ import annotations

import random
from types import SimpleNamespace
from typing import Any

import pytest

from sova.rerun.providers import (
    Budget,
    ModelEndpoint,
    ModelSettings,
    Pacer,
    Pricing,
    ProviderSetupError,
    backoff_seconds,
    build_sdk_client,
    default_api,
    estimate_tokens,
    is_transient,
    scrub,
    usage_from_response,
)
from sova.rerun.records import CallRecord, Usage


class StatusError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"status {status}")
        self.status_code = status


class RateLimitError(Exception):
    pass


class APITimeoutError(Exception):
    pass


class WrappedResponseError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__("wrapped")
        self.response = SimpleNamespace(status_code=status)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"model": ""}, "model name"),
        ({"model": "m", "provider": "other"}, "unsupported provider"),
        ({"model": "m", "api": "messages"}, "chat or responses"),
        ({"model": "m", "provider": "anthropic", "api": "chat"}, "Messages API"),
        ({"model": "m", "tpm": 0}, "--tpm"),
        ({"model": "m", "rpm": -1}, "--rpm"),
        ({"model": "m", "concurrency": 0}, "positive"),
    ],
)
def test_settings_validation(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ProviderSetupError, match=message):
        ModelSettings(**kwargs)


def test_settings_describe_names_variables_never_values() -> None:
    settings = ModelSettings(model="m", base_url_env="BASE", api_key_env="KEY", temperature=0.0)
    described = settings.describe()
    assert described["apiKeyEnv"] == "KEY"
    assert described["baseUrlEnv"] == "BASE"
    assert described["temperature"] == "0.0"
    assert described["maxTokens"] is None
    anthropic = ModelSettings(model="c", provider="anthropic", api="messages")
    assert anthropic.key_env == "ANTHROPIC_API_KEY"
    assert anthropic.describe()["maxTokens"] == 4096
    assert ModelSettings(model="m").key_env == "OPENAI_API_KEY"
    assert default_api("anthropic", None) == "messages"
    assert default_api("openai-compatible", None) == "chat"
    assert default_api("openai-compatible", "responses") == "responses"


def test_build_client_reads_named_environment_variables_only() -> None:
    created: dict[str, Any] = {}

    def factory(**kwargs: Any) -> str:
        created.update(kwargs)
        return "client"

    module = SimpleNamespace(OpenAI=factory, Anthropic=factory)
    settings = ModelSettings(model="m", base_url_env="MY_BASE", api_key_env="MY_KEY")
    environ = {"MY_BASE": "https://example.invalid/v1", "MY_KEY": "secret-value"}
    client, secrets = build_sdk_client(settings, environ=environ, importer=lambda _name: module)
    assert client == "client"
    assert created["max_retries"] == 0
    assert created["base_url"] == "https://example.invalid/v1"
    assert set(secrets) == {"secret-value", "https://example.invalid/v1"}

    anthropic = ModelSettings(model="c", provider="anthropic", api="messages")
    _client, secrets = build_sdk_client(
        anthropic, environ={"ANTHROPIC_API_KEY": "k"}, importer=lambda _name: module
    )
    assert secrets == ("k",)
    assert created["base_url"] == "https://api.anthropic.com"  # never read implicitly


def test_build_client_errors_name_the_variable_but_not_a_value() -> None:
    settings = ModelSettings(model="m", base_url_env="MY_BASE", api_key_env="MY_KEY")
    with pytest.raises(ProviderSetupError, match="MY_KEY") as missing_key:
        build_sdk_client(settings, environ={})
    assert "secret" not in str(missing_key.value)
    with pytest.raises(ProviderSetupError, match="MY_BASE"):
        build_sdk_client(settings, environ={"MY_KEY": "secret"})

    def absent(_name: str) -> Any:
        message = "no sdk"
        raise ImportError(message)

    with pytest.raises(ProviderSetupError, match=r"sova-oss\[agentdojo\]"):
        build_sdk_client(
            settings,
            environ={"MY_KEY": "secret", "MY_BASE": "https://example.invalid"},
            importer=absent,
        )


def test_build_client_defaults_to_the_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOVA_TEST_UNSET_KEY", raising=False)
    with pytest.raises(ProviderSetupError, match="SOVA_TEST_UNSET_KEY"):
        build_sdk_client(ModelSettings(model="m", api_key_env="SOVA_TEST_UNSET_KEY"))


def test_transient_classification_and_backoff() -> None:
    assert is_transient(StatusError(429))
    assert is_transient(StatusError(503))
    assert not is_transient(StatusError(400))
    assert not is_transient(StatusError(401))
    assert is_transient(WrappedResponseError(502))
    assert is_transient(RateLimitError())
    assert is_transient(APITimeoutError())
    assert is_transient(TimeoutError())
    assert not is_transient(ValueError("bad"))
    rng = random.Random(0)  # noqa: S311 - deterministic jitter
    assert 4.0 <= backoff_seconds(0, rng) <= 7.0
    assert 90.0 <= backoff_seconds(10, rng) <= 93.0


def test_scrub_and_estimate() -> None:
    assert scrub("key=abc and abc", ["abc", ""]) == "key=[redacted] and [redacted]"
    assert len(scrub("x" * 1000, [])) == 300
    small = estimate_tokens({"messages": [{"role": "user", "content": "hi"}]})
    assert small > 1200
    assert estimate_tokens({"input": "x" * 3200, "tools": [], "system": "s"}) > 2000


def test_usage_extraction_for_each_api() -> None:
    chat = SimpleNamespace(
        model="m-1",
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=2, prompt_tokens_details=None),
        choices=[SimpleNamespace(finish_reason="stop")],
    )
    usage, stop, returned = usage_from_response("chat", chat)
    assert (usage.input_tokens, usage.output_tokens, stop, returned) == (10, 2, "stop", "m-1")
    empty_chat = SimpleNamespace(usage=None, choices=[])
    usage, stop, returned = usage_from_response("chat", empty_chat)
    assert (usage, stop, returned) == (Usage(), None, None)
    responses = SimpleNamespace(
        model="r",
        status=None,
        usage=SimpleNamespace(
            input_tokens=5,
            output_tokens=True,
            input_tokens_details=None,
            output_tokens_details=SimpleNamespace(reasoning_tokens=3),
        ),
    )
    usage, stop, _ = usage_from_response("responses", responses)
    assert usage.output_tokens == 0  # booleans are not token counts
    assert usage.reasoning_tokens == 3
    assert stop == "completed"
    message = SimpleNamespace(
        model="c",
        stop_reason=None,
        usage=SimpleNamespace(
            input_tokens=1,
            output_tokens=2,
            cache_creation_input_tokens=3,
            cache_read_input_tokens=4,
        ),
    )
    usage, stop, _ = usage_from_response("messages", message)
    assert usage == Usage(1, 2, 3, 4, 0)
    assert stop is None


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_pacer_enforces_token_and_request_windows() -> None:
    clock = Clock()
    pacer = Pacer(clock=clock, sleep=clock.sleep, poll_seconds=10.0)
    first = pacer.acquire("m", 600, tpm=1000, rpm=None)
    pacer.settle(first, 900)
    pacer.acquire("m", 50, tpm=1000, rpm=None)
    assert clock.sleeps == []
    pacer.acquire("m", 600, tpm=1000, rpm=None)
    assert clock.now > 60.0  # waited until the first slot left the window
    clock.now = 1000.0
    pacer.acquire("r", 1, tpm=None, rpm=1)
    pacer.acquire("r", 1, tpm=None, rpm=1)
    assert clock.now > 1060.0
    huge = pacer.acquire("big", 10**9, tpm=10, rpm=None)
    assert huge[1] == float(10**9)
    pacer.settle(huge, 0)
    assert huge[1] == 1.0
    pacer.acquire("free", 10**9, tpm=None, rpm=None)


class Operation:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def __call__(self, **_kwargs: Any) -> Any:
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _endpoint(operation: Operation, **settings: Any) -> tuple[ModelEndpoint, list[float]]:
    sleeps: list[float] = []
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=operation)))
    endpoint = ModelEndpoint(
        ModelSettings(model="m", **settings),
        client,
        pacer=Pacer(),
        secrets=("sk-123",),
        sleep=sleeps.append,
        rng=random.Random(0),  # noqa: S311 - deterministic jitter
    )
    return endpoint, sleeps


def _ok() -> Any:
    return SimpleNamespace(
        model="m-returned",
        usage=SimpleNamespace(prompt_tokens=3, completion_tokens=4, prompt_tokens_details=None),
        choices=[SimpleNamespace(finish_reason="stop")],
    )


def test_endpoint_retries_transient_errors_and_keeps_every_attempt() -> None:
    operation = Operation([StatusError(429), RateLimitError("sk-123 slow"), _ok()])
    endpoint, sleeps = _endpoint(operation)
    calls: list[CallRecord] = []
    response = endpoint.call({"model": "m", "messages": []}, calls)
    assert response.model == "m-returned"
    assert len(sleeps) == 2
    record = calls[0]
    assert [attempt.attempt for attempt in record.failed_attempts] == [1, 2]
    assert record.failed_attempts[0].status_code == 429
    assert "sk-123" not in record.failed_attempts[1].message
    assert record.returned_model == "m-returned"
    assert record.usage.output_tokens == 4
    assert record.to_json()["failedAttempts"][0]["backoffSeconds"] is not None


def test_endpoint_does_not_retry_permanent_errors() -> None:
    operation = Operation([StatusError(400)])
    endpoint, sleeps = _endpoint(operation)
    calls: list[CallRecord] = []
    with pytest.raises(StatusError):
        endpoint.call({"model": "m"}, calls)
    assert operation.calls == 1
    assert sleeps == []
    assert calls[0].error is not None
    assert calls[0].failed_attempts[0].transient is False


def test_endpoint_gives_up_after_max_tries() -> None:
    operation = Operation([StatusError(500) for _ in range(3)])
    endpoint, sleeps = _endpoint(operation, max_tries=3)
    calls: list[CallRecord] = []
    with pytest.raises(StatusError):
        endpoint.call({"model": "m"}, calls)
    assert operation.calls == 3
    assert len(sleeps) == 2
    assert calls[0].failed_attempts[-1].backoff_seconds is None
    assert endpoint.scrub("sk-123") == "[redacted]"


def test_pricing_and_budget() -> None:
    pricing = Pricing(2.0, 10.0)
    usage = Usage(
        input_tokens=1_000_000,
        output_tokens=100_000,
        cache_write_tokens=0,
        cache_read_tokens=1_000_000,
    )
    assert pricing.cost(usage) == pytest.approx(2.0 + 1.0 + 0.2)
    assert pricing.cost(Usage(cache_write_tokens=1_000_000)) == pytest.approx(2.5)
    budget = Budget(max_usd=5.0, pricing=pricing, already_spent=1.0)
    assert not budget.exhausted()
    budget.add(budget.cost_of(usage))
    budget.add(None)
    assert budget.spent == pytest.approx(3.2)
    assert budget.total == pytest.approx(4.2)
    budget.add(1.0)
    assert budget.exhausted()
    free = Budget(max_usd=None, pricing=None)
    assert free.cost_of(usage) is None
    assert not free.exhausted()
    with pytest.raises(ProviderSetupError, match="price-in"):
        Budget(max_usd=1.0, pricing=None)
    with pytest.raises(ProviderSetupError, match="positive"):
        Budget(max_usd=0.0, pricing=pricing)
