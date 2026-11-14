# SPDX-License-Identifier: Apache-2.0
"""Model clients for fresh runs: credentials from named environment variables only.

Keys are never accepted as arguments, never written to a trace, report, or log,
and never printed. Every call is paced against per-model token and request
budgets over a sliding 60-second window and retried only for transient errors
(rate limits, timeouts, connection errors, server errors) with exponential
backoff, up to 12 tries per call. Every failed attempt is kept.
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import import_module
from typing import TYPE_CHECKING, Any, Final, Literal

from sova.formats.errors import FormatError
from sova.rerun.records import CallRecord, FailedAttempt, Usage

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

ProviderName = Literal["openai-compatible", "anthropic"]
PROVIDERS: Final[tuple[str, ...]] = ("openai-compatible", "anthropic")
OPENAI_APIS: Final[tuple[str, ...]] = ("chat", "responses")
DEFAULT_API_KEY_ENV: Final[Mapping[str, str]] = {
    "openai-compatible": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}
DEFAULT_BASE_URL: Final[Mapping[str, str]] = {
    "openai-compatible": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
}
MAX_TRIES: Final = 12
WINDOW_SECONDS: Final = 60.0
INSTALL_HINT: Final = 'install the optional extra: pip install "sova-oss[agentdojo]"'
_TRANSIENT_NAMES: Final = (
    "RateLimitError",
    "APITimeoutError",
    "APIConnectionError",
    "InternalServerError",
    "ServiceUnavailableError",
    "OverloadedError",
    "Timeout",
    "TimeoutError",
    "ConnectError",
    "ConnectTimeout",
    "ReadTimeout",
    "RemoteProtocolError",
)
_RATE_LIMITED: Final = 429
_SERVER_ERROR: Final = 500
_MESSAGE_LIMIT: Final = 300
_BACKOFF_BASE: Final = 4.0
_BACKOFF_CAP: Final = 90.0
_BACKOFF_JITTER: Final = 3.0


class ProviderSetupError(FormatError):
    """A provider could not be configured; the message never contains a credential."""

    def __init__(self, message: str) -> None:
        """Create the error with a fixed machine-readable code."""
        super().__init__("SOVA-RERUN-PROVIDER", message)


@dataclass(frozen=True, slots=True)
class ModelSettings:
    """How to reach one model. Only environment-variable *names* are stored here."""

    model: str
    provider: str = "openai-compatible"
    api: str = "chat"
    base_url_env: str | None = None
    api_key_env: str | None = None
    temperature: float | None = None
    max_tokens: int = 4096
    tpm: int | None = None
    rpm: int | None = None
    concurrency: int = 4
    max_tries: int = MAX_TRIES
    timeout_seconds: float = 300.0

    def __post_init__(self) -> None:
        """Validate provider/API pairing and limits."""
        problem = self._problem()
        if problem is not None:
            raise ProviderSetupError(problem)

    def _problem(self) -> str | None:  # noqa: PLR0911 - one message per invalid setting
        if not self.model:
            return "a model name is required"
        if self.provider not in PROVIDERS:
            return f"unsupported provider: {self.provider!r}"
        if self.provider == "openai-compatible" and self.api not in OPENAI_APIS:
            return "openai-compatible supports --api chat or responses"
        if self.provider == "anthropic" and self.api != "messages":
            return "the anthropic provider uses the Messages API only"
        for name, value in (("tpm", self.tpm), ("rpm", self.rpm)):
            if value is not None and value <= 0:
                return f"--{name} must be positive"
        if self.concurrency < 1 or self.max_tries < 1 or self.max_tokens < 1:
            return "concurrency, tries, and max tokens must be positive"
        return None

    @property
    def key_env(self) -> str:
        """Return the environment variable that holds the API key."""
        return self.api_key_env or DEFAULT_API_KEY_ENV[self.provider]

    def describe(self) -> dict[str, Any]:
        """Return a JSON-safe description containing variable names, never values."""
        return {
            "model": self.model,
            "provider": self.provider,
            "api": self.api,
            "apiKeyEnv": self.key_env,
            "baseUrlEnv": self.base_url_env,
            "temperature": None if self.temperature is None else repr(self.temperature),
            "maxTokens": self.max_tokens if self.provider == "anthropic" else None,
            "tokensPerMinute": self.tpm,
            "requestsPerMinute": self.rpm,
            "concurrency": self.concurrency,
            "maxTriesPerCall": self.max_tries,
        }


def default_api(provider: str, api: str | None) -> str:
    """Return the API used by default for a provider."""
    if provider == "anthropic":
        return "messages"
    return api or "chat"


def _required_env(environ: Mapping[str, str], name: str, what: str) -> str:
    value = environ.get(name)
    if not value:
        message = f"environment variable {name} ({what}) is not set"
        raise ProviderSetupError(message)
    return value


def build_sdk_client(
    settings: ModelSettings,
    *,
    environ: Mapping[str, str] | None = None,
    importer: Callable[[str], Any] = import_module,
) -> tuple[Any, tuple[str, ...]]:
    """Create an SDK client from environment variables named in ``settings``.

    Returns the client and the sensitive values (key and base URL) so that
    error messages can be scrubbed; those values are kept only in memory. SDK
    retries are disabled because every retry is made, and recorded, here.
    """
    environment = os.environ if environ is None else environ
    key = _required_env(environment, settings.key_env, "API key")
    # Pass the provider's public endpoint explicitly when no variable is named, so
    # the SDK does not read a base URL from an environment variable of its own.
    base_url = DEFAULT_BASE_URL[settings.provider]
    secrets = [key]
    if settings.base_url_env is not None:
        base_url = _required_env(environment, settings.base_url_env, "base URL")
        secrets.append(base_url)
    module_name = "openai" if settings.provider == "openai-compatible" else "anthropic"
    try:
        module = importer(module_name)
    except ImportError as error:
        message = f"the {module_name} SDK is not installed; {INSTALL_HINT}"
        raise ProviderSetupError(message) from error
    factory = module.OpenAI if module_name == "openai" else module.Anthropic
    client = factory(
        api_key=key,
        base_url=base_url,
        max_retries=0,
        timeout=settings.timeout_seconds,
    )
    return client, tuple(secrets)


def scrub(text: str, secrets: Sequence[str]) -> str:
    """Remove sensitive values from text and bound its length."""
    cleaned = text
    for secret in secrets:
        if secret:
            cleaned = cleaned.replace(secret, "[redacted]")
    return cleaned[:_MESSAGE_LIMIT]


def _status_code(error: BaseException) -> int | None:
    status = getattr(error, "status_code", None)
    if isinstance(status, int) and not isinstance(status, bool):
        return status
    response = getattr(error, "response", None)
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) and not isinstance(status, bool) else None


def is_transient(error: BaseException) -> bool:
    """Return whether an error is worth retrying (rate limit, timeout, connection, 5xx)."""
    status = _status_code(error)
    if status is not None:
        return status == _RATE_LIMITED or status >= _SERVER_ERROR
    names = {cls.__name__ for cls in type(error).__mro__}
    return bool(names.intersection(_TRANSIENT_NAMES))


def backoff_seconds(attempt: int, rng: random.Random) -> float:
    """Exponential backoff with jitter: min(90, 4 * 2**attempt) + U(0, 3) seconds."""
    return min(_BACKOFF_CAP, _BACKOFF_BASE * 2.0**attempt) + rng.random() * _BACKOFF_JITTER


def estimate_tokens(kwargs: Mapping[str, Any]) -> int:
    """Rough request size in tokens, used only to pace calls before they are made."""
    size = len(json.dumps(kwargs.get("messages") or kwargs.get("input") or "", default=str))
    size += len(json.dumps(kwargs.get("tools") or [], default=str))
    size += len(json.dumps(kwargs.get("system") or "", default=str))
    return int(size / 3.2) + 1200


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def usage_from_response(api: str, response: Any) -> tuple[Usage, str | None, str | None]:
    """Extract token usage, stop reason, and the returned model string from a response."""
    usage = getattr(response, "usage", None)
    returned = getattr(response, "model", None)
    returned_model = str(returned) if returned is not None else None
    if api == "chat":
        details = getattr(usage, "prompt_tokens_details", None)
        choices = getattr(response, "choices", None) or []
        stop = getattr(choices[0], "finish_reason", None) if choices else None
        return (
            Usage(
                input_tokens=_int(getattr(usage, "prompt_tokens", 0)),
                output_tokens=_int(getattr(usage, "completion_tokens", 0)),
                cache_read_tokens=_int(getattr(details, "cached_tokens", 0)),
            ),
            None if stop is None else str(stop),
            returned_model,
        )
    if api == "responses":
        input_details = getattr(usage, "input_tokens_details", None)
        output_details = getattr(usage, "output_tokens_details", None)
        status = getattr(response, "status", None) or "completed"
        return (
            Usage(
                input_tokens=_int(getattr(usage, "input_tokens", 0)),
                output_tokens=_int(getattr(usage, "output_tokens", 0)),
                cache_read_tokens=_int(getattr(input_details, "cached_tokens", 0)),
                reasoning_tokens=_int(getattr(output_details, "reasoning_tokens", 0)),
            ),
            str(status),
            returned_model,
        )
    stop = getattr(response, "stop_reason", None)
    return (
        Usage(
            input_tokens=_int(getattr(usage, "input_tokens", 0)),
            output_tokens=_int(getattr(usage, "output_tokens", 0)),
            cache_write_tokens=_int(getattr(usage, "cache_creation_input_tokens", 0)),
            cache_read_tokens=_int(getattr(usage, "cache_read_input_tokens", 0)),
        ),
        None if stop is None else str(stop),
        returned_model,
    )


class Pacer:
    """Sliding 60-second window of tokens and requests, kept separately per model.

    A request waits until both budgets have room; a single request larger than
    the token budget is still admitted when the window is empty.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        poll_seconds: float = 0.5,
    ) -> None:
        """Create a pacer with injectable time functions for deterministic tests."""
        self._lock = threading.Lock()
        self._windows: dict[str, deque[list[float]]] = {}
        self._clock = clock
        self._sleep = sleep
        self._poll = poll_seconds

    def acquire(self, key: str, estimate: int, *, tpm: int | None, rpm: int | None) -> list[float]:
        """Block until the call fits both budgets; return its window slot."""
        while True:
            with self._lock:
                now = self._clock()
                window = self._windows.setdefault(key, deque())
                while window and now - window[0][0] > WINDOW_SECONDS:
                    window.popleft()
                tokens = sum(slot[1] for slot in window)
                fits_tokens = tpm is None or tokens + estimate <= tpm
                fits_requests = rpm is None or len(window) + 1 <= rpm
                if (fits_tokens and fits_requests) or not window:
                    slot = [now, float(estimate)]
                    window.append(slot)
                    return slot
            self._sleep(self._poll)

    def settle(self, slot: list[float], actual: int) -> None:
        """Replace a slot's estimate with the provider-reported token count."""
        with self._lock:
            slot[1] = float(max(actual, 1))


_OPERATIONS: Final[Mapping[str, tuple[str, ...]]] = {
    "chat": ("chat", "completions", "create"),
    "responses": ("responses", "create"),
    "messages": ("messages", "create"),
}


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class ModelEndpoint:
    """Paced, retried calls to one model through one SDK client."""

    def __init__(  # noqa: PLR0913 - every dependency is injectable for offline tests
        self,
        settings: ModelSettings,
        client: Any,
        *,
        pacer: Pacer,
        secrets: Sequence[str] = (),
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
        clock: Callable[[], float] = time.monotonic,
        software: Mapping[str, str] | None = None,
    ) -> None:
        """Bind a settings object to an SDK client and a shared pacer."""
        self.settings = settings
        self.software = dict(software or {})
        self._client = client
        self._pacer = pacer
        self._secrets = tuple(secrets)
        self._sleep = sleep
        self._rng = rng or random.Random()  # noqa: S311 - jitter, not security
        self._clock = clock

    def _operation(self) -> Callable[..., Any]:
        target: Any = self._client
        for name in _OPERATIONS[self.settings.api]:
            target = getattr(target, name)
        return target  # type: ignore[no-any-return]

    def scrub(self, text: str) -> str:
        """Remove this endpoint's sensitive values from text."""
        return scrub(text, self._secrets)

    def call(self, kwargs: dict[str, Any], calls: list[CallRecord]) -> Any:
        """Make one paced call, retrying transient errors, and append its record.

        The record is appended whether the call succeeds or finally fails; a
        final failure is re-raised after recording.
        """
        operation = self._operation()
        estimate = estimate_tokens(kwargs)
        failures: list[FailedAttempt] = []
        started_at = _now()
        started = self._clock()
        tpm, rpm = self.settings.tpm, self.settings.rpm
        for attempt in range(self.settings.max_tries):
            slot = self._pacer.acquire(self.settings.model, estimate, tpm=tpm, rpm=rpm)
            try:
                response = operation(**kwargs)
            except Exception as error:
                self._pacer.settle(slot, estimate)
                transient = is_transient(error)
                last = attempt + 1 >= self.settings.max_tries
                wait = None if (not transient or last) else backoff_seconds(attempt, self._rng)
                failures.append(
                    FailedAttempt(
                        attempt=attempt + 1,
                        error_type=type(error).__name__,
                        status_code=_status_code(error),
                        message=self.scrub(str(error)),
                        transient=transient,
                        backoff_seconds=wait,
                    )
                )
                if wait is None:
                    calls.append(
                        CallRecord(
                            index=len(calls),
                            requested_model=self.settings.model,
                            returned_model=None,
                            usage=Usage(),
                            stop=None,
                            failed_attempts=tuple(failures),
                            started_at=started_at,
                            seconds=self._clock() - started,
                            error=f"{type(error).__name__}: {self.scrub(str(error))}",
                        )
                    )
                    raise
                self._sleep(wait)
                continue
            usage, stop, returned = usage_from_response(self.settings.api, response)
            self._pacer.settle(
                slot, usage.input_tokens + usage.output_tokens + usage.cache_write_tokens
            )
            calls.append(
                CallRecord(
                    index=len(calls),
                    requested_model=self.settings.model,
                    returned_model=returned,
                    usage=usage,
                    stop=stop,
                    failed_attempts=tuple(failures),
                    started_at=started_at,
                    seconds=self._clock() - started,
                )
            )
            return response
        message = "max_tries must be positive"  # pragma: no cover - validated in settings
        raise ProviderSetupError(message)  # pragma: no cover


@dataclass(frozen=True, slots=True)
class Pricing:
    """Assumed USD prices per million tokens."""

    input_per_million: float
    output_per_million: float

    def cost(self, usage: Usage) -> float:
        """Estimate cost; cache writes at 1.25x and cache reads at 0.1x the input price."""
        return (
            usage.input_tokens * self.input_per_million
            + usage.cache_write_tokens * self.input_per_million * 1.25
            + usage.cache_read_tokens * self.input_per_million * 0.1
            + usage.output_tokens * self.output_per_million
        ) / 1_000_000


class Budget:
    """Thread-safe spend estimate; new runs stop starting once it reaches the cap."""

    def __init__(
        self,
        *,
        max_usd: float | None,
        pricing: Pricing | None,
        already_spent: float = 0.0,
    ) -> None:
        """Create a budget; ``max_usd`` requires ``pricing``."""
        problem = None
        if max_usd is not None and pricing is None:
            problem = "--max-usd needs --price-in and --price-out"
        elif max_usd is not None and max_usd <= 0:
            problem = "--max-usd must be positive"
        if problem is not None:
            raise ProviderSetupError(problem)
        self.max_usd = max_usd
        self.pricing = pricing
        self.previously_spent = already_spent
        self._spent = 0.0
        self._lock = threading.Lock()

    def cost_of(self, usage: Usage) -> float | None:
        """Return the estimated cost of a usage total, or ``None`` without prices."""
        return None if self.pricing is None else self.pricing.cost(usage)

    def add(self, cost: float | None) -> None:
        """Add one run's estimated cost."""
        if cost is None:
            return
        with self._lock:
            self._spent += cost

    @property
    def spent(self) -> float:
        """Return spend estimated in this invocation."""
        with self._lock:
            return self._spent

    @property
    def total(self) -> float:
        """Return spend in this invocation plus spend recorded earlier in the output folder."""
        return self.previously_spent + self.spent

    def exhausted(self) -> bool:
        """Return whether no new run may start."""
        return self.max_usd is not None and self.total >= self.max_usd


__all__ = [
    "DEFAULT_API_KEY_ENV",
    "DEFAULT_BASE_URL",
    "INSTALL_HINT",
    "MAX_TRIES",
    "OPENAI_APIS",
    "PROVIDERS",
    "Budget",
    "ModelEndpoint",
    "ModelSettings",
    "Pacer",
    "Pricing",
    "ProviderName",
    "ProviderSetupError",
    "backoff_seconds",
    "build_sdk_client",
    "default_api",
    "estimate_tokens",
    "is_transient",
    "scrub",
    "usage_from_response",
]
