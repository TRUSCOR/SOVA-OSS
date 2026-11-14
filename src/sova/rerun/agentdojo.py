# SPDX-License-Identifier: Apache-2.0
"""Fresh AgentDojo episodes for recorded findings (optional ``agentdojo`` extra).

AgentDojo (MIT licence, pinned to 0.1.35) is imported lazily, only when a run is
actually started. Its environments are simulated: synthetic banking, workspace,
travel, and Slack data with no real account or network effect. The only network
traffic is the model provider call, made through :class:`ModelEndpoint`.

The pipeline settings map to AgentDojo's ``PipelineConfig`` exactly: ``defense``
(``None``, ``repeat_user_prompt``, ``spotlighting_with_delimiting``),
``tool_output_format`` (``None``/``yaml`` or ``json``), and ``system_message``
(``None`` keeps AgentDojo's default). AgentDojo 0.1.35's JSON tool output cannot
serialize dates; the runner writes them as ISO-8601 strings instead.
"""

from __future__ import annotations

import functools
import json
import re
import threading
import time
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import import_module, metadata
from typing import Any, Final, Protocol

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.rerun.providers import INSTALL_HINT, ModelEndpoint
from sova.rerun.records import CallRecord, Condition, RunJob, RunRecord, jsonable

AGENTDOJO_VERSION: Final = "0.1.35"
DEFAULT_MODEL_NAME: Final = "the AI language model"
PIPELINE_ATTEMPTS: Final = 3
_VALID_TOOL_NAME: Final = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_PROBE_NAME: Final = "sova-rerun-attack-name-probe"
_NAMES_LOCK: Final = threading.Lock()
_ERROR_LIMIT: Final = 300
# Names AgentDojo 0.1.35 itself uses for these model ids (its MODEL_NAMES table),
# where a family rule below would give a different name.
_AGENTDOJO_EXACT_NAMES: Final[Mapping[str, str]] = {
    "meta-llama/Llama-3-70b-chat-hf": "AI assistant",
    "command-r-plus": "Command R+",
    "command-r": "Command R",
    "local": "Local model",
    "vllm_parsed": "Local model",
}
_FAMILY_NAMES: Final[tuple[tuple[str, str], ...]] = (
    ("gpt-4", "GPT-4"),
    ("gpt-3.5", "GPT-3.5"),
    ("gpt", "GPT"),
    ("claude", "Claude"),
    ("deepseek", "DeepSeek"),
    ("grok", "Grok"),
    ("llama", "Llama"),
    ("kimi", "Kimi"),
    ("moonshot", "Kimi"),
    ("mixtral", "Mixtral"),
    ("mistral", "Mistral"),
    ("qwen", "Qwen"),
    ("gemini", "AI model developed by Google"),
)


class AgentDojoUnavailableError(FormatError):
    """The optional AgentDojo dependency is missing or is not the pinned version."""

    def __init__(self, message: str) -> None:
        """Create the error with a fixed machine-readable code."""
        super().__init__("SOVA-RERUN-AGENTDOJO", message)


def default_attack_name(model: str) -> str:
    """Return how the attack text addresses the model, derived from its id.

    AgentDojo's own names are kept where it defines one (gpt-4o is "GPT-4");
    otherwise a family name is used (GPT, Claude, DeepSeek, Grok, Llama, Kimi,
    Mistral, ...), and AgentDojo's generic default for unknown models.
    """
    if model in _AGENTDOJO_EXACT_NAMES:
        return _AGENTDOJO_EXACT_NAMES[model]
    lowered = model.lower()
    return next((name for family, name in _FAMILY_NAMES if family in lowered), DEFAULT_MODEL_NAME)


@dataclass(frozen=True, slots=True)
class AgentDojoAPI:
    """The parts of AgentDojo the runner uses, injectable for offline tests."""

    version: str
    base_element: type[Any]
    agent_pipeline: Any
    pipeline_config: Callable[..., Any]
    abort_error: type[BaseException]
    empty_env: Callable[[], Any]
    functions_runtime: Callable[[Any], Any]
    get_suites: Callable[[str], Mapping[str, Any]]
    load_attack: Callable[[str, Any, Any], Any]
    stack_trace: Callable[[Sequence[Any]], Any]
    model_output: Callable[[Sequence[Any]], Any]
    openai_llm: Any
    anthropic_llm: Any
    function_call: Callable[..., Any]
    assistant_message: Callable[..., Any]
    text_of: Callable[[Any], str]
    text_block: Callable[[str], Any]
    tools_executor: type[Any]
    tool_result_to_str: Callable[..., str]
    model_names: MutableMapping[str, str]


def load_agentdojo_api(
    *,
    importer: Callable[[str], Any] = import_module,
    version_of: Callable[[str], str] = metadata.version,
) -> AgentDojoAPI:
    """Import the pinned AgentDojo release, or explain how to install it."""
    try:
        version = version_of("agentdojo")
    except metadata.PackageNotFoundError as error:
        message = (
            f"re-running AgentDojo findings needs agentdojo {AGENTDOJO_VERSION}; {INSTALL_HINT}"
        )
        raise AgentDojoUnavailableError(message) from error
    if version != AGENTDOJO_VERSION:
        message = (
            f"this runner is pinned to agentdojo {AGENTDOJO_VERSION} but {version} is installed; "
            f"{INSTALL_HINT}"
        )
        raise AgentDojoUnavailableError(message)
    try:
        models = importer("agentdojo.models")
        pipeline = importer("agentdojo.agent_pipeline.agent_pipeline")
        base = importer("agentdojo.agent_pipeline.base_pipeline_element")
        errors = importer("agentdojo.agent_pipeline.errors")
        tools = importer("agentdojo.agent_pipeline.tool_execution")
        attacks = importer("agentdojo.attacks.attack_registry")
        runtime = importer("agentdojo.functions_runtime")
        suites = importer("agentdojo.task_suite.load_suites")
        task_suite = importer("agentdojo.task_suite.task_suite")
        types = importer("agentdojo.types")
        openai_llm = importer("agentdojo.agent_pipeline.llms.openai_llm")
        anthropic_llm = importer("agentdojo.agent_pipeline.llms.anthropic_llm")
    except ImportError as error:
        message = f"agentdojo {AGENTDOJO_VERSION} could not be imported; {INSTALL_HINT}"
        raise AgentDojoUnavailableError(message) from error
    return AgentDojoAPI(
        version=version,
        base_element=base.BasePipelineElement,
        agent_pipeline=pipeline.AgentPipeline,
        pipeline_config=pipeline.PipelineConfig,
        abort_error=errors.AbortAgentError,
        empty_env=runtime.EmptyEnv,
        functions_runtime=runtime.FunctionsRuntime,
        get_suites=suites.get_suites,
        load_attack=attacks.load_attack,
        stack_trace=task_suite.functions_stack_trace_from_messages,
        model_output=task_suite.model_output_from_messages,
        openai_llm=openai_llm,
        anthropic_llm=anthropic_llm,
        function_call=runtime.FunctionCall,
        assistant_message=types.ChatAssistantMessage,
        text_of=types.get_text_content_as_str,
        text_block=types.text_content_block_from_string,
        tools_executor=tools.ToolsExecutor,
        tool_result_to_str=tools.tool_result_to_str,
        model_names=models.MODEL_NAMES,
    )


# --------------------------------------------------------------------------- messages
def _text_and_omitted(content: Any) -> tuple[str, dict[str, int]]:
    if content is None:
        return "", {}
    if isinstance(content, str):
        return content, {}
    parts: list[str] = []
    omitted: dict[str, int] = {}
    for block in content:
        if isinstance(block, Mapping):
            kind = str(block.get("type") or "text")
            if kind == "text":
                parts.append(str(block.get("content") or block.get("text") or ""))
            else:
                omitted[kind] = omitted.get(kind, 0) + 1
        else:
            parts.append(str(block))
    return "\n".join(parts), omitted


def _tool_call_json(call: Any) -> dict[str, Any]:
    args = getattr(call, "args", None)
    return {
        "id": getattr(call, "id", None),
        "function": getattr(call, "function", None),
        "args": jsonable(dict(args) if isinstance(args, Mapping) else args),
    }


def normalize_messages(messages: Sequence[Any]) -> tuple[dict[str, Any], ...]:
    """Turn AgentDojo chat messages into plain, canonical-JSON-safe dictionaries.

    Only text blocks are kept as text; other blocks (for example a model's
    thinking) are counted in ``omittedBlocks`` but not recorded.
    """
    normalized: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        role = message.get("role")
        text, omitted = _text_and_omitted(message.get("content"))
        item: dict[str, Any] = {"role": role, "text": text}
        if omitted:
            item["omittedBlocks"] = omitted
        if role == "assistant":
            item["toolCalls"] = [_tool_call_json(call) for call in message.get("tool_calls") or []]
        elif role == "tool":
            item["function"] = getattr(message.get("tool_call"), "function", None)
            item["toolCallId"] = message.get("tool_call_id")
            item["error"] = message.get("error")
        normalized.append(item)
    return tuple(normalized)


def _keep_valid_tool_calls(output: Any) -> Any:
    calls = output.get("tool_calls")
    if calls is not None:
        output["tool_calls"] = [
            call for call in calls if _VALID_TOOL_NAME.match(str(call.function))
        ] or None
    return output


# --------------------------------------------------------------------------- model elements
class _Turn(Protocol):
    def __call__(self, messages: Sequence[Any], runtime: Any) -> Any: ...


def _element(api: AgentDojoAPI, name: str, turn: _Turn) -> Any:
    def query(
        _self: Any,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: Sequence[Any] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, list[Any], dict[str, Any]]:
        environment = env if env is not None else api.empty_env()
        output = turn(list(messages), runtime)
        return query, runtime, environment, [*messages, output], extra_args or {}

    element_type = type("SovaRerunLLM", (api.base_element,), {"query": query, "name": name})
    return element_type()


def _chat_turn(api: AgentDojoAPI, endpoint: ModelEndpoint, calls: list[CallRecord]) -> _Turn:
    model = endpoint.settings.model

    def turn(messages: Sequence[Any], runtime: Any) -> Any:
        tools = [api.openai_llm._function_to_openai(item) for item in runtime.functions.values()]
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": [api.openai_llm._message_to_openai(item, model) for item in messages],
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if endpoint.settings.temperature is not None:
            kwargs["temperature"] = endpoint.settings.temperature
        completion = endpoint.call(kwargs, calls)
        message = completion.choices[0].message
        return _keep_valid_tool_calls(api.openai_llm._openai_to_assistant_message(message))

    return turn


def _responses_input(
    api: AgentDojoAPI,
    messages: Sequence[Any],
    raw_outputs: Sequence[list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    turn = 0
    for message in messages:
        role = message["role"]
        if role in {"system", "user"}:
            items.append(
                {
                    "role": "developer" if role == "system" else "user",
                    "content": api.text_of(message["content"] or []),
                }
            )
        elif role == "assistant":
            if turn < len(raw_outputs):
                items.extend(raw_outputs[turn])
            else:  # an assistant turn this element did not produce
                text = api.text_of(message["content"] or [])
                if text:
                    items.append({"role": "assistant", "content": text})
                items.extend(
                    {
                        "type": "function_call",
                        "call_id": call.id,
                        "name": call.function,
                        "arguments": json.dumps(dict(call.args)),
                    }
                    for call in message["tool_calls"] or []
                )
            turn += 1
        elif role == "tool":
            output = message["error"] or api.text_of(message["content"] or [])
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": message["tool_call_id"],
                    "output": output,
                }
            )
    return items


def _responses_turn(api: AgentDojoAPI, endpoint: ModelEndpoint, calls: list[CallRecord]) -> _Turn:
    """Responses API, stateless (``store=False``): encrypted reasoning is carried between turns."""
    model = endpoint.settings.model
    raw_outputs: list[list[dict[str, Any]]] = []

    def turn(messages: Sequence[Any], runtime: Any) -> Any:
        produced = sum(1 for message in messages if message["role"] == "assistant")
        del raw_outputs[produced:]  # a pipeline retry restarts the conversation
        tools = []
        for item in runtime.functions.values():
            function = api.openai_llm._function_to_openai(item)["function"]
            tools.append(
                {
                    "type": "function",
                    "name": function["name"],
                    "description": function.get("description", ""),
                    "parameters": function["parameters"],
                }
            )
        kwargs: dict[str, Any] = {
            "model": model,
            "input": _responses_input(api, messages, raw_outputs),
            "store": False,
            "include": ["reasoning.encrypted_content"],
        }
        if tools:
            kwargs["tools"] = tools
        if endpoint.settings.temperature is not None:
            kwargs["temperature"] = endpoint.settings.temperature
        response = endpoint.call(kwargs, calls)
        raw = [item.model_dump(exclude_none=True) for item in response.output]
        for item in raw:
            item.pop("status", None)
        raw_outputs.append(raw)
        text = "\n".join(
            part.get("text", "")
            for item in raw
            if item.get("type") == "message"
            for part in item.get("content", [])
            if part.get("type") == "output_text"
        )
        tool_calls = [
            api.function_call(
                function=item["name"],
                args=json.loads(item.get("arguments") or "{}"),
                id=item["call_id"],
            )
            for item in raw
            if item.get("type") == "function_call"
        ]
        output = api.assistant_message(
            role="assistant",
            content=[api.text_block(text)] if text else None,
            tool_calls=tool_calls or None,
        )
        return _keep_valid_tool_calls(output)

    return turn


def _anthropic_turn(api: AgentDojoAPI, endpoint: ModelEndpoint, calls: list[CallRecord]) -> _Turn:
    """Messages API without sampling or thinking parameters unless given, with prompt caching."""
    settings = endpoint.settings

    def turn(messages: Sequence[Any], runtime: Any) -> Any:
        system_prompt, anthropic_messages = api.anthropic_llm._conversation_to_anthropic(messages)
        tools = [
            dict(api.anthropic_llm._function_to_anthropic(item))
            for item in runtime.functions.values()
        ]
        if tools:
            tools[-1]["cache_control"] = {"type": "ephemeral"}
        kwargs: dict[str, Any] = {
            "model": settings.model,
            "max_tokens": settings.max_tokens,
            "messages": anthropic_messages,
        }
        if tools:
            kwargs["tools"] = tools
        if system_prompt:
            kwargs["system"] = [
                {"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}
            ]
        if settings.temperature is not None:
            kwargs["temperature"] = settings.temperature
        completion = endpoint.call(kwargs, calls)
        return _keep_valid_tool_calls(api.anthropic_llm._anthropic_to_assistant_message(completion))

    return turn


def make_llm_element(api: AgentDojoAPI, endpoint: ModelEndpoint, calls: list[CallRecord]) -> Any:
    """Return an AgentDojo pipeline element that calls ``endpoint`` and records each call."""
    settings = endpoint.settings
    if settings.provider == "anthropic":
        turn = _anthropic_turn(api, endpoint, calls)
    elif settings.api == "responses":
        turn = _responses_turn(api, endpoint, calls)
    else:
        turn = _chat_turn(api, endpoint, calls)
    return _element(api, settings.model, turn)


# --------------------------------------------------------------------------- pipeline
def _iso_json(value: Any) -> str:
    return json.dumps(
        value, default=lambda item: item.isoformat() if hasattr(item, "isoformat") else str(item)
    )


def _use_iso_dates(api: AgentDojoAPI, element: Any, *, delimited: bool) -> None:
    formatter = functools.partial(api.tool_result_to_str, dump_fn=_iso_json)

    def delimited_formatter(result: Any) -> str:
        return f"<<{formatter(result)}>>"

    if isinstance(element, api.tools_executor):
        element.output_formatter = delimited_formatter if delimited else formatter
    for child in getattr(element, "elements", None) or []:
        _use_iso_dates(api, child, delimited=delimited)


def build_pipeline(api: AgentDojoAPI, llm: Any, condition: Condition) -> Any:
    """Build AgentDojo's own pipeline for ``condition`` around ``llm``."""
    config = api.pipeline_config(
        llm=llm,
        model_id=None,
        defense=condition.defense,
        system_message_name=None,
        system_message=condition.system_message,
        tool_output_format=condition.tool_output_format,
    )
    pipeline = api.agent_pipeline.from_config(config)
    if condition.tool_output_format == "json":
        _use_iso_dates(api, pipeline, delimited=condition.defense == "spotlighting_with_delimiting")
    return pipeline


def _never_queried(_self: Any, *_args: Any, **_kwargs: Any) -> Any:
    message = "the attack-name probe must never be queried"
    raise RuntimeError(message)


def _resolved_name(names: Mapping[str, str], pipeline_name: str) -> str | None:
    # AgentDojo returns the first table entry whose key occurs in the pipeline name.
    return next((name for key, name in names.items() if key in pipeline_name), None)


def injections_for(  # noqa: PLR0913 - an attack is fully determined by these inputs
    api: AgentDojoAPI,
    suite: Any,
    *,
    attack: str,
    attack_name: str,
    user_task: Any,
    injection_task: Any,
) -> dict[str, str]:
    """Build the attack's injections, addressing the model as ``attack_name``.

    An existing AgentDojo table entry that already resolves to ``attack_name`` is
    used as is; otherwise a probe entry is added for the duration of the call
    and removed afterwards, so AgentDojo's table is left unchanged.
    """
    with _NAMES_LOCK:
        names = api.model_names
        probe_name = next(
            (
                key
                for key, name in names.items()
                if name == attack_name and _resolved_name(names, key) == attack_name
            ),
            None,
        )
        inserted = probe_name is None
        if probe_name is None:
            probe_name = _PROBE_NAME
            names[probe_name] = attack_name
        try:
            if _resolved_name(names, probe_name) != attack_name:
                message = (
                    f"AgentDojo's model-name table cannot address the model as {attack_name!r}"
                )
                raise FormatError("SOVA-RERUN-ATTACK-NAME", message)
            probe_type = type(
                "SovaAttackNameProbe",
                (api.base_element,),
                {"query": _never_queried, "name": probe_name},
            )
            loaded = api.load_attack(attack, suite, probe_type())
            return {
                str(key): str(value)
                for key, value in loaded.attack(user_task, injection_task).items()
            }
        finally:
            if inserted:
                names.pop(probe_name, None)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class AgentDojoRunner:
    """Run fresh AgentDojo episodes through paced, recorded model endpoints."""

    def __init__(
        self,
        endpoint_factory: Callable[[str], ModelEndpoint],
        *,
        api_loader: Callable[[], AgentDojoAPI] = load_agentdojo_api,
        software: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create a runner; nothing is imported or contacted until :meth:`prepare`."""
        self._endpoint_factory = endpoint_factory
        self._api_loader = api_loader
        self._software = dict(software or {})
        self._clock = clock
        self._api: AgentDojoAPI | None = None
        self._endpoints: dict[str, ModelEndpoint] = {}
        self._injections: dict[tuple[str, ...], dict[str, str]] = {}
        self._lock = threading.Lock()

    @property
    def api(self) -> AgentDojoAPI:
        """Return the loaded AgentDojo API (after :meth:`prepare`)."""
        if self._api is None:
            message = "runner.prepare() must be called before running episodes"
            raise RuntimeError(message)
        return self._api

    def prepare(self, models: Sequence[str]) -> None:
        """Import AgentDojo and build an endpoint for each model; fail fast on setup errors."""
        if self._api is None:
            self._api = self._api_loader()
        for model in models:
            if model not in self._endpoints:
                self._endpoints[model] = self._endpoint_factory(model)

    def _injections_for(
        self, job: RunJob, suite: Any, user_task: Any, injection_task: Any
    ) -> dict[str, str]:
        key = (
            job.benchmark_version,
            job.suite,
            job.user_task,
            job.injection_task,
            job.attack,
            job.attack_name,
        )
        with self._lock:
            cached = self._injections.get(key)
        if cached is not None:
            return cached
        value = injections_for(
            self.api,
            suite,
            attack=job.attack,
            attack_name=job.attack_name,
            user_task=user_task,
            injection_task=injection_task,
        )
        with self._lock:
            self._injections[key] = value
        return value

    def run(self, job: RunJob) -> RunRecord:
        """Run one episode; any failure is recorded on the run, never raised as a verdict."""
        api = self.api
        endpoint = self._endpoints[job.model]
        calls: list[CallRecord] = []
        messages: Sequence[Any] = []
        started_at = _now()
        started = self._clock()
        injection_digest: str | None = None
        model_output_missing = False
        security: bool | None = None
        utility: bool | None = None
        error: str | None = None
        try:
            suite = api.get_suites(job.benchmark_version)[job.suite]
            user_task = suite.user_tasks[job.user_task]
            injection_task = suite.injection_tasks[job.injection_task]
            injections = self._injections_for(job, suite, user_task, injection_task)
            injection_digest = sha256_digest(canonical_json_bytes(injections))
            pipeline = build_pipeline(api, make_llm_element(api, endpoint, calls), job.condition)
            environment = suite.load_and_inject_default_environment(injections)
            task_environment = user_task.init_environment(environment)
            pre_environment = task_environment.model_copy(deep=True)
            runtime = api.functions_runtime(suite.tools)
            model_output = None
            for _ in range(PIPELINE_ATTEMPTS):
                try:
                    _, _, task_environment, messages, _ = pipeline.query(
                        user_task.PROMPT, runtime, task_environment
                    )
                except api.abort_error as abort:
                    task_environment = getattr(abort, "task_environment", task_environment)
                    messages = getattr(abort, "messages", messages)
                model_output = api.model_output(messages)
                if model_output is not None:
                    break
            model_output_missing = model_output is None
            stack = api.stack_trace(messages)
            utility = bool(
                suite._check_task_result(
                    user_task, model_output or [], pre_environment, task_environment, stack
                )
            )
            security = bool(
                suite._check_task_result(
                    injection_task, model_output or [], pre_environment, task_environment, stack
                )
            )
        except Exception as failure:  # noqa: BLE001 - a failed run is recorded as can't-tell
            security = utility = None
            error = f"{type(failure).__name__}: {endpoint.scrub(str(failure))}"[:_ERROR_LIMIT]
        software = {"agentdojo": api.version, **self._software, **endpoint.software}
        return RunRecord(
            job=job,
            provider=endpoint.settings.provider,
            api=endpoint.settings.api,
            temperature=endpoint.settings.temperature,
            started_at=started_at,
            finished_at=_now(),
            seconds=self._clock() - started,
            messages=normalize_messages(messages),
            calls=tuple(calls),
            security=security,
            utility=utility,
            error=error,
            model_output_missing=model_output_missing,
            injection_digest=injection_digest,
            software=software,
        )


__all__ = [
    "AGENTDOJO_VERSION",
    "DEFAULT_MODEL_NAME",
    "AgentDojoAPI",
    "AgentDojoRunner",
    "AgentDojoUnavailableError",
    "build_pipeline",
    "default_attack_name",
    "injections_for",
    "load_agentdojo_api",
    "make_llm_element",
    "normalize_messages",
]
