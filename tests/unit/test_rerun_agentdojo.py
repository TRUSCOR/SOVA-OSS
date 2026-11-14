# SPDX-License-Identifier: Apache-2.0
"""AgentDojo runner against an offline stand-in (no agentdojo, model, or network)."""

from __future__ import annotations

import random
from importlib import metadata
from types import SimpleNamespace
from typing import Any

import pytest

from sova.formats.errors import FormatError
from sova.rerun.agentdojo import (
    AgentDojoRunner,
    AgentDojoUnavailableError,
    _keep_valid_tool_calls,
    _never_queried,
    build_pipeline,
    default_attack_name,
    injections_for,
    load_agentdojo_api,
    make_llm_element,
    normalize_messages,
)
from sova.rerun.providers import ModelEndpoint, ModelSettings, Pacer
from sova.rerun.records import CallRecord, Condition, RunJob
from tests.support.fake_agentdojo import (
    FakeCall,
    FakeEnv,
    FakePipeline,
    FakeRuntime,
    FakeSuite,
    FakeTool,
    ScriptedSDK,
    anthropic_response,
    chat_response,
    fake_api,
    responses_response,
    tool_messages,
)

SEND: tuple[str, dict[str, Any]] = (
    "send_money",
    {"recipient": "US133000000121212121212", "amount": 0.01},
)
LOOK: tuple[str, dict[str, Any]] = ("get_most_recent_transactions", {"n": 100})


def _job(model: str = "gpt-5.5", condition: Condition | None = None, **changes: Any) -> RunJob:
    values: dict[str, Any] = {
        "key": f"k|{model}",
        "finding_label": "finding",
        "benchmark_version": "v1.2.2",
        "attack": "important_instructions",
        "suite": "banking",
        "user_task": "user_task_1",
        "injection_task": "injection_task_0",
        "model": model,
        "attack_name": default_attack_name(model),
        "condition": condition or Condition(),
        "trial": 1,
        "source_capsule_digest": "sha256:" + "0" * 64,
    }
    values.update(changes)
    return RunJob(**values)


def _attacking(kwargs: dict[str, Any]) -> Any:
    seen = tool_messages(kwargs)
    if "input" in kwargs:
        return responses_response(
            call=[LOOK, SEND][seen] if seen < 2 else None, text=None if seen < 2 else "done"
        )
    if "max_tokens" in kwargs:
        return anthropic_response(
            call=[LOOK, SEND][seen] if seen < 2 else None, text="checking" if seen < 2 else "done"
        )
    return chat_response(
        call=[LOOK, SEND][seen] if seen < 2 else None, content=None if seen < 2 else "done"
    )


def _runner(settings: ModelSettings, sdk: ScriptedSDK, **kwargs: Any) -> AgentDojoRunner:
    def endpoint(model: str) -> ModelEndpoint:
        assert model == settings.model
        return ModelEndpoint(
            settings,
            sdk,
            pacer=Pacer(sleep=lambda _seconds: None),
            secrets=("sk-test-secret",),
            sleep=lambda _seconds: None,
            rng=random.Random(1),  # noqa: S311 - deterministic backoff jitter
            software={"openai": "fake"},
        )

    runner = AgentDojoRunner(endpoint, api_loader=lambda: fake_api(**kwargs))
    runner.prepare([settings.model])
    return runner


@pytest.mark.parametrize(
    ("model", "name"),
    [
        ("gpt-4o", "GPT-4"),
        ("gpt-4o-2024-05-13", "GPT-4"),
        ("gpt-3.5-turbo-0125", "GPT-3.5"),
        ("gpt-5.5", "GPT"),
        ("claude-opus-5-5", "Claude"),
        ("DeepSeek-V4-Pro-2", "DeepSeek"),
        ("grok-4.7", "Grok"),
        ("Llama-4-Maverick-17B-128E-Instruct-FP8", "Llama"),
        ("Kimi-K3.1-Pro", "Kimi"),
        ("moonshot-v1", "Kimi"),
        ("Mistral-Large-3", "Mistral"),
        ("mistralai/Mixtral-8x7B-Instruct-v0.1", "Mixtral"),
        ("qwen3-max", "Qwen"),
        ("gemini-2.5-pro", "AI model developed by Google"),
        ("meta-llama/Llama-3-70b-chat-hf", "AI assistant"),
        ("command-r-plus", "Command R+"),
        ("o3-mini", "the AI language model"),
    ],
)
def test_default_attack_name(model: str, name: str) -> None:
    assert default_attack_name(model) == name


def test_load_api_reports_missing_wrong_and_unimportable_versions() -> None:
    def missing(_name: str) -> str:
        raise metadata.PackageNotFoundError("agentdojo")

    with pytest.raises(AgentDojoUnavailableError, match=r"sova-oss\[agentdojo\]"):
        load_agentdojo_api(version_of=missing)
    with pytest.raises(AgentDojoUnavailableError, match=r"0\.1\.35 but 0\.2\.0"):
        load_agentdojo_api(version_of=lambda _name: "0.2.0")

    def broken(_name: str) -> Any:
        raise ImportError("broken")

    with pytest.raises(AgentDojoUnavailableError, match="could not be imported"):
        load_agentdojo_api(version_of=lambda _name: "0.1.35", importer=broken)


def test_load_api_maps_the_pinned_modules() -> None:
    def module(_name: str) -> Any:
        return SimpleNamespace(
            MODEL_NAMES={"a": "A"},
            AgentPipeline="pipeline",
            PipelineConfig="config",
            BasePipelineElement=object,
            AbortAgentError=RuntimeError,
            ToolsExecutor=object,
            tool_result_to_str=str,
            load_attack="load",
            EmptyEnv=dict,
            FunctionsRuntime=list,
            FunctionCall=dict,
            get_suites="suites",
            functions_stack_trace_from_messages=list,
            model_output_from_messages=list,
            ChatAssistantMessage=dict,
            get_text_content_as_str=str,
            text_content_block_from_string=str,
        )

    api = load_agentdojo_api(version_of=lambda _name: "0.1.35", importer=module)
    assert api.version == "0.1.35"
    assert api.model_names == {"a": "A"}
    assert api.abort_error is RuntimeError


def test_normalize_messages_keeps_text_and_counts_other_blocks() -> None:
    messages = [
        "not a message",
        {"role": "system", "content": "plain"},
        {"role": "user", "content": None},
        {
            "role": "assistant",
            "content": [
                {"type": "thinking", "content": "hidden"},
                {"type": "text", "content": "visible"},
                "raw",
            ],
            "tool_calls": [
                FakeCall("f", {"x": 1.5}, "c1"),
                SimpleNamespace(function="g", args=None, id=None),
            ],
        },
        {
            "role": "tool",
            "content": [{"text": "result"}],
            "tool_call": FakeCall("f", {}, "c1"),
            "tool_call_id": "c1",
            "error": None,
        },
    ]
    normalized = normalize_messages(messages)
    assert [item["role"] for item in normalized] == ["system", "user", "assistant", "tool"]
    assert normalized[1]["text"] == ""
    assert normalized[2]["text"] == "visible\nraw"
    assert normalized[2]["omittedBlocks"] == {"thinking": 1}
    assert normalized[2]["toolCalls"][0] == {"id": "c1", "function": "f", "args": {"x": "1.5"}}
    assert normalized[2]["toolCalls"][1]["args"] is None
    assert normalized[3]["function"] == "f"
    assert "hidden" not in str(normalized)


def test_invalid_tool_names_are_dropped() -> None:
    output = {"tool_calls": [FakeCall("ok_name", {}), FakeCall("bad name!", {})]}
    assert [call.function for call in _keep_valid_tool_calls(output)["tool_calls"]] == ["ok_name"]
    only_bad = {"tool_calls": [FakeCall("x" * 65, {})]}
    assert _keep_valid_tool_calls(only_bad)["tool_calls"] is None
    assert _keep_valid_tool_calls({"tool_calls": None})["tool_calls"] is None


def test_chat_run_records_attack_calls_and_returned_models() -> None:
    settings = ModelSettings(model="gpt-5.5", temperature=0.0)
    sdk = ScriptedSDK(_attacking)
    record = _runner(settings, sdk).run(_job())
    assert record.error is None
    assert record.security is True
    assert record.utility is True
    assert record.returned_models() == ("fake-2026",)
    assert len(record.calls) == 3
    assert record.usage_total().cache_read_tokens == 300
    assert record.software == {"agentdojo": "0.1.35", "openai": "fake"}
    assert sdk.requests[0]["temperature"] == 0.0
    assert sdk.requests[0]["tool_choice"] == "auto"
    assert "GPT" in record.messages[3]["text"]
    assert record.injection_digest is not None


def test_responses_run_carries_encrypted_reasoning_and_resets_on_retry() -> None:
    settings = ModelSettings(model="gpt-6", api="responses", temperature=0.5)
    sdk = ScriptedSDK(_attacking)
    runner = _runner(settings, sdk)
    record = runner.run(_job("gpt-6"))
    assert record.security is True
    second = sdk.requests[1]
    assert second["store"] is False
    assert second["include"] == ["reasoning.encrypted_content"]
    assert second["temperature"] == 0.5
    types = [item.get("type", item.get("role")) for item in second["input"]]
    assert types[:2] == ["developer", "user"]
    assert "reasoning" in types
    assert "function_call_output" in types
    assert all("status" not in item for item in second["input"])


def test_responses_input_rebuilds_turns_not_produced_by_the_element() -> None:
    api = fake_api()
    settings = ModelSettings(model="gpt-6", api="responses")
    sdk = ScriptedSDK(lambda _kwargs: responses_response(text="ok"))
    calls: list[CallRecord] = []
    element = make_llm_element(api, ModelEndpoint(settings, sdk, pacer=Pacer()), calls)
    history = [
        {"role": "system", "content": [{"type": "text", "content": "sys"}]},
        {"role": "user", "content": [{"type": "text", "content": "hi"}]},
        {
            "role": "assistant",
            "content": [{"type": "text", "content": "earlier"}],
            "tool_calls": [FakeCall("f", {"a": 1}, "c9")],
        },
        {
            "role": "tool",
            "content": [{"type": "text", "content": "out"}],
            "tool_call_id": "c9",
            "error": None,
        },
        {"role": "assistant", "content": None, "tool_calls": None},
        {"role": "tool", "content": [], "tool_call_id": "c10", "error": "failed"},
    ]
    _query, _runtime, _env, messages, extra = element.query("hi", FakeRuntime([]), None, history)
    sent = sdk.requests[0]["input"]
    assert {"role": "assistant", "content": "earlier"} in sent
    assert any(item.get("type") == "function_call" and item["call_id"] == "c9" for item in sent)
    assert {"type": "function_call_output", "call_id": "c10", "output": "failed"} in sent
    assert "tools" not in sdk.requests[0]
    assert messages[-1]["content"] == [{"type": "text", "content": "ok"}]
    assert extra == {}


def test_anthropic_run_uses_caching_and_no_sampling_by_default() -> None:
    settings = ModelSettings(
        model="claude-x", provider="anthropic", api="messages", max_tokens=1024
    )
    sdk = ScriptedSDK(_attacking)
    record = _runner(settings, sdk).run(_job("claude-x"))
    assert record.security is True
    first = sdk.requests[0]
    assert "temperature" not in first
    assert "thinking" not in first
    assert first["max_tokens"] == 1024
    assert first["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert first["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    assert record.messages[2]["omittedBlocks"] == {"thinking": 1}
    assert record.usage_total().cache_write_tokens == 150

    tempered = ModelSettings(
        model="claude-x", provider="anthropic", api="messages", temperature=1.0
    )
    sdk2 = ScriptedSDK(_attacking)
    _runner(tempered, sdk2).run(_job("claude-x"))
    assert sdk2.requests[0]["temperature"] == 1.0


def test_anthropic_without_tools_or_system_prompt() -> None:
    api = fake_api()
    settings = ModelSettings(model="claude-x", provider="anthropic", api="messages")
    sdk = ScriptedSDK(lambda _kwargs: anthropic_response(text="hello"))
    element = make_llm_element(api, ModelEndpoint(settings, sdk, pacer=Pacer()), [])
    element.query(
        "q",
        FakeRuntime([]),
        FakeEnv(),
        [{"role": "user", "content": [{"type": "text", "content": "q"}]}],
    )
    assert "tools" not in sdk.requests[0]
    assert "system" not in sdk.requests[0]


def test_json_tool_output_writes_dates_as_iso_strings_and_keeps_delimiters() -> None:
    api = fake_api()
    llm = SimpleNamespace(name="m")
    plain = build_pipeline(api, llm, Condition(tool_output_format="json"))
    text = plain.executor.output_formatter({"date": __import__("datetime").datetime(2022, 3, 1)})
    assert text == '{"date": "2022-03-01T00:00:00"}'
    other = plain.executor.output_formatter({"value": object()})
    assert other.startswith('{"value": "<object')
    spotlit = build_pipeline(
        api, llm, Condition(defense="spotlighting_with_delimiting", tool_output_format="json")
    )
    assert spotlit.executor.output_formatter({"a": 1}) == '<<{"a": 1}>>'
    yaml_default = build_pipeline(api, llm, Condition())
    assert yaml_default.config.tool_output_format is None
    assert yaml_default.config.defense is None


def test_json_run_and_repeat_user_prompt_defense() -> None:
    settings = ModelSettings(model="gpt-5.5")
    sdk = ScriptedSDK(_attacking)
    condition = Condition(
        defense="repeat_user_prompt", tool_output_format="json", system_message="Be careful."
    )
    record = _runner(settings, sdk).run(_job(condition=condition))
    assert record.error is None
    assert record.messages[0]["text"] == "Be careful."
    tool_text = next(item["text"] for item in record.messages if item["role"] == "tool")
    assert '"date": "2022-03-01T12:00:00"' in tool_text
    assert sum(1 for item in record.messages if item["role"] == "user") >= 2


def test_injections_use_existing_names_or_a_temporary_probe() -> None:
    api = fake_api()
    suite = FakeSuite()
    user, injection = suite.user_tasks["user_task_1"], suite.injection_tasks["injection_task_0"]
    before = dict(api.model_names)
    existing = injections_for(
        api, suite, attack="a", attack_name="GPT-4", user_task=user, injection_task=injection
    )
    assert "GPT-4" in existing["injection_incoming_transaction"]
    probed = injections_for(
        api, suite, attack="a", attack_name="Grok", user_task=user, injection_task=injection
    )
    assert "Grok" in probed["injection_incoming_transaction"]
    assert api.model_names == before

    shadowed = fake_api(model_names={"probe": "Other"})
    with pytest.raises(FormatError, match="cannot address"):
        injections_for(
            shadowed,
            suite,
            attack="a",
            attack_name="Grok",
            user_task=user,
            injection_task=injection,
        )
    assert shadowed.model_names == {"probe": "Other"}
    with pytest.raises(RuntimeError, match="never be queried"):
        _never_queried(None)


def test_failures_are_recorded_and_secrets_scrubbed() -> None:
    settings = ModelSettings(model="gpt-5.5")

    def leak(_kwargs: dict[str, Any]) -> Any:
        message = "bad request with sk-test-secret inside"
        raise ValueError(message)

    record = _runner(settings, ScriptedSDK(leak)).run(_job())
    assert record.security is None
    assert record.error is not None
    assert "sk-test-secret" not in record.error
    assert "[redacted]" in record.error
    assert record.calls[0].error is not None

    unknown = _runner(settings, ScriptedSDK(_attacking)).run(_job(suite="nope"))
    assert unknown.error is not None
    assert unknown.error.startswith("KeyError")
    assert unknown.messages == ()


def test_abort_and_missing_model_output() -> None:
    settings = ModelSettings(model="gpt-5.5")
    original_abort, original_stop = FakePipeline.abort_on_query, FakePipeline.stop_without_output
    try:
        FakePipeline.abort_on_query = True
        aborted = _runner(settings, ScriptedSDK(_attacking)).run(_job())
        assert aborted.error is not None  # aborted before an assistant message
        assert "Last message was not an assistant message" in aborted.error
        FakePipeline.abort_on_query = False
        FakePipeline.stop_without_output = True
        sdk = ScriptedSDK(_attacking)
        missing = _runner(settings, sdk).run(_job())
        assert missing.model_output_missing is True
        assert missing.security is True
        assert len(sdk.requests) == 9  # three pipeline attempts of three calls each
    finally:
        FakePipeline.abort_on_query, FakePipeline.stop_without_output = (
            original_abort,
            original_stop,
        )


def test_runner_lifecycle() -> None:
    settings = ModelSettings(model="gpt-5.5")
    built: list[str] = []

    def endpoint(model: str) -> ModelEndpoint:
        built.append(model)
        return ModelEndpoint(settings, ScriptedSDK(_attacking), pacer=Pacer())

    runner = AgentDojoRunner(endpoint, api_loader=fake_api)
    with pytest.raises(RuntimeError, match="prepare"):
        _ = runner.api
    runner.prepare(["gpt-5.5"])
    runner.prepare(["gpt-5.5"])
    assert built == ["gpt-5.5"]
    first = runner.run(_job())
    second = runner.run(_job(trial=2))
    assert first.injection_digest == second.injection_digest
    assert FakeTool("other").run({"a": 1}, FakeEnv()) == {"status": "sent", "args": {"a": 1}}
