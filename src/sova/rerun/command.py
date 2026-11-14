# SPDX-License-Identifier: Apache-2.0
"""Arguments and handlers for ``sova rerun``, ``sova matrix`` and ``sova calibrate``."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from importlib import metadata
from pathlib import Path
from typing import IO, Any

from sova.rerun.agentdojo import AgentDojoRunner
from sova.rerun.calibrate import CHANGES, DEFAULT_CHANGES, CalibrateOptions, run_calibration
from sova.rerun.engine import (
    DEFAULT_ENVELOPE,
    EpisodeRunner,
    RerunError,
    RerunOptions,
    RunStore,
    load_envelope,
    rerun_finding,
)
from sova.rerun.findings import discover_capsules, load_finding, slug
from sova.rerun.matrix import MatrixOptions, run_matrix
from sova.rerun.providers import (
    OPENAI_APIS,
    PROVIDERS,
    Budget,
    ModelEndpoint,
    ModelSettings,
    Pacer,
    Pricing,
    build_sdk_client,
    default_api,
)

RunnerFactory = Callable[[Callable[[str], ModelSettings]], EpisodeRunner]
_DEFENSE_CHOICES = ("none", "repeat_user_prompt", "spotlighting_with_delimiting")

RERUN_EPILOG = """\
example:
  sova rerun finding.sova --model gpt-5.5 --provider openai-compatible \\
      --base-url-env SOVA_OPENAI_BASE_URL --api-key-env SOVA_OPENAI_API_KEY --trials 10 --authorize

Keys are read from the environment variables you name and are never printed or
written. Without --authorize nothing is run and no model is called.
"""

MATRIX_EPILOG = """\
examples:
  sova matrix findings/ --models a,b,c --trials 3 --authorize --out results/
  sova matrix findings/ --baseline old-model --candidate new-model --trials 5 --authorize

Runs already recorded in --out are reused, so an interrupted matrix can be resumed.
"""

CALIBRATE_EPILOG = """\
example:
  sova calibrate findings/ --model my-model --alternative other-model --trials 3 \\
      --authorize --out calibration/
  sova rerun finding.sova --model my-model --envelope calibration/envelope.json --authorize

Each finding runs unchanged and under each change. A change is material when the 95%
interval of its drop in recurrence is at or above --threshold, non-material when the
whole interval is below it, and undetermined otherwise. The envelope treats material
and undetermined changes as exact-match and records non-material ones. Runs already
in --out are reused; without --authorize no model is called, so the report is rebuilt
only when every run is already there.
"""


def _progress(stream: IO[str]) -> Callable[[str], None]:
    def write(line: str) -> None:
        stream.write(f"{line}\n")
        stream.flush()

    return write


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        message = "must be a positive integer"
        raise argparse.ArgumentTypeError(message)
    return number


def _non_negative_float(value: str) -> float:
    number = float(value)
    if number < 0:
        message = "must not be negative"
        raise argparse.ArgumentTypeError(message)
    return number


def _add_common(parser: argparse.ArgumentParser, *, envelope: bool = True) -> None:
    provider = parser.add_argument_group(
        "model provider (credentials come only from environment variables)"
    )
    provider.add_argument("--provider", choices=PROVIDERS, default="openai-compatible")
    provider.add_argument(
        "--api",
        choices=OPENAI_APIS,
        help="openai-compatible only: Chat Completions (default) or the Responses API "
        "(stateless, store=False, encrypted reasoning carried between turns)",
    )
    provider.add_argument("--base-url-env", metavar="NAME", help="variable holding the base URL")
    provider.add_argument(
        "--api-key-env",
        metavar="NAME",
        help="variable holding the API key (default OPENAI_API_KEY or ANTHROPIC_API_KEY)",
    )
    provider.add_argument("--temperature", type=float, help="sent only when given")
    provider.add_argument("--max-tokens", type=_positive_int, default=4096, help="anthropic only")
    pacing = parser.add_argument_group("pacing and budget (per model)")
    pacing.add_argument("--tpm", type=_positive_int, help="tokens per minute (default unlimited)")
    pacing.add_argument("--rpm", type=_positive_int, help="requests per minute (default unlimited)")
    pacing.add_argument(
        "--concurrency", type=_positive_int, default=4, help="runs in flight (default 4)"
    )
    pacing.add_argument(
        "--max-usd",
        type=_non_negative_float,
        metavar="USD",
        help="stop starting new runs once the estimated spend in --out reaches this",
    )
    pacing.add_argument(
        "--price-in", type=_non_negative_float, metavar="USD", help="per million input tokens"
    )
    pacing.add_argument(
        "--price-out", type=_non_negative_float, metavar="USD", help="per million output tokens"
    )
    run = parser.add_argument_group("what to run")
    run.add_argument(
        "--trials",
        type=_positive_int,
        metavar="N",
        help="fresh runs per finding and model (default: rerun 5, matrix 3)",
    )
    run.add_argument(
        "--defense", choices=_DEFENSE_CHOICES, help="default: the capsule's, else none"
    )
    run.add_argument(
        "--tool-output-format", choices=("yaml", "json"), help="default: the capsule's"
    )
    run.add_argument(
        "--system-message-file",
        type=Path,
        metavar="FILE",
        help="replace AgentDojo's system message with this text",
    )
    run.add_argument(
        "--attack-name",
        metavar="NAME",
        help="how the attack text addresses the model (default: from the model id)",
    )
    run.add_argument(
        "--benchmark-version",
        metavar="VERSION",
        help="AgentDojo suite version if the capsule omits it",
    )
    if envelope:
        run.add_argument(
            "--envelope",
            type=Path,
            metavar="FILE",
            help="JSON file overriding which differences from the recorded run are material",
        )
    output = parser.add_argument_group("output")
    output.add_argument(
        "--out", type=Path, metavar="DIR", help="output folder (runs found there are reused)"
    )
    output.add_argument("--json", action="store_true", help="print the JSON summary")
    parser.add_argument(
        "--authorize",
        action="store_true",
        help="allow model calls against AgentDojo's simulated environments",
    )


def add_rerun_arguments(parser: argparse.ArgumentParser) -> None:
    """Register ``sova rerun`` arguments."""
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.description = (
        "Re-run a recorded AgentDojo finding on a model and report how often the attack "
        "worked, and whether the recorded outcome was reproduced."
    )
    parser.epilog = RERUN_EPILOG
    parser.add_argument("capsule", type=Path, help="finding capsule (.sova)")
    parser.add_argument("--model", required=True, help="model id to run")
    parser.add_argument(
        "--recorded-trace",
        metavar="NAME",
        help="compare with this recorded trace in the capsule (default: chosen automatically)",
    )
    _add_common(parser)


def add_matrix_arguments(parser: argparse.ArgumentParser) -> None:
    """Register ``sova matrix`` arguments."""
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.description = (
        "Run findings x models x trials and print a table; with --baseline and "
        "--candidate, classify each finding across a model upgrade."
    )
    parser.epilog = MATRIX_EPILOG
    parser.add_argument("findings", nargs="+", type=Path, help="capsules or folders of capsules")
    parser.add_argument("--models", metavar="A,B,C", help="comma-separated model ids")
    parser.add_argument("--baseline", metavar="MODEL", help="upgrade check: the current model")
    parser.add_argument("--candidate", metavar="MODEL", help="upgrade check: the new model")
    _add_common(parser)


def _changes(value: str) -> tuple[str, ...]:
    names = tuple(item.strip() for item in value.split(",") if item.strip())
    unknown = [name for name in names if name not in CHANGES]
    if not names or unknown:
        message = f"choose from {', '.join(CHANGES)}"
        raise argparse.ArgumentTypeError(message)
    return names


def _fraction(value: str) -> float:
    number = float(value)
    if not 0 < number < 1:
        message = "must be between 0 and 1"
        raise argparse.ArgumentTypeError(message)
    return number


def add_calibrate_arguments(parser: argparse.ArgumentParser) -> None:
    """Register ``sova calibrate`` arguments."""
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.description = (
        "Measure, on one model, which setup changes affect whether recorded attacks recur, "
        "and write an envelope file for `sova rerun --envelope`."
    )
    parser.epilog = CALIBRATE_EPILOG
    parser.add_argument("findings", nargs="+", type=Path, help="capsules or folders of capsules")
    parser.add_argument("--model", required=True, help="model id to calibrate")
    parser.add_argument("--alternative", metavar="MODEL", help="other model for the 'model' change")
    parser.add_argument(
        "--changes",
        type=_changes,
        default=None,
        metavar="A,B",
        help=f"changes to measure (default: {','.join(DEFAULT_CHANGES)}; "
        "'model' is skipped without --alternative)",
    )
    parser.add_argument(
        "--threshold",
        type=_fraction,
        default=0.10,
        help="drop in recurrence that counts as material (default 0.10)",
    )
    parser.add_argument(
        "--resamples", type=_positive_int, default=2000, help="bootstrap resamples (default 2000)"
    )
    parser.add_argument("--seed", type=int, default=20261113, help="bootstrap seed")
    _add_common(parser, envelope=False)


def settings_factory(args: argparse.Namespace) -> Callable[[str], ModelSettings]:
    """Return a function building validated settings for one model from the arguments."""
    if args.provider == "anthropic" and args.api is not None:
        raise RerunError("SOVA-RERUN-ARGUMENTS", "--api applies to openai-compatible only")

    def build(model: str) -> ModelSettings:
        return ModelSettings(
            model=model,
            provider=args.provider,
            api=default_api(args.provider, args.api),
            base_url_env=args.base_url_env,
            api_key_env=args.api_key_env,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            tpm=args.tpm,
            rpm=args.rpm,
            concurrency=args.concurrency,
        )

    return build


def installed_version(package: str) -> str:
    """Return an installed package's version for the run record."""
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return "not-installed"


def default_runner(settings_for: Callable[[str], ModelSettings]) -> AgentDojoRunner:
    """Build the AgentDojo runner; SDK clients are created only for models that will run."""
    pacer = Pacer()

    def endpoint(model: str) -> ModelEndpoint:
        settings = settings_for(model)
        client, secrets = build_sdk_client(settings)
        package = "openai" if settings.provider == "openai-compatible" else "anthropic"
        return ModelEndpoint(
            settings,
            client,
            pacer=pacer,
            secrets=secrets,
            software={package: installed_version(package)},
        )

    return AgentDojoRunner(endpoint)


def _condition_override(args: argparse.Namespace) -> dict[str, Any]:
    override: dict[str, Any] = {}
    if args.defense is not None:
        override["defense"] = None if args.defense == "none" else args.defense
    if args.tool_output_format is not None:
        override["tool_output_format"] = args.tool_output_format
    if args.system_message_file is not None:
        override["system_message"] = args.system_message_file.read_text(encoding="utf-8")
    return override


def _budget(args: argparse.Namespace, store: RunStore) -> Budget:
    prices = (args.price_in, args.price_out)
    if (prices[0] is None) != (prices[1] is None):
        raise RerunError("SOVA-RERUN-ARGUMENTS", "give both --price-in and --price-out")
    pricing = None if prices[0] is None else Pricing(prices[0], prices[1])
    return Budget(
        max_usd=args.max_usd, pricing=pricing, already_spent=store.spent() if pricing else 0.0
    )


def _envelope(args: argparse.Namespace) -> tuple[Any, ...]:
    return DEFAULT_ENVELOPE if args.envelope is None else load_envelope(args.envelope)


def run_rerun_command(
    args: argparse.Namespace,
    *,
    runner_factory: RunnerFactory | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    """Handle ``sova rerun``."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    settings_for = settings_factory(args)
    settings = settings_for(args.model)
    finding = load_finding(args.capsule)
    out_dir = args.out or Path(f"{slug(finding.label, 80)}-rerun")
    options = RerunOptions(
        model=args.model,
        provider=args.provider,
        trials=args.trials or 5,
        out_dir=out_dir,
        authorize=args.authorize,
        concurrency=args.concurrency,
        condition_override=_condition_override(args),
        attack_name=args.attack_name,
        benchmark_version=args.benchmark_version,
        envelope=_envelope(args),
        recorded_trace=args.recorded_trace,
        settings=settings.describe(),
    )
    report = rerun_finding(
        finding,
        options,
        runner=(runner_factory or default_runner)(settings_for),
        budget=_budget(args, RunStore(out_dir)),
        progress=_progress(err),
    )
    if args.json:
        out.write(json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n")
    else:
        out.write(report.render() + "\n")
    return 0


def _matrix_models(args: argparse.Namespace) -> tuple[tuple[str, ...], str | None, str | None]:
    upgrade = args.baseline is not None or args.candidate is not None
    if upgrade and args.models:
        raise RerunError("SOVA-MATRIX-MODELS", "use either --models or --baseline/--candidate")
    if upgrade:
        if not args.baseline or not args.candidate:
            raise RerunError(
                "SOVA-MATRIX-MODELS", "an upgrade check needs both --baseline and --candidate"
            )
        if args.baseline == args.candidate:
            raise RerunError("SOVA-MATRIX-MODELS", "--baseline and --candidate must differ")
        return (args.baseline, args.candidate), args.baseline, args.candidate
    models = tuple(item.strip() for item in (args.models or "").split(",") if item.strip())
    return models, None, None


def run_matrix_command(
    args: argparse.Namespace,
    *,
    runner_factory: RunnerFactory | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    """Handle ``sova matrix``."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    models, baseline, candidate = _matrix_models(args)
    settings_for = settings_factory(args)
    described = {model: settings_for(model).describe() for model in models}
    findings = [load_finding(path) for path in discover_capsules(args.findings)]
    out_dir = args.out or Path("sova-matrix")
    options = MatrixOptions(
        models=models,
        provider=args.provider,
        trials=args.trials or 3,
        out_dir=out_dir,
        authorize=args.authorize,
        concurrency=args.concurrency,
        baseline=baseline,
        candidate=candidate,
        condition_override=_condition_override(args),
        attack_name=args.attack_name,
        benchmark_version=args.benchmark_version,
        envelope=_envelope(args),
        settings=described,
    )
    report = run_matrix(
        findings,
        options,
        runner=(runner_factory or default_runner)(settings_for),
        budget=_budget(args, RunStore(out_dir)),
        progress=_progress(err),
    )
    if args.json:
        out.write(json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n")
    else:
        out.write(report.render() + "\n")
    return 0


def run_calibrate_command(
    args: argparse.Namespace,
    *,
    runner_factory: RunnerFactory | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    """Handle ``sova calibrate``."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    if args.changes is not None:
        changes = args.changes
    else:
        changes = tuple(
            name for name in DEFAULT_CHANGES if name != "model" or args.alternative is not None
        )
    models = [args.model] + ([args.alternative] if args.alternative else [])
    if args.alternative == args.model:
        raise RerunError("SOVA-CALIBRATE-ALTERNATIVE", "--alternative must differ from --model")
    settings_for = settings_factory(args)
    findings = [load_finding(path) for path in discover_capsules(args.findings)]
    out_dir = args.out or Path("sova-calibration")
    options = CalibrateOptions(
        model=args.model,
        provider=args.provider,
        trials=args.trials or 3,
        out_dir=out_dir,
        authorize=args.authorize,
        changes=changes,
        alternative=args.alternative,
        threshold=args.threshold,
        resamples=args.resamples,
        seed=args.seed,
        concurrency=args.concurrency,
        attack_name=args.attack_name,
        benchmark_version=args.benchmark_version,
        base_override=_condition_override(args),
        settings={model: settings_for(model).describe() for model in models},
    )
    report = run_calibration(
        findings,
        options,
        runner=(runner_factory or default_runner)(settings_for),
        budget=_budget(args, RunStore(out_dir)),
        progress=_progress(err),
    )
    if args.json:
        out.write(json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n")
    else:
        out.write(report.render() + "\n")
    return 0


__all__ = [
    "RunnerFactory",
    "add_calibrate_arguments",
    "add_matrix_arguments",
    "add_rerun_arguments",
    "default_runner",
    "installed_version",
    "run_calibrate_command",
    "run_matrix_command",
    "run_rerun_command",
    "settings_factory",
]
