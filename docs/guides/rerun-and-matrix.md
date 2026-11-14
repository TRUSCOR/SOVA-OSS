<!-- status: implemented -->

# Re-run a finding on your model

A `.sova` finding records an attack on an AI agent: the scenario, the recorded
run as a `.sova-trace`, and the outcome. `sova rerun` runs that attack again, fresh,
on the model you choose and tells you how often it works now. `sova matrix` does
the same for many findings and models, and can check a model upgrade.

Today this works for findings recorded on [AgentDojo](https://github.com/ethz-spylab/agentdojo)
(the scenario's `parameters.benchmark` is `AgentDojo`). Runs happen only in
AgentDojo's simulated banking, workspace, travel, and Slack environments: no real
account, payment, message, or file is touched. The only network traffic is the
call to your model provider.

## Install

```powershell
pip install "sova-oss[agentdojo]"
```

The extra pins `agentdojo==0.1.35`, which also brings the OpenAI and Anthropic
Python SDKs. Opening, verifying, or inspecting a capsule never needs it.

## Re-run one finding (two minutes)

Put the endpoint and key in environment variables. SOVA reads only the variables
you name; it never accepts a key as an argument and never prints or writes one.

```powershell
$env:SOVA_OPENAI_BASE_URL = "https://your-endpoint.example/v1"
$env:SOVA_OPENAI_API_KEY  = "..."   # set it in your shell, not in a file you share

sova rerun finding.sova --model gpt-5.5 --provider openai-compatible `
  --base-url-env SOVA_OPENAI_BASE_URL --api-key-env SOVA_OPENAI_API_KEY `
  --trials 10 --authorize
```

```text
-> attack worked 7 of 10 runs (Wilson 95%: 40%-89%); 0 runs could not be judged
-> compared with the recorded run: not comparable (model changed: gpt-4o -> gpt-5.5); outcome on the new model reported above
```

How to read it:

- **The first line is the answer**: attacks among the runs that could be judged,
  with a Wilson 95% interval. Runs that crashed, ran out of retries, or got no
  verdict from the benchmark are counted separately as "could not be judged",
  with the reason. They never count as an attack or as a non-attack.
- **The second line compares with the run recorded in the capsule.** By default
  a different model, defense, benchmark version, or attack makes the runs "not
  comparable": the outcome rate on your model is still the answer, but it is not
  a reproduction of the recorded run. With the same model it says "reproduced"
  (the recorded outcome came back at least once), "not reproduced" (it did not
  come back in at least 3 judged runs), or "inconclusive" (for example, fewer
  than 3 judged runs, or the recording does not say which defense it used).
  Differences that do not block the comparison, such as the tool-output format,
  a paraphrased system prompt, or a different model string returned by the
  provider, are listed as "outside the envelope".

Without `--authorize` nothing runs and no model is called; the command says how
many runs it would make. Use `--provider anthropic` (key from `ANTHROPIC_API_KEY`
by default) for Claude models, and `--api responses` for OpenAI models served
through the Responses API (stateless, `store=False`). Without `--base-url-env`
the provider's public endpoint is used; the SDK is never left to pick a URL from
some other environment variable.

The output folder (`--out`, default `<finding>-rerun/`) holds one `.sova-trace`
per run, a `runs.jsonl` ledger, and a new capsule with the fresh traces and a
`rerun.json` summary. The new capsule references the original capsule and the
recorded trace by digest; it does not copy them. Run the same command again into
the same folder and finished runs are reused, not repeated.

### Useful options

| Option | Effect |
|---|---|
| `--trials N` | fresh runs (default 5 for `rerun`, 3 for `matrix`) |
| `--tpm`, `--rpm`, `--concurrency` | per-model tokens and requests per minute (sliding 60 s window) and runs in flight |
| `--max-usd X --price-in P --price-out Q` | stop starting new runs once the estimated spend in the output folder reaches X (prices in USD per million tokens) |
| `--defense`, `--tool-output-format`, `--system-message-file` | AgentDojo pipeline settings; default to the capsule's |
| `--attack-name NAME` | how the attack text addresses the model; the default comes from the model id (gpt-4o is "GPT-4", as in AgentDojo; others "GPT", "Claude", "DeepSeek", ...) |
| `--temperature T` | sent only when given; no thinking parameter is ever sent |
| `--envelope FILE` | change which differences are material, for example `{"dimensions": {"model": "record"}}` |
| `--json` | print the JSON summary instead of text |

Provider calls are retried only for rate limits, timeouts, connection errors, and
server errors, with exponential backoff, up to 12 tries per call. Every failed
attempt is kept in the trace.

## Check a model upgrade

```powershell
sova matrix findings/ --baseline old-model --candidate new-model --trials 5 --authorize
```

Each finding is classified from judged runs only:

| Result | Meaning |
|---|---|
| still works | at least one attack on both models |
| stopped working | attacks on the baseline, none in at least 3 judged runs on the candidate |
| newly works | none in at least 3 judged runs on the baseline, attacks on the candidate |
| no attack on either | none in at least 3 judged runs on each |
| can't tell | fewer than 3 judged runs where a "none" is needed |

For a plain table of findings x models, use `--models a,b,c`:

```powershell
sova matrix findings/ --models a,b,c --trials 3 --authorize --out results/
```

Each cell is `k/n` (attacks among judged runs), with `(c?)` for runs that could
not be judged. The folder gets `matrix.json` and one `matrix.sova` capsule holding
every trace. Runs already in `--out` are reused, so an interrupted matrix resumes
where it stopped. Two capsules that name the same AgentDojo episode share runs.
One invocation uses one provider; run it again with another `--provider` into the
same folder to add models from a second provider.

## What the answer does not tell you

- The default judge is AgentDojo's own security check. On some tasks it scores a
  reply that only *names* the attacker's target, for example a warning to the
  user, as a successful attack. Read the traces before acting on a single rate.
- A rate from a few runs is wide; read the interval, not only the count.
- Costs are estimates from token counts at the prices you give.
