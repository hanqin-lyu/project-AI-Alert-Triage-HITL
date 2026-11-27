# AI-Assisted Alert Triage with Human-in-the-Loop

An AI triage layer on Microsoft Sentinel that cuts alert fatigue without giving the
AI any power to act. When an incident is created, a Logic App gathers its context with
KQL, Azure OpenAI returns a structured triage with cited evidence, and deterministic
routing sends the incident either to approval-gated execution or straight to an analyst.
The analyst always makes the final call.

Status: planning. Nothing is built yet.

> All data comes from my own labs: the honeypot incidents from
> [project-Sentinel-SOC](https://github.com/hanqin-lyu/project-Sentinel-SOC) and the
> Defender for Endpoint alerts from
> [project-Endpoint-IR-Lab](https://github.com/hanqin-lyu/project-Endpoint-IR-Lab).
> No customer data.

## The question

Not "can I plug AI into a SOC", but: **can the AI's conclusions be trusted, where are
they wrong, and can an attacker use them?**

## Design principles

- **The AI never acts on its own.** There are 2 modes only: human approval then
  execution, or full human triage. There is no autonomous mode.
- **Routing is code, not the model.** 4 signals – model confidence, policy exceptions,
  ambiguity and asset impact – are computed deterministically; thresholds are versioned
  in Git.
- **Two separate identities.** The triage identity can read data and write comments,
  nothing else. The execution playbook has its own identity, limited to one reversible
  action: isolating a device in Defender for Endpoint.
- **No automatic closing.** A wrongly closed true positive is a silent miss, attacker-
  controlled alert fields can inflate the model's confidence, and a lab-sized test set
  cannot prove a low miss rate (0 misses in 10 true positives still leaves an upper
  bound of about 30% at 95% confidence).

## What gets measured

- Accuracy against a ground-truth set I labelled before the AI ever ran (committed first),
  with missed true positives reported on their own
- Coverage, routing errors, confidence calibration and run-to-run consistency
- Fabricated evidence, checked automatically against the input
- Triage time and queue ranking, with and without the AI
- Indirect prompt injection planted in alert fields, as a matrix of location, technique
  and goal, before and after the guardrails

## Deliverables

- The pipeline, deployed with Terraform through GitHub Actions OIDC
- The labelled ground-truth set, context snapshots and evaluation scripts
- An evaluation report and a postmortem in 7 sections
- A one-page note on what the AI can and cannot do in this workflow, and why the final
  decision stays with a person

## Plan

The full working plan (in Chinese) is in [docs/plan.md](docs/plan.md).
