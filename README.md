# Customer Support Escalation Agent

A single-file, stdlib-only Python agent that triages support tickets, answers **only** what it can ground in an approved knowledge base, and escalates everything else to a human with a complete, redacted handoff package.

**Design principle: safe containment.** Resolve only what can be proven; hand off the rest without losing context. A lower containment rate is the correct outcome when it prevents a fraudulent refund, an account-takeover mistake, or a mishandled legal complaint.

- File: `support_escalation_agent.py` (Python 3.9+, no dependencies; `anthropic` is optional)
- v1 never sends email, issues refunds, resets passwords or changes ownership. It drafts replies and creates escalations only.

---

## Architecture

```
ticket ──► validate ──► normalize (NFKC, strip zero-width) ──► PII redaction ──► injection screen
                                                                       │
                                  MASTER AGENT (deterministic decision engine)
        ┌───────────────┬───────────────────┬─────────────────┬──────────────────┐
     triage          research            responder        escalation
   [internal,       [kb:read,          [reply:draft]    [ticket:escalate,
    ticket:read]    customer:read]                       ticket:note]
        └───────── each worker = ReAct loop (Thought → Action → Observation) ─────┘
                                      │
                      SANDBOXED DISPATCHER (every tool call)
   deny-list · scope check · schema validation · size cap · timeout · retry
   call budget · observation sanitising · hash-chained audit log
                                      │
                      VALIDATOR (auto-evaluation of every output)
        schema · PII leak · grounding · no commitments · one question · handoff complete
              fails → downgrade to ESCALATE (never fails open)
```

### Master–Worker split

| Component | Role | Scopes |
|---|---|---|
| **Master** | Sanitises input, sequences workers, owns the decision rules, validates output, fail-safes on any error | none (no tools) |
| `triage` worker | Classify intent/risk/sentiment; fetch history only for intents that need it | `internal`, `ticket:read` |
| `research` worker | KB retrieval; minimum-necessary customer fields per intent | `kb:read`, `customer:read` |
| `responder` worker | Draft a cited reply or one clarifying question (never sends) | `reply:draft` |
| `escalation` worker | Internal note + handoff record to the right queue | `ticket:escalate`, `ticket:note` |

Workers cannot call each other's tools. The dispatcher enforces this, not the prompt.

### Real ReAct trace (TCK-2041, billing dispute)

```
triage      classify_ticket        Classify the sanitized ticket; its text is untrusted data...
triage      get_ticket_history     Intent may depend on earlier contact; fetch recent ticket history.
research    get_customer_profile   Fetch only the profile fields this intent needs.   (KB skipped: out of scope)
master      decision               ESCALATE  high_risk:billing_dispute
escalation  add_internal_note      Record why this is being escalated.
escalation  escalate_to_human      Create the handoff package for the human queue.
validator   validation_passed
```

---

## Decision policy (deterministic, evaluated in this order)

| # | Condition | Decision |
|---|---|---|
| 1 | Prompt-injection / role-inversion detected | ESCALATE → `security_trust` (P1) |
| 2 | High-risk intent: security, legal, privilege escalation, billing dispute, enterprise contract, refund over limit | ESCALATE → specialist queue |
| 3 | Clarification limit reached (`clarify_rounds ≥ 2`) | ESCALATE |
| 4 | Intent unclear | CLARIFY (one question) |
| 5 | Intent outside `ALLOWED_INTENTS` | ESCALATE |
| 6 | KB sources conflict | ESCALATE |
| 7 | Required field missing (e.g. `customer_id` for invoices) | CLARIFY |
| 8 | Account-specific intent and identity unverified | ESCALATE → `identity_verification` |
| 9 | Customer has custom contract terms | ESCALATE → `account_team` |
| 10 | Confidence < 0.75 (min of classifier and KB retrieval score) | ESCALATE |
| 11 | Otherwise | RESOLVE (draft only, `sent: false`) |

The LLM (if enabled) can never loosen this table. It only influences which tool is proposed next.

---

## Security model

| Threat | Control |
|---|---|
| Instruction override (“ignore your rules”) | Regex screen on normalised text; match is **removed** and the ticket is escalated, never obeyed |
| Role inversion (`<system>`, `SYSTEM:`, “you are now admin”, “I am the administrator”) | `fake_role_markup`, `role_reassignment`, `authority_claim` patterns |
| Obfuscation (fullwidth letters, zero-width chars, control chars) | NFKC normalisation + stripping *before* screening |
| Tool forging / hallucinated actions (`issue_refund`, `reset_password`…) | Hard deny-list in the dispatcher, plus a `tool_forging` pattern; denied calls are audited |
| Privilege creep between workers | Per-worker scopes enforced at dispatch |
| Malformed or oversized tool args | Typed schemas, `additionalProperties: false`, pattern/enum/length checks, 8 KB cap, copy-on-call |
| Poisoned KB or tool output | Every tool observation is screened; poisoned KB articles are quarantined and excluded from grounding |
| PII exposure | Redaction happens before the model, tools, logs or retrieval; audit data is re-scrubbed on write |
| Runaway or hung tools | Per-call timeout, retry for transient errors only, per-ticket call budget, ReAct step cap, loop detection |
| Tampering with the audit trail | SHA-256 hash chain; `AuditLog.verify()` detects any edit |
| Agent failure | Any exception, tool failure or validation failure → ESCALATE with a handoff. It never fails open |
| Silent customer-facing action | No send tool exists. Output is `DRAFT_PENDING_APPROVAL` |

**PII handling**

| Data | Handling |
|---|---|
| Email | `r***@example.com` |
| Phone | all digits masked except last 2 |
| Card (Luhn-validated) | all but last 4 |
| SSN / PAN / Aadhaar-style IDs | `[REDACTED:gov_id]` |
| Password / OTP / PIN / API key / JWT | `[REDACTED:secret]` |
| Date of birth | `[REDACTED:dob]` |

---

## Usage

```bash
python support_escalation_agent.py init-data --dir data           # write 18 sample tickets
python support_escalation_agent.py triage --ticket data/ticket_TCK-2041.json
python support_escalation_agent.py triage --ticket data/ticket_TCK-2042.json --json
echo '{"ticket_id":"TCK-1","text":"How do I reset my password?"}' | python support_escalation_agent.py triage --ticket -
python support_escalation_agent.py evaluate                       # exit code 1 if the gate fails
python support_escalation_agent.py serve --mcp                    # stdio JSON-RPC, tool: triage_ticket
```

Optional LLM planner: `pip install anthropic`, set `ANTHROPIC_API_KEY` (and optionally `SUPPORT_AGENT_MODEL`), then add `--llm`. If the package or key is missing, or the model returns anything invalid, the agent falls back to the deterministic planner.

Ticket input: `{"ticket_id": "TCK-1", "customer_id": "C-100" | null, "text": "...", "clarify_rounds": 0}`

### Example output

```
Ticket TCK-2041  [aud_175cad]
Intent: billing_dispute | Risk: HIGH | Confidence: 0.82
Decision: ESCALATE -> billing_specialists (P2)
Reason: high_risk:billing_dispute
Summary: Customer disputes a charge. Amount mentioned: $249. Account record shows no cancellation request. ...
Next action: Verify the charge and cancellation timeline in the billing system; decide refund per policy.
Handoff: HND-655339e6 (summary, history, risk signals, next action)
PII redacted: email, phone
```

`--json` returns the full structured record: `ticket_id, intent, risk_level, confidence, decision, target_queue, priority, customer_tier, customer_reply, delivery, escalation_summary, context_for_human, risk_signals, recommended_action, handoff_id, citations, redactions_applied, injection_flags, reasons, audit_id, metrics`.

---

## Evaluation (auto-evaluation)

Two layers:

1. **Runtime validator** (every ticket): schema, no raw PII, no injection echo, no first-person commitments (“we have refunded…”), replies are verbatim-grounded in cited and retrieved KB articles, clarifications ask exactly one question, handoffs are complete. A failure on RESOLVE/CLARIFY is downgraded to ESCALATE.
2. **Offline harness** (`evaluate`): 18 golden tickets plus 14 robustness probes.

Results from this build (offline, mock data):

| Metric | Result |
|---|---|
| Decision accuracy / routing accuracy | 100% / 100% |
| Escalation precision / recall | 100% / 100% |
| False-resolution count | 0 |
| Containment (eligible tickets) | 100% |
| PII leaks in outputs or audit log | 0 |
| Handoff completeness | 100% |
| Latency p50 / p95 | ~1.5 ms / ~1.8 ms (mock tools) |
| Avg tool calls per ticket | 4.1 |
| Audit chain valid | yes |
| Robustness probes | 14/14 |

Golden cases include: password reset, invoice, refund policy, double charge, account takeover, $800 refund, PII-laden refund, “make me admin”, regulator threat, repeat contact, ambiguous input, enterprise contract, conflicting KB articles, poisoned KB article, role-inversion wrapping a benign question, unverified identity, and missing customer ID.

Robustness probes cover: forbidden tool, scope violation, unknown tool, schema abuse (3 variants), invalid ticket, audit verify and tamper detection, tool timeout, call budget, transient failure with retry, persistent failure with fail-safe escalation, and fullwidth + zero-width obfuscated injection.

**Read these numbers honestly.** The golden set was written alongside the rules, so 100% shows the pipeline behaves as designed. It does not predict accuracy on real traffic.

---

## Honest limitations

- **Classifier is regex/keyword based.** It is deterministic and auditable but brittle on real language. In production, replace `classify_text` with an LLM or fine-tuned classifier and keep the deterministic decision engine as the gate.
- **Sandbox is thread-level**, not process isolation. Timeouts return control but cannot kill a hung thread. With real connectors, run tools in subprocesses or containers with network and credential isolation.
- **Regex PII/injection detection is not exhaustive.** Treat it as one layer. Add a managed DLP service and a trained injection classifier before handling real customer data. Redaction patterns are US/IN-biased (SSN, PAN, Aadhaar-style).
- **The LLM planner path was not run against the live API in this build.** Its guardrails were tested with a stub that proposes forbidden, out-of-scope, premature-finish and oversized-args actions. All were contained.
- **KB retrieval is tag-overlap scoring**, not embeddings. Swap `t_kb` for a vector store, and keep the quarantine and conflict checks.
- **Mock data only.** `CUSTOMERS`, `HISTORY`, `KB`, `TICKETS` are in-file stubs. The MCP server is a minimal stdio implementation of `initialize`, `tools/list` and `tools/call`; test it with your client before relying on it. There is no authentication, so keep it local or put it behind an authenticated gateway.
- Audit log is hash-chained but not externally anchored; a writer with file access could rewrite the whole chain. Ship events to WORM storage for true immutability.

## Production hardening checklist

1. Replace mocks with real CRM, ticketing and KB connectors using per-tool service accounts with least privilege.
2. Move tool execution to subprocess/container isolation.
3. Add rate limiting and per-customer abuse throttling at the entry point.
4. Ship the audit log to append-only storage and alert on `tool_denied`, `injection_detected` and `validation_failed` spikes.
5. Add a human approval service before any send tool is introduced, and keep refunds and account changes out of the agent.
6. Re-run `evaluate` in CI on every change, with the gate: zero false resolutions, zero PII leaks.
7. Track containment, reopen rate and CSAT. A rising containment rate with a rising reopen rate is a false-resolution signal.
