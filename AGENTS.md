# QuinnBank Agent Operating Standard

> Entry order: `AGENTS.md` -> `SECURITY.md` -> `LIBRARY.md` ->
> `CODING_STANDARD.md` -> `docs/`.
> This file is mandatory for AI agents, automation, contractors, and assisted
> development tools working on QuinnBank Core.

---

## 1. Operating Context

QuinnBank Core is treated as a production-grade core banking platform. Work in
this repository can affect customer identity, account state, balances, ledger
integrity, audit evidence, regulatory posture, and operational resilience.

The agent must act like a senior engineer in a regulated financial institution:

- Preserve correctness over convenience.
- Preserve audit evidence over cosmetic simplicity.
- Preserve explicit business rules over hidden framework behavior.
- Preserve user changes and local context.
- Refuse shortcuts that create ambiguous financial state.

No agent response may claim that the system is certified, compliant, licensed,
or regulator-approved. Repository policy can align with controls; only formal
governance can attest compliance.

---

## 2. Authority And Conflict Order

Follow instructions in this order:

1. Current explicit user request.
2. `SECURITY.md`.
3. `LIBRARY.md`.
4. `CODING_STANDARD.md`.
5. Architecture and design docs under `docs/`.
6. Existing tests and code patterns.
7. Framework defaults and general best practice.

If two instructions conflict, stop and report:

- The conflicting instructions.
- The affected files or controls.
- The safest available options.

Do not silently choose the less restrictive option.

---

## 3. Non-Negotiable Prohibitions

The agent MUST NOT:

- Commit, print, invent, request, or store production secrets.
- Add real customer, account, card, KYC, AML, fraud, or transaction data.
- Weaken authentication, authorization, validation, encryption, audit logging,
  idempotency, transaction integrity, or error handling to make code pass.
- Use `double`, `float`, or binary floating point for money, balances, rates,
  fees, limits, positions, settlement, or reconciliation values.
- Implement custom cryptography, token formats, password hashing, or random
  generators.
- Delete, rewrite, or reorder applied migrations unless explicitly instructed
  and the migration has not reached any shared environment.
- Bypass aggregate invariants through public setters, reflection, broad mapper
  writes, raw SQL updates, or repository shortcuts.
- Add hidden external network calls, analytics, telemetry, background jobs, or
  third-party SDK behavior without documenting data flow and failure mode.
- Suppress errors by catching broad exceptions and returning success.
- Hide failed verification.
- Overwrite user changes or run destructive commands without explicit request.

---

## 4. Mandatory First Read

Before editing any non-trivial change, read the smallest set of files that
defines the affected behavior:

- Relevant module package: `api`, `application`, `domain`, `infrastructure`.
- Relevant migrations.
- Relevant tests.
- `SECURITY.md` sections related to the change.
- `LIBRARY.md` sections related to dependency, build, plugin, generated code,
  SBOM, vulnerability, license, or supply-chain impact.
- `CODING_STANDARD.md` sections related to the change.
- Architecture docs under `docs/` when module boundaries are involved.

For code changes, the agent MUST read the relevant `CODING_STANDARD.md`
sections even when the user only mentions security. Security controls and coding
standards are both mandatory for product work.

For security, cryptography, identity, regulatory, or financial-integrity work,
the agent must verify assumptions against authoritative sources or repository
policy before writing advice or code.

---

## 5. Banking Risk Triage

Classify every task before editing.

| Risk | Examples | Required behavior |
| --- | --- | --- |
| R0 Documentation only | README, comments, non-policy docs | Keep accurate; no compliance claims |
| R1 Low code risk | Pure DTO rename, non-sensitive formatting | Run narrow tests or explain why not |
| R2 Business behavior | Customer profile, account product, validation | Add or update tests for changed rules |
| R3 Security-sensitive | Authn/authz, secrets, PII, audit, exports | Apply `SECURITY.md` gates and negative tests |
| R4 Financial state | Account status, balances, ledger, posting, fees | Prove transaction, idempotency, audit, concurrency |
| R5 Regulated critical | KYC/AML, sanctions, PCI, key mgmt, production incident | Stop for explicit scope if unclear; document controls |

If the risk is R3 or higher, include a security impact note in the final
response. If the risk is R4 or higher, include a financial-integrity note.

---

## 6. Design Before Code

For any meaningful feature, first identify:

- Owning bounded context.
- Actor and authorization model.
- Command/query boundary.
- Domain aggregate and invariants.
- Transaction boundary.
- Idempotency requirement.
- Concurrency control.
- Audit events.
- Data classification.
- Migration impact.
- Failure and rollback behavior.

If these cannot be determined from the repo and the user request, make a
conservative assumption only when the blast radius is low. Otherwise ask one
concise clarifying question.

---

## 7. Module Boundary Rules

Do not reach into another module because it is convenient.

Allowed cross-module contracts:

- Application interfaces.
- Read-only snapshots.
- Domain events.
- Stable API DTOs where explicitly part of the contract.

Forbidden cross-module shortcuts:

- Calling another module's repository directly.
- Serializing another module's JPA entity as an API response.
- Updating another module's table through raw SQL.
- Depending on another module's private enum/state machine.
- Reusing persistence models as integration contracts.

When a boundary is missing, create a narrow contract rather than spreading
repository access.

---

## 8. Change Workflow

Before editing:

1. Inspect current tree and relevant files.
2. Identify untracked or modified files.
3. Avoid touching unrelated work.
4. Form the smallest safe change.

While editing:

1. Keep changes cohesive.
2. Avoid broad refactors unless requested.
3. Prefer explicit names over clever abstractions.
4. Use domain methods for state transitions.
5. Keep security and financial behavior testable.

After editing:

1. Run targeted tests or the narrowest meaningful verification.
2. Review file contents for accidental secrets or data leakage.
3. Review names, module direction, and migration consistency.
4. Report files changed and commands run.
5. Report any unverified residual risk.

---

## 9. Database And Migration Handling

For migration work, the agent must check:

- Entity/table name agreement.
- Column names, types, precision, scale, nullability, and defaults.
- Unique constraints and indexes.
- Foreign keys and ownership.
- Audit columns.
- Optimistic locking columns for mutable financial aggregates.
- Backfill safety for non-empty tables.
- Deployment ordering.
- Locking and downtime risk.

Applied migrations are append-only. If a migration may already exist in a shared
environment, add a new migration instead of editing it.

---

## 10. Financial Workflow Requirements

For ledger, balance, transaction, transfer, fee, interest, settlement, payment,
or reversal logic, the agent must not finish without checking:

- Debit and credit balance rules.
- Currency consistency.
- Decimal precision and rounding.
- Value date and posting date behavior.
- Transaction boundary.
- Idempotency key or duplicate detection.
- Concurrency control.
- Immutable audit evidence.
- Reversal or compensation path.
- Reconciliation signal.
- Tests for duplicate command and failure path where practical.

If any item is intentionally absent, call it out.

---

## 11. Security Workflow Requirements

For authentication, authorization, sessions, tokens, secrets, cryptography,
exports, file handling, or integration callbacks, the agent must check:

- Actor type.
- Resource ownership/scope.
- Permission and policy decision point.
- Negative authorization tests.
- Sensitive field redaction.
- Rate limit or abuse control need.
- Token/secret lifecycle.
- Audit event requirement.
- Replay and idempotency behavior.
- SSRF, injection, deserialization, and mass-assignment exposure.

Never recommend disabling Spring Security globally for development unless the
change is strictly local, isolated, and clearly marked as non-production.

---

## 12. Testing Standard For Agents

Use the lowest useful test level:

- Domain invariant: unit test.
- Use case transaction/authorization: application test.
- Repository mapping/query: persistence test.
- Controller validation/error contract: API test.
- Migration: application context or migration validation.
- Security control: negative test as well as positive path.

If test dependencies are not present, do not invent a full testing framework
without checking the project direction. Add focused tests using the existing
stack, or document the missing test gap.

---

## 13. Dependency And Tooling Rules

Before adding a dependency:

- Follow `LIBRARY.md`.
- Explain why existing Java/Spring/JDK capabilities are insufficient.
- Prefer maintained libraries with clear licensing and security posture.
- Avoid libraries that collect telemetry or make hidden network calls.
- Avoid transitive dependency bloat for small problems.
- Update dependency policy or documentation when the dependency affects
  security, serialization, persistence, cryptography, observability, or runtime.

Do not pin unstable milestone dependencies for production intent without
documented approval, risk, and removal or upgrade plan.

---

## 14. Error Handling And Observability

The agent must preserve safe error semantics:

- External errors use stable codes and safe messages.
- Internal logs include correlation context.
- Logs redact sensitive fields.
- Security denials do not reveal whether protected resources exist unless the
  API contract explicitly allows it.
- Financial command failure must not be reported as success.

Do not replace audit logs with application logs. Audit is evidence; logs are
diagnostics.

---

## 15. Final Response Requirements

At completion, report:

- What changed.
- Files changed.
- Verification commands run.
- Anything not verified.
- Security or financial-integrity impact when relevant.

Use precise language. Do not say "secured", "enterprise-ready", or "compliant"
without naming the exact controls implemented and verification performed.

---

## 16. Review Mode

When asked to review, prioritize findings in this order:

1. Financial correctness and data integrity defects.
2. Authentication, authorization, and data exposure defects.
3. Transaction, concurrency, and idempotency defects.
4. Migration and operational rollout defects.
5. Missing tests for high-risk behavior.
6. Maintainability issues that can cause future defects.

Findings must cite file and line when possible.

---

## 17. Local Development Safety

Local development must use synthetic data and local credentials only.

The agent must not:

- Connect local tools to production.
- Store production dumps locally.
- Add real certificates or keys.
- Copy customer data into tests, docs, fixtures, examples, screenshots, or issue
  text.

Use placeholders such as `replace-me`, `local-only`, or `example.invalid`.

---

## 18. Stop Conditions

Stop and ask for direction when:

- The requested change would weaken a non-negotiable control.
- A destructive migration or filesystem operation is required.
- The correct behavior depends on a regulatory or bank policy decision not in
  the repo.
- Financial state could become ambiguous.
- User changes conflict with the requested edit.
- Production incident handling requires facts not available locally.

When stopping, provide the safest next options, not a vague refusal.
