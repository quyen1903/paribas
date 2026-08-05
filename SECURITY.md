# QuinnBank Core Security Standard

> Entry order: `AGENTS.md` -> this file -> `LIBRARY.md` ->
> `CODING_STANDARD.md` -> `docs/`.
> This file overrides ordinary coding preference whenever security or financial
> integrity is involved.

---

## 1. Purpose And Security Model

QuinnBank Core is treated as a real banking platform. The system must protect
customer trust, regulated data, account state, ledger integrity, operational
resilience, and audit evidence.

Security is not a release checklist at the end. It is part of feature design,
domain modeling, code review, testing, deployment, monitoring, and incident
response.

This document does not claim legal compliance or regulator approval. It defines
engineering controls that support formal security governance.

---

## 2. Control Baseline

The security program SHOULD align to:

- OWASP ASVS 5.0.0 for application security verification.
- NIST Cybersecurity Framework 2.0 for risk governance outcomes.
- NIST SP 800-63-4 for digital identity and authenticator lifecycle guidance.
- NIST SP 800-218 SSDF 1.1 for secure software development practices.
- PCI DSS v4.0.1 when cardholder data is stored, processed, or transmitted.
- FFIEC Authentication and Access guidance for financial institution systems.
- FFIEC Architecture, Infrastructure, and Operations guidance.
- FFIEC Development, Acquisition, and Maintenance guidance.

Internal bank policy, applicable law, regulator expectations, contractual
requirements, and risk committee decisions take precedence when stricter.

---

## 3. Highest-Risk Areas

The following areas are treated as high-risk by default:

- Customer identity, CIF, profile, contact, KYC, AML, sanctions, fraud, and risk
  decisions.
- Authentication, MFA, sessions, service identities, API keys, and privileged
  access.
- Authorization across customer, account, branch, tenant, role, permission,
  channel, and maker-checker state.
- Account opening, account blocking, account closure, limits, overdraft, fees,
  interest, and product eligibility.
- Ledger posting, balance update, transfer, payment, reversal, refund,
  settlement, reconciliation, and end-of-day processing.
- Webhooks, batch imports, payment rails, card integrations, external provider
  callbacks, and message consumers.
- Admin/back-office actions over customer, account, transaction, KYC, AML,
  sanctions, fraud, or security data.
- Data export, report generation, file upload/download, object storage, and
  support tooling.
- Secrets, keys, certificates, signing material, encryption material, and
  production configuration.
- Audit logs and security monitoring evidence.

Any change in these areas requires explicit security review.

---

## 4. Data Classification

Default assumption: data is confidential unless product requirements explicitly
classify it as public.

| Class | Examples | Handling |
| --- | --- | --- |
| Public | Published status page, public API docs, public product descriptions | Safe to expose intentionally |
| Internal | Non-sensitive runbooks, synthetic test data, internal architecture diagrams | Access limited to workforce and approved vendors |
| Customer confidential | CIF number, name, email, phone, address, customer profile, device metadata, IP address | Customer/role scoped, redacted in logs |
| Financial confidential | Account number, balances, limits, fees, interest, transaction history, statements | Strict scope, audit access where appropriate |
| Restricted identity | KYC documents, identity numbers, AML/sanctions results, fraud signals, risk scores | Need-to-know, audited, encrypted, retention controlled |
| Cardholder data | PAN, cardholder name, expiry, service code, SAD such as CVV/PIN/track data | PCI scoped; do not store SAD; minimize and tokenize |
| Authentication secret | Password hashes, refresh tokens, reset tokens, OTP/MFA secrets, session ids, signing keys | Never log; protect with approved hashing/encryption/secret manager |
| Integration secret | API keys, OAuth tokens, webhook secrets, provider credentials, mTLS keys | Secret manager only; rotate and audit |
| Audit/security evidence | Security events, privileged action logs, investigation notes | Tamper-evident, access controlled, retention governed |
| Operational telemetry | Logs, metrics, traces, request ids, job results | Redact sensitive fields; preserve investigation value |

Restricted and financial confidential data MUST NOT be used in tests, examples,
screenshots, issue text, local databases, or documentation unless synthetic or
formally de-identified.

---

## 5. Trust Boundaries

```text
Internet / mobile / browser / partner
  -> CDN, WAF, DDoS, reverse proxy
  -> API gateway / application edge
  -> QuinnBank Core modules
  -> Database, cache, queue, object storage, audit store
  -> KMS/HSM/secret manager
  -> External systems: payment rails, card processor, AML/KYC, SMS/email,
     credit bureau, fraud engine, identity provider, observability platform
  -> Operators and back-office tools
```

Rules:

- Browser and mobile clients are untrusted.
- Partner systems are untrusted until authenticated, authorized, and validated.
- Client-supplied identity, role, permission, branch, customer id, account id,
  amount, fee, balance, currency, payment status, and risk status are untrusted.
- Queue messages are untrusted until schema, source, signature where applicable,
  and idempotency are verified.
- Webhooks are untrusted until provider-specific signatures and replay controls
  pass.
- File uploads and imports are untrusted even from authenticated employees.
- Admin tools are high-risk entry points, not trusted backdoors.
- Internal network location does not replace authentication or authorization.

---

## 6. Authentication

All non-public endpoints MUST require authentication.

Actor types must be explicit:

- Retail customer.
- Business customer.
- Bank employee.
- Back-office operator.
- System/service account.
- Third-party partner.
- Batch job.

Requirements:

- MFA is mandatory for employee, administrator, back-office, production, and
  high-risk customer actions.
- Customer MFA or step-up authentication SHOULD be required for high-risk
  transfers, beneficiary changes, device binding, credential reset, profile
  changes, and unusual risk signals.
- Service-to-service authentication MUST use approved service identity, such as
  mTLS, signed token, workload identity, or equivalent bank-approved control.
- Passwords, if used, MUST be hashed with an approved adaptive password hashing
  algorithm and unique salts.
- Password reset, device enrollment, MFA reset, and account recovery MUST be
  treated as authentication flows and audited.
- Session and token lifetimes MUST be bounded, revocable, and risk-based.
- Refresh tokens MUST be stored server-side or otherwise revocable.
- Token validation MUST check signature, issuer, audience, subject, expiration,
  not-before where present, token type, and required claims.
- Authentication failures MUST be rate-limited and monitored.

Never infer admin status from email address, route path, environment, or local
development convenience.

---

## 7. Authorization And Resource Isolation

Authorization must answer:

1. Who is the actor?
2. What action is requested?
3. Which resource is targeted?
4. Is the resource inside the actor's allowed scope?
5. Does context require step-up, maker-checker, or denial?

Decision tree:

```text
Is the route public?
  |
  +-- yes -> validate input, rate-limit where relevant, return only public data
  |
  +-- no -> authenticated?
        |
        +-- no -> 401
        |
        +-- yes -> actor allowed action?
              |
              +-- no -> 403
              |
              +-- yes -> resource in actor scope?
                    |
                    +-- no -> 403 or contract-safe 404
                    |
                    +-- yes -> context requires step-up or approval?
                          |
                          +-- yes -> challenge or pending approval
                          |
                          +-- no -> allow
```

Scope rules:

- Customer-facing reads MUST be scoped to the authenticated customer
  relationship.
- Account operations MUST verify account ownership, role, mandate, signatory
  rights, account status, and transaction eligibility.
- Employee access MUST be scoped by role, branch, portfolio, function, and
  need-to-know.
- Back-office privileged actions MUST be audited and SHOULD use maker-checker.
- Support tooling MUST not grant mutation through broad read roles.
- Service accounts MUST be scoped to specific use cases and data domains.
- Batch jobs MUST have explicit identities and least privilege.

Bad:

```java
accountRepository.findById(accountId);
```

Good:

```java
accountRepository.findVisibleAccount(accountId, actor.customerId(), actor.allowedScopes());
```

Authorization MUST be enforced before sensitive reads and before mutations.

---

## 8. Maker-Checker And Segregation Of Duties

High-risk actions SHOULD require dual control.

Examples:

- Manual ledger adjustment.
- Large transfer approval.
- Customer block/unblock.
- Account closure.
- Limit or overdraft change.
- Fee waiver above threshold.
- KYC override.
- Sanctions/fraud override.
- Role or entitlement change.
- Secret, certificate, or key rotation in production.
- Production data export.

Rules:

- Maker and checker MUST be different actors.
- Checker MUST have explicit authority for the action.
- Approval decision MUST be audited.
- Pending requests MUST be immutable except for cancellation or superseding
  workflow.
- Rejected requests MUST not mutate target financial state.

---

## 9. API Boundary And Abuse Controls

API boundary responsibilities:

- Public route allowlist.
- Authentication resolution.
- Authorization policy invocation.
- Request id and correlation id.
- Request body size limits.
- File size limits.
- Rate limiting and abuse detection.
- Safe error responses.
- Structured access logging with redaction.
- Security headers where applicable.

Rate limit or abuse-protect:

- Login, MFA, registration, password reset, token refresh.
- Customer lookup and account lookup.
- Transfers, payments, beneficiary management, and card operations.
- OTP, email, SMS, and notification triggers.
- File upload, import, export, report generation.
- Search endpoints and high-cost filters.
- Webhook receivers and partner APIs.

Client-supplied identity headers MUST be ignored unless they are produced by a
trusted and authenticated gateway under a documented contract.

---

## 10. Input Validation

Validate all external input:

- Body.
- Query.
- Path params.
- Headers.
- Cookies.
- File metadata and content.
- Queue messages.
- Webhook payloads.
- Batch import files.
- External provider responses.
- Search, filter, sort, and pagination parameters.

Banking-specific validation:

- Amount must be positive where required and within configured limits.
- Currency must be supported and consistent with account/product rules.
- Account status must permit the operation.
- Customer status and KYC status must permit the operation.
- Product eligibility must be checked server-side.
- Transaction date, value date, and cutoff behavior must be explicit.
- Beneficiary, routing, bank code, and account identifiers must be validated.
- Fees, interest, exchange rates, discounts, waivers, and tax values must be
  calculated or verified server-side.
- Risk, fraud, sanctions, and AML decisions from clients are untrusted.

Validation errors MUST use stable codes and MUST NOT reveal internals.

---

## 11. Financial Integrity Controls

Financial state changes MUST be designed for correctness, replay safety, and
auditability.

Mandatory controls:

- Transaction boundary at use-case level.
- Idempotency for externally retried commands.
- Duplicate detection for provider events and batch records.
- Optimistic lock, pessimistic lock, atomic update, or equivalent concurrency
  control.
- Explicit state machine for financial commands.
- Immutable audit or ledger evidence.
- Deterministic failure behavior.
- Reversal or compensation path.
- Reconciliation signal.

Do not trust client-provided:

- Balance.
- Fee.
- Interest.
- Exchange rate.
- Discount.
- Tax.
- Payment success.
- Settlement status.
- Available limit.
- Risk decision.

---

## 12. Ledger, Balance, And Posting Security

Ledger is security-critical.

Rules:

- Ledger entries SHOULD be immutable.
- Corrections SHOULD use reversals or explicit adjustment entries.
- Every journal entry MUST identify source command, actor/system, reason,
  amount, currency, debit, credit, posting date, value date, and correlation id.
- Debits and credits MUST balance by currency.
- Balance projections MUST reconcile to ledger entries.
- Manual adjustments MUST require reason, maker-checker where applicable, and
  audit evidence.
- Posting idempotency keys MUST be unique.
- Reversal MUST not double-credit or double-debit under retry.
- End-of-day and reconciliation jobs MUST be repeatable or safely restartable.

Alert on:

- Unbalanced journal attempt.
- Ledger posting failure.
- Balance/ledger mismatch.
- Duplicate provider event beyond expected retries.
- Manual adjustment volume anomaly.
- Reconciliation exception.

---

## 13. KYC, AML, Sanctions, And Fraud Controls

KYC/AML/fraud data is restricted identity data.

Rules:

- KYC document access MUST be need-to-know and audited.
- KYC status changes MUST be explicit state transitions.
- Sanctions and AML decisions MUST record source, rule/model version where
  applicable, decision, timestamp, actor/system, and reason.
- Overrides MUST require privileged authorization and audit evidence.
- Fraud signals MUST not be exposed to customers or unprivileged staff.
- High-risk customer or transaction status MUST gate account opening and
  financial operations.
- Batch screening results MUST be idempotent and traceable to input batch.

Do not log raw identity documents, full identity numbers, sanctions match
details, fraud model features, or adverse action internals unless explicitly
approved and protected.

---

## 14. Cards And PCI Scope

If cardholder data enters the system:

- PCI DSS v4.0.1 scoping MUST be completed before design approval.
- Sensitive authentication data such as CVV, PIN, PIN block, and track data MUST
  NOT be stored after authorization.
- PAN MUST be minimized, masked, encrypted or tokenized according to approved
  PCI design.
- Card data environments MUST be segmented from non-card environments.
- Logs, traces, metrics, and audit records MUST not contain full PAN or SAD.
- Test data MUST use approved test card numbers only.

Avoid bringing QuinnBank Core into PCI scope unless the architecture explicitly
requires it.

---

## 15. Secrets And Key Management

Secrets belong in approved secret management, not source code.

Must redact:

- `Authorization`.
- `Cookie` and `Set-Cookie`.
- API keys.
- JWTs and refresh tokens.
- Passwords and password hashes.
- Password reset tokens.
- OTP and MFA secrets.
- Private keys.
- Webhook secrets.
- OAuth tokens.
- Database URLs with passwords.
- Object storage credentials.
- Email/SMS provider credentials.
- Payment provider credentials.
- mTLS private keys and keystores.

Key management rules:

- Production keys MUST be owned, inventoried, access controlled, and rotated.
- Key rotation MUST be supported without code changes.
- Cryptographic keys MUST be stored separately from encrypted data.
- HSM or KMS SHOULD be used for high-value signing and encryption keys.
- Key compromise MUST have a documented containment and rotation procedure.
- Local development MUST use local-only throwaway secrets.

---

## 16. Cryptography

Rules:

- Use approved platform libraries only.
- Do not implement custom encryption, hashing, signing, token, random, or key
  agreement logic.
- TLS MUST be enforced for non-local network traffic.
- Service-to-service traffic SHOULD use mTLS or equivalent workload identity
  where appropriate.
- Passwords MUST use approved adaptive hashing.
- Tokens MUST use approved signing algorithms and key lifecycle controls.
- Random values for security MUST use cryptographically secure randomness.
- Encryption at rest MUST follow data classification and key management policy.

Do not select algorithms based on online snippets. Use bank-approved crypto
standards or a security architecture decision.

---

## 17. File Upload, Download, Import, And Export

Files are untrusted.

Upload/import rules:

- Enforce route-specific size limits.
- Validate MIME type and content, not only extension.
- Sanitize filenames.
- Store outside the web root.
- Use private object storage by default.
- Scan for malware where available.
- Parse CSV/Excel defensively.
- Validate every row before mutation.
- Make batch imports idempotent.
- Produce safe error reports that do not leak other customers' data.

Download/export rules:

- Require authorization for the target dataset.
- Audit bulk exports and sensitive document downloads.
- Mask sensitive values where full values are not required.
- Encrypt exports at rest and in transit.
- Expire export links.
- Rate-limit and monitor high-volume exports.

---

## 18. Webhooks, Callbacks, SSRF, And External Calls

Inbound webhooks:

- Verify provider-specific signature using raw payload.
- Validate timestamp or nonce where supported.
- Store provider event id for replay detection.
- Process idempotently.
- Reject oversized payloads.
- Use safe errors and avoid leaking verification details.

Outbound callbacks or partner webhooks:

- HTTPS required in production.
- Block loopback, private, link-local, multicast, and metadata service IP ranges.
- Re-check DNS and redirects where practical.
- Set short timeouts.
- Limit retries and use backoff.
- Sign payloads.
- Do not send secrets or unnecessary PII.

External calls:

- Use allowlisted destinations for high-risk integrations.
- Use timeouts and circuit breakers where operationally required.
- Do not make non-idempotent external calls inside database transactions unless
  the failure mode is designed and documented.

---

## 19. Audit Logging

Audit is evidence, not debug output.

Audit these events:

- Login, logout, MFA challenge, MFA reset, password reset, credential change.
- Authentication failure patterns where security-relevant.
- Authorization denial for sensitive resources.
- Role, permission, entitlement, branch, and service account changes.
- Customer creation, status change, profile high-risk change.
- KYC status change, AML/sanctions/fraud decision and override.
- Account opening, status change, block, unblock, close, reopen.
- Limit, fee, interest, product eligibility, and overdraft changes.
- Transfer/payment command acceptance, rejection, posting, reversal, refund.
- Manual ledger adjustment.
- Data export, report generation, bulk read, document download.
- Secret, certificate, key, webhook, integration, and security policy changes.
- Production deployment and emergency change where integrated.

Audit fields:

- Event id.
- Timestamp in UTC.
- Actor type and actor id.
- Authentication method or service identity where relevant.
- Action.
- Entity type and entity id.
- Customer/account scope where safe.
- Decision and reason code.
- Old/new values when safe and required.
- Request/correlation id.
- Source IP/device/channel where relevant.
- Approval id for maker-checker.

Audit records MUST be protected against unauthorized modification and deletion.

---

## 20. Logging And Monitoring

Application logs MUST be safe by default.

Do not log:

- Passwords, tokens, API keys, session ids, cookies, private keys.
- CVV, PIN, PIN block, track data, or full PAN.
- Full account numbers unless explicitly approved and masked.
- Full request/response bodies for financial or identity endpoints.
- KYC document content.
- Fraud model features or sensitive AML match details.

Security alerts SHOULD cover:

- Spike in 401, 403, or 429.
- Repeated login, MFA, password reset, token refresh, or OTP failures.
- Cross-customer or cross-account access attempts.
- Privilege escalation or role change.
- Admin access anomaly.
- Export volume anomaly.
- Failed webhook signature validation.
- Duplicate provider events outside normal retry profile.
- Ledger posting failures.
- Balance/ledger mismatch.
- Reconciliation exceptions.
- Secret scanning alerts.
- Critical dependency or container vulnerabilities.

Operational metrics SHOULD include latency, error rate, saturation, queue depth,
outbox lag, database lock conflicts, duplicate command rate, and business
command outcomes.

---

## 21. Privacy And Data Minimization

Rules:

- Collect only data needed for a defined business, regulatory, fraud, security,
  or operational purpose.
- Do not expose more data than the actor needs.
- Retain data according to approved schedules.
- Use synthetic or formally de-identified data outside production.
- Production data MUST NOT be copied into local development.
- Customer data rights, legal hold, retention, deletion, and disclosure workflows
  MUST be handled through approved governance.
- Analytics and reporting SHOULD use aggregated or minimized data unless
  detailed data is explicitly authorized.

---

## 22. Dependency And Supply Chain Security

Dependency and library governance is defined in `LIBRARY.md`. This section sets
the minimum security bar.

Rules:

- Dependencies MUST come from approved repositories.
- Critical tooling and runtime dependencies SHOULD be pinned or centrally
  managed.
- Dependency changes MUST be reviewed for maintenance, license, vulnerability,
  transitive dependency, and data-flow impact.
- CI MUST run vulnerability scanning when configured by the project.
- Build scripts MUST NOT download and execute unreviewed code.
- Gradle wrapper updates MUST be reviewed.
- Container base images MUST be minimal and patched.
- Third-party SDKs MUST document network destinations, telemetry, data
  collection, retry behavior, and failure mode.

Do not add a dependency for a small task that the JDK, Spring, or existing
project stack can safely handle.

---

## 23. CI/CD And Release Controls

Minimum release controls:

- Protected branches.
- Required review.
- Required automated tests.
- Secret scanning.
- Dependency/container scanning where configured.
- Build provenance or attributable build logs.
- Migration review for database changes.
- Security review for high-risk changes.
- Change record for production deployment.
- Rollback or roll-forward plan.
- Monitoring plan for high-risk releases.

CI logs MUST mask secrets. Release artifacts MUST not contain local config,
secrets, database dumps, or production customer data.

---

## 24. Infrastructure And Runtime

Rules:

- Services run with least privilege.
- Network access is deny-by-default where practical.
- Admin interfaces are not publicly exposed.
- Database access uses dedicated service identities.
- Production config is externalized and access controlled.
- Backups are encrypted, access controlled, and restore tested.
- Health endpoints do not expose sensitive internals.
- Debug endpoints are disabled or protected in production.
- Object storage defaults to private.
- Observability exporters do not leak sensitive payloads.

---

## 25. Secure Development Gates

Security review is mandatory for changes involving:

- Authentication, MFA, sessions, tokens, cookies, password reset.
- Authorization, roles, permissions, entitlements, object ownership.
- Customer PII, CIF, KYC, AML, sanctions, fraud, risk.
- Account, balance, ledger, transfer, payment, card, loan, fee, interest.
- Cryptography, secrets, keys, certificates, TLS.
- File upload/download, imports, exports, reports.
- Webhooks, callbacks, external integrations, partner APIs, message consumers.
- Database schema involving sensitive or financial data.
- CI/CD, container, infrastructure, runtime config.
- Logging, audit, monitoring, or incident response.

Required security review output:

- Threats considered.
- Controls implemented.
- Negative tests added or justified.
- Residual risk.
- Monitoring or audit impact.

---

## 26. Release Security Checklist

- [ ] Public routes are explicitly allowlisted.
- [ ] Non-public routes require authentication.
- [ ] Authorization checks include actor, action, resource, and scope.
- [ ] Customer/account access is scoped server-side.
- [ ] Privileged operations are audited.
- [ ] Maker-checker exists for high-risk operations where required.
- [ ] Inputs are validated for body, query, params, headers, files, and messages.
- [ ] Sensitive fields are redacted from logs, errors, traces, and metrics.
- [ ] Financial commands are transactional.
- [ ] Retriable financial commands are idempotent.
- [ ] Concurrency control prevents lost updates.
- [ ] Ledger postings are balanced and immutable by design.
- [ ] Reversal and compensation behavior is defined.
- [ ] KYC/AML/fraud gates are enforced where relevant.
- [ ] Webhooks verify signatures and replay controls.
- [ ] File uploads/imports are validated and safe.
- [ ] Exports are authorized, audited, and protected.
- [ ] New dependencies are justified and scanned.
- [ ] Migrations are deterministic and reviewed.
- [ ] Negative security tests cover denial paths.
- [ ] Monitoring and alerting are considered.

---

## 27. Incident Response

When a vulnerability or security incident is suspected:

1. Preserve evidence without exposing secrets or customer data.
2. Identify affected service, actor population, data class, accounts, time
   window, deployment version, provider events, and correlation ids.
3. Contain active risk: disable route, revoke tokens, rotate keys, block source,
   pause job, disable integration, isolate environment, or roll back.
4. Assess financial impact: ledger entries, balance projections,
   reconciliation, duplicate commands, unauthorized transactions.
5. Assess legal, regulatory, customer, card network, and contractual
   notification obligations through approved governance.
6. Patch or mitigate through reviewed change control.
7. Add regression tests or detection rules where feasible.
8. Redeploy with monitoring.
9. Complete root cause analysis and preventive action.

Do not disclose incident details in public issues, public logs, commit messages,
or screenshots before an approved disclosure path exists.

---

## 28. Local Development Rules

- Use synthetic data only.
- Use local-only secrets only.
- Do not connect local tools to production.
- Do not store real customer exports, account statements, KYC documents,
  database dumps, certificates, or private keys in the repository.
- Do not disable security controls globally to simplify development.
- Local overrides belong in ignored files such as `application-local.yml`.

Safe placeholders:

```env
DATABASE_URL=jdbc:postgresql://localhost:5432/quinnbank
DATABASE_USERNAME=local_user
DATABASE_PASSWORD=replace-me
JWT_SIGNING_KEY=replace-me-local-only
WEBHOOK_SECRET=replace-me-local-only
```

---

## 29. Related Documents

- `AGENTS.md`
- `LIBRARY.md`
- `CODING_STANDARD.md`
- `docs/architecture/cif-module-design.md`
