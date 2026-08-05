# QuinnBank Library And Dependency Governance Standard

> Entry order: `AGENTS.md` -> `SECURITY.md` -> this file ->
> `CODING_STANDARD.md` -> `docs/`.
> This file governs third-party libraries, build plugins, runtime components,
> generated artifacts, and supply-chain risk for QuinnBank Core.

---

## 1. Purpose

QuinnBank Core is a banking product. A dependency is not just a convenience; it
is imported code with operational, security, legal, licensing, privacy, and
resilience impact.

This standard defines how libraries are evaluated, approved, added, upgraded,
monitored, and removed. It applies to:

- Gradle plugins.
- Java libraries.
- Annotation processors.
- Runtime drivers.
- Test libraries.
- Build tools.
- Container images.
- Generated code tools.
- CLI tools used by CI.
- Transitive dependencies that materially affect runtime or security.

No dependency may be added only because it is popular, fashionable, or saves a
few lines of code.

---

## 2. Baseline References

Dependency governance SHOULD align with:

- NIST SP 800-218 Secure Software Development Framework:
  https://csrc.nist.gov/pubs/sp/800/218/final
- SLSA supply-chain integrity principles:
  https://slsa.dev/
- OpenSSF Scorecard signals for open-source security posture:
  https://openssf.org/projects/scorecard/
- CycloneDX SBOM format for software bill of materials:
  https://cyclonedx.org/specification/overview/
- OWASP ASVS dependency, configuration, and secure SDLC expectations:
  https://owasp.org/www-project-application-security-verification-standard/
- Bank vendor risk, legal, privacy, and procurement policy where stricter.

This file defines repository-level engineering rules. Formal vendor approval,
legal approval, and regulator-facing attestations are outside the repository and
must follow bank governance.

---

## 3. Dependency Risk Classes

Classify every new dependency before adding it.

| Class | Examples | Approval bar |
| --- | --- | --- |
| L0 Test-only low risk | AssertJ, test fixtures, local test utilities | Engineering review |
| L1 Build-time | Gradle plugin, formatter, annotation processor | Engineering and supply-chain review |
| L2 Runtime low risk | Small mature utility without sensitive data access | Engineering review plus vulnerability/license check |
| L3 Runtime platform | Spring module, database driver, serializer, HTTP client, cache client | Senior review plus operational and security review |
| L4 Security-sensitive | Auth, crypto, JWT, password hashing, secrets, TLS, policy engine | Security architecture review required |
| L5 Financial/regulatory critical | Payment, card, KYC, AML, sanctions, fraud, ledger, reporting, export | Security, architecture, legal/vendor risk review required |

If uncertain, classify upward.

---

## 4. Default Decision Rule

Before adding a dependency, answer:

1. Can the JDK, Spring, Gradle, or current project stack solve this safely?
2. Is the problem business-critical enough to justify imported code?
3. Does the library become part of a sensitive or financial workflow?
4. What transitive dependencies enter the system?
5. What data can the library read, write, log, serialize, transmit, or persist?
6. What happens if the library has a critical vulnerability tomorrow?
7. What is the exit plan?

If the answer is unclear, do not add the dependency.

---

## 5. Mandatory Evaluation Checklist

Every proposed dependency MUST be evaluated for:

- Business need.
- Scope of use.
- Runtime versus test-only usage.
- Direct and transitive dependency tree.
- License.
- Maintenance activity.
- Release cadence.
- Known vulnerabilities.
- Security posture.
- Ownership and project governance.
- Artifact source and repository.
- Integrity verification.
- Compatibility with Java, Spring Boot, Gradle, and deployment environment.
- Logging behavior.
- Network behavior.
- Telemetry or phone-home behavior.
- Data handling and privacy impact.
- Operational failure modes.
- Upgrade path.
- Removal or replacement path.

For L3 or higher, record the evaluation in the pull request or an architecture
decision record.

---

## 6. Hard Blocks

The following MUST NOT be introduced:

- Abandoned libraries for production runtime use.
- Libraries with unresolved critical vulnerabilities and no mitigation.
- Libraries with unknown, custom, or incompatible licenses.
- Libraries that execute downloaded code at runtime.
- Libraries that make hidden network calls.
- Libraries that collect telemetry without explicit review and disablement
  controls.
- Libraries that require broad reflection or unsafe access in sensitive
  workflows without tests.
- Libraries that bypass Spring Security, transaction boundaries, validation, or
  audit controls.
- Custom cryptography libraries not approved by security architecture.
- Payment/card/KYC/AML/fraud SDKs without vendor risk review.
- Dependencies pulled from personal package repositories for production use.
- Dependencies added only to avoid writing simple domain code.

---

## 7. License Policy

License risk can block product launch.

Rules:

- Every dependency MUST have a known license.
- License compatibility MUST be checked before merge.
- Copyleft, source-available, commercial, trial, field-of-use restricted, or
  ambiguous licenses require legal review.
- Dependency notices MUST be retained where required.
- Generated code licenses MUST be understood.
- Transitive licenses matter.
- Test-only dependencies still require license review, but the bar may differ
  from production runtime dependencies.

No developer or agent may interpret complex license obligations as legal advice.
Escalate to legal/procurement governance.

---

## 8. Security Posture Review

For L2 or higher, review:

- Known CVEs and advisories.
- Maintainer response history.
- Signed releases or provenance where available.
- OpenSSF Scorecard or equivalent signals where applicable.
- Use of branch protection and release discipline.
- Dependency freshness.
- Security policy and vulnerability disclosure process.
- History of typosquatting or namespace confusion.
- Artifact checksums and repository trust.
- Whether the package is a thin wrapper over native code or external binaries.

For L4 or L5, security architecture must approve algorithm choices, token
formats, protocol behavior, key handling, secret handling, and failure behavior.

---

## 9. Approved Sources

Allowed by default:

- Maven Central.
- Spring official repositories when already required by project direction.
- Gradle Plugin Portal for reviewed build plugins.
- Bank-approved internal artifact repositories.

Restricted:

- JitPack.
- Personal GitHub package repositories.
- Random binary download URLs.
- Vendor-hosted repositories without procurement/security review.
- Snapshot, milestone, alpha, beta, release-candidate dependencies in production
  code.

If a restricted source is needed, document why approved sources are insufficient
and obtain explicit review.

---

## 10. Versioning And Pinning

Rules:

- Versions MUST be controlled through Gradle dependency management, version
  catalog, platform/BOM, or explicit version declarations.
- Production dependencies MUST NOT use dynamic versions such as `latest.release`,
  `+`, open ranges, or unbounded snapshots.
- Gradle wrapper version changes MUST be reviewed.
- Spring Boot and Spring dependency versions SHOULD be managed through the
  Spring Boot BOM unless there is an explicit override decision.
- Overrides MUST document reason, risk, and removal plan.
- Security patches SHOULD be applied with the smallest compatible upgrade that
  resolves the risk unless a broader upgrade is intentionally planned.

---

## 11. Transitive Dependency Control

Transitive dependencies are part of the product.

Rules:

- Review dependency tree for new runtime libraries.
- Exclude unnecessary transitive dependencies.
- Avoid duplicate libraries that solve the same concern.
- Avoid introducing a second JSON, HTTP, logging, metrics, crypto, or database
  abstraction without architecture review.
- Do not allow transitive dependencies to override core platform versions
  accidentally.
- Record high-risk transitive dependencies in the PR discussion.

Recommended Gradle checks:

```powershell
.\gradlew dependencies
.\gradlew dependencyInsight --dependency <name>
```

---

## 12. Library Categories And Specific Rules

### Serialization

- Prefer Spring/Jackson defaults already in the stack.
- For external contracts, DTOs must be explicit.
- Do not enable unsafe polymorphic deserialization.
- Do not deserialize untrusted payloads into domain aggregates.
- Validate queue and webhook payloads before processing.

### HTTP Clients

- Use a small number of approved HTTP clients.
- Configure connect/read timeouts.
- Avoid retries for non-idempotent requests.
- Redact headers and payloads from logs.
- Use allowlisted hosts for high-risk integrations.

### Database And ORM

- Do not introduce a second ORM or migration tool without architecture review.
- Database drivers must be maintained and compatible with deployed database
  versions.
- SQL helper libraries must not bypass audit, transaction, or invariant controls.

### Cryptography And Tokens

- Use only bank-approved, maintained libraries.
- Do not implement custom crypto.
- Do not accept libraries that hide key management.
- JWT/token libraries must enforce algorithm allowlists and claim validation.

### Money, Time, And Scheduling

- Money libraries must define currency, scale, rounding, and serialization
  behavior.
- Scheduling libraries must support idempotent jobs, observability, locking, and
  safe retry semantics for financial workflows.
- Time libraries must preserve timezone and UTC semantics explicitly.

### Observability

- Logging, metrics, tracing, and APM libraries must support redaction.
- Telemetry destinations must be documented.
- Sensitive payload capture must be disabled by default.
- Metrics labels must not contain PII, account numbers, tokens, or high-cardinal
  financial identifiers.

### AI, ML, And Analytics

- No AI/ML SDK may receive customer, account, KYC, AML, fraud, transaction, or
  security data without explicit data governance and security approval.
- Model telemetry, prompts, traces, and training data behavior must be reviewed.
- Generated recommendations must not become financial decisions without
  governed model risk controls.

---

## 13. Build Plugins And Annotation Processors

Build plugins and annotation processors execute code during build. Treat them as
supply-chain sensitive.

Rules:

- Use only reviewed plugins.
- Pin versions.
- Avoid plugins that download arbitrary binaries.
- Avoid plugins that modify source code without deterministic output.
- Review plugin permissions, tasks, and network behavior.
- Annotation processors must not hide domain invariants or generate broad
  setters for aggregates.
- Generated code must be reproducible and reviewable.

Lombok is allowed only for low-risk boilerplate. It MUST NOT be used to create
public setters, all-args constructors, or builders that bypass aggregate
invariants.

---

## 14. SBOM Requirements

QuinnBank Core SHOULD produce a software bill of materials for release artifacts.

SBOM expectations:

- Use CycloneDX or another bank-approved format.
- Include direct and transitive dependencies.
- Include versions, package identifiers, licenses, and hashes where available.
- Generate SBOM in CI for release builds.
- Store SBOM with the build artifact or release evidence.
- Use SBOM for vulnerability impact analysis.

If SBOM generation is not configured yet, dependency changes should still be
reviewed manually through Gradle dependency reports.

---

## 15. Vulnerability Management

Dependency vulnerabilities MUST be triaged by severity, exploitability, exposure,
and business context.

Minimum response expectations:

| Severity | Expected handling |
| --- | --- |
| Critical exploited or internet-exposed | Immediate triage; mitigate, patch, disable, or isolate |
| Critical not exposed | Urgent patch plan and documented compensating controls |
| High | Planned patch within bank risk tolerance |
| Medium | Track and patch in normal maintenance |
| Low | Track; patch opportunistically |

Triage must consider:

- Is the vulnerable code reachable?
- Is the service internet-facing?
- Does the service handle restricted or financial data?
- Is authentication required?
- Is there a known exploit?
- Is there a compensating control?
- Is a safe patched version available?
- Does the patch introduce breaking changes?

Do not dismiss a vulnerability only because it is transitive.

---

## 16. Emergency Dependency Changes

Emergency patches are allowed when risk requires speed, but they must still be
controlled.

Emergency process:

1. Identify affected dependency and version.
2. Identify vulnerable path and affected runtime.
3. Apply smallest safe upgrade or mitigation.
4. Run focused tests.
5. Review dependency tree.
6. Document risk accepted during emergency.
7. Create follow-up for full review and cleanup.

Do not bundle unrelated refactors with emergency dependency changes.

---

## 17. Deprecation And Removal

Dependencies must have an exit path.

Remove a dependency when:

- It is unused.
- It is abandoned.
- It has repeated unresolved vulnerabilities.
- It duplicates platform capability.
- It creates unacceptable license risk.
- It phones home or changes data behavior unexpectedly.
- It blocks platform upgrades.
- It bypasses core banking controls.

Removal must preserve behavior and tests.

---

## 18. Dependency Request Template

Use this template in PRs or ADRs for L3 or higher dependencies:

```text
Dependency:
Version:
Scope: runtime | test | build | annotationProcessor
Risk class: L0 | L1 | L2 | L3 | L4 | L5
Business need:
Why existing stack is insufficient:
Direct dependency source:
Transitive dependency summary:
License:
Known vulnerabilities:
Maintenance status:
Security posture:
Telemetry/network behavior:
Sensitive data access:
Operational failure mode:
Alternatives considered:
Upgrade/removal plan:
Tests added:
Reviewer approvals:
```

---

## 19. Review Checklist

Before merging dependency changes:

- [ ] Dependency has a clear business need.
- [ ] Existing stack cannot reasonably solve the problem.
- [ ] Risk class is assigned.
- [ ] License is known and acceptable or escalated.
- [ ] Vulnerabilities are checked.
- [ ] Transitive dependencies are reviewed.
- [ ] Source repository is approved.
- [ ] Version is pinned or managed.
- [ ] No dynamic versions or snapshots for production.
- [ ] Telemetry and network behavior are documented.
- [ ] Sensitive data exposure is understood.
- [ ] Operational failure mode is understood.
- [ ] Tests cover integration points.
- [ ] Security/architecture/legal review completed where required.
- [ ] SBOM/dependency report impact is understood.

---

## 20. Related Documents

- `AGENTS.md`
- `SECURITY.md`
- `CODING_STANDARD.md`
- `docs/architecture/cif-module-design.md`
