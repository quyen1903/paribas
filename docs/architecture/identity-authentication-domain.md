# Identity Authentication Domain

## Scope And Ownership

The `identity` bounded context owns password-backed authentication identities,
authentication sessions, refresh-token rotation, issuer public-key metadata,
and access/refresh JWT issuance and validation. It does not own customer
profiles, government identifiers, KYC state, account state, roles,
permissions, or MFA authenticators.

`IdentityAccount` refers to its business subject through the scalar pair
`actorType` and `subjectId`. It must not import a CIF entity or call a CIF
repository. CIF's `CustomerIdentifier` remains a customer-document concept and
is not a login credential.

## Aggregate And Invariants

`IdentityAccount` is the aggregate root. It owns:

- a canonical, case-normalized login identifier;
- an opaque BCrypt value produced by Spring Security's configured
  `PasswordEncoder` outside the domain;
- administrative status, temporary lockout state, and failed-attempt count;
- credential-change, last-authentication, creation, and update timestamps;
- optimistic concurrency through `version`.

New identities are provisioned as `DISABLED` and require an explicit enable
transition. Only interactive actor types may use the password-backed aggregate.
Service accounts, partners, and batch jobs require a separately reviewed
authentication mechanism.

Raw customer passwords exist only transiently in redacted login inputs. CIF
provisioning never accepts a customer password; Identity stores a BCrypt value
derived from server-generated random material that is not returned to any
caller. A future activation flow must replace it only after ownership proof.
Raw passwords never enter a domain entity, migration, fixture, log, audit event,
or persistence model.
The encoded password is an authentication secret and must not be logged or
serialized.

## Runtime Flows And Application Boundary

The exact public HTTP allowlist is:

- `POST /api/v1/identity/login`
- `POST /api/v1/identity/refresh`

Every other route requires an access JWT. The refresh route is public only at
the HTTP-filter level; its signed, server-revocable refresh JWT is the
credential. HTTP Basic, form login, and server sessions are disabled.

Public self-registration is intentionally absent. A public request must never
select or submit a CIF/customer subject id because that would permit
cross-customer credential binding. Identity instead exposes the narrow
`ProvisionCustomerIdentityUseCase` application contract to a trusted
CIF/onboarding coordinator. The coordinator loads the customer server-side and
passes `Customer.id`; Identity creates a distinct identity id, fixes actor type
to `RETAIL_CUSTOMER`, stores the customer id as `subjectId`, and leaves the new
identity `DISABLED`. Provisioning creates no session and returns no token.

The current CIF coordinator accepts only an `ACTIVE` customer, locks that row,
and derives the login identifier from the stored customer email. `ACTIVE` is not
proof of KYC approval. Exposing provisioning or enabling the identity requires
a separately reviewed activation/KYC contract. Identity fixes the provisioning
audit actor to a server-side `SERVICE_ACCOUNT`; callers cannot select target
actor type, status, authority, scope, or password. That fixed audit attribution
does not replace caller authorization, which remains a release gate before the
internal command gets a production caller.

Login locks the identity row, performs BCrypt verification outside the domain,
updates success/failure state, opens a session, and persists audit evidence in
one transaction. Failed credential updates use an explicit commit-on-expected-
401 transaction rule so lockout counters and audit evidence are not rolled
back.

Refresh validation first checks JWT cryptography and claims, then locks the
session row. A refresh JTI is single-use. A stale valid JTI is treated as replay
and revokes the whole session; that revocation and its audit events commit even
though the HTTP result is 401. A signing or persistence failure rolls back a
successful rotation, so an undisclosed replacement does not burn the current
credential.

Concurrent authentication failures and refreshes use pessimistic row locks;
mutable aggregates also retain optimistic versions. Customer identity
provisioning locks an existing `(actorType, subjectId)` binding and treats a
same-customer/same-login replay as success only while it remains `DISABLED`;
database unique constraints remain the last race guard. A concurrent first
provision can still return a safe conflict
and requires caller retry. A bounded process-local rate limiter covers
provisioning source, login source/login identifier, and refresh requests. It
supplements account lockout, but a shared gateway/distributed limiter is still
required for a multi-node production deployment.

`AuthenticatedSubjectProvider` keeps JWT `sub` as the identity id, loads the
current `IdentityAccount` through the Identity repository port, verifies the
token actor type against stored state, and returns the server-stored
`subjectId`. CIF's `GET /api/v1/customers/me` uses that contract and never
accepts a customer id from the client, so the application read is scoped to the
authenticated business subject as well as protected at the HTTP boundary.
Denied customer-profile reads and method-security denials are persisted as
append-only `AUTHORIZATION_DENIED` audit events with safe reason and correlation
codes, without copying customer profile fields.

## JWT And Ephemeral Key Lifecycle

Both access and refresh tokens are RS256 JWTs produced by Spring Security's
Nimbus integration. Access tokens default to five minutes; refresh sessions
default to seven days. Both carry only opaque identity/session identifiers and
server-derived actor type; CIF/customer identifiers remain server-side.
Validation requires the fixed algorithm, `kid`,
header type, issuer, exact audience, subject, JTI, issued-at, not-before,
expiration, token use, active identity, and active session. Refresh JWTs are
never accepted as API bearer access tokens.
Authentication/session timestamps are canonicalized to JWT NumericDate's
whole-second precision. Validators cap token lifetime, bind issue/expiry to the
session, and reject tokens issued before the session or credential state.

Every token-pair issuance generates a new 3072-bit RSA key pair with the JDK
security provider. The same ephemeral private key signs that issuance's access
and refresh JWTs. A new opaque `kid` identifies the pair. The matching canonical
X.509/SPKI public key, its recomputed SHA-256 fingerprint, algorithm, `kid`, and
lifecycle timestamps are persisted as a verification-only key in the same
application transaction before the token pair can be returned to the client.
A public key can verify its two tokens; it cannot recreate the private key or
mint another token.

The private key is never written to PostgreSQL, configuration, source, logs,
audit records, or an API response. It remains reachable only through the local
issuance material while the two JWTs are encoded; after `issuePair` returns,
the application retains no reference to it. This is reference disposal, not a
guarantee that the JVM has immediately overwritten every provider-, library-,
or JVM-owned memory copy. Heap-dump controls and process isolation therefore
remain required. This in-process design is not equivalent to a non-exportable
KMS/HSM key and still requires formal security-architecture approval before
production use.

JWT verification loads a public key by `kid` from PostgreSQL, decodes and
validates its canonical RSA representation, and recomputes the SHA-256
fingerprint instead of trusting the fingerprint column alone. This preserves
the read-only signing-key-table compromise invariant: disclosure of every key
row reveals public material only and cannot by itself mint a token. PostgreSQL
is, however, now the verification trust root. An attacker able to insert or replace
both a public key and its fingerprint, or to bypass the lifecycle triggers, can
authorize an attacker-controlled signing key and forge JWTs for otherwise valid
identity/session state. The recomputation detects corruption or a one-column
substitution; it is not an independent trust anchor against database write
compromise. Least-privilege database roles, immutable-key triggers, append-only
key audit, write monitoring, and protected backups are therefore mandatory.

Each public key is verification-only from registration and may later be
revoked; there is no long-lived active signing key and no rotation of private
material. Key records are database-immutable, deletes are rejected, lifecycle
changes are constrained, and registration/status changes are recorded in the
append-only key audit table. Because issuance creates one key row and one key
audit event per token pair, governed retention, capacity monitoring, and an
approved archival strategy are required before production scale.

## Audit And Data Classification

Login identifiers are customer-confidential data. Encoded passwords are
authentication secrets. Authentication events are audit/security evidence.

The audit table contains identity and actor references, action, decision,
authentication method, stable reason code, correlation id, and UTC timestamp.
It never contains a submitted password, encoded password, token, or submitted
unknown login identifier. Unknown login/refresh failures use a
fixed anonymous actor and nullable target. Failures against a known identity
retain that identity only as the target and still record the initiating actor
as anonymous, avoiding false attribution to the customer. Database triggers
reject audit updates/deletes and identity-account deletes; closure is a state
transition.

The application must add validated source/channel context and record unknown
login failures through the audit boundary without copying the submitted login
identifier. Database privileges and retention remain deployment/governance
responsibilities.

## Migration And Failure Behavior

Flyway manages only the module-owned PostgreSQL `identity` schema and stores its
history there. Startup fails if its migration is invalid. Automatic baselining
and Flyway clean are disabled.

Hibernate validates all mapped tables and does not mutate them. Migrating the
pre-existing public/CIF schema to Flyway is a separate task because the current
local database has drift and existing rows. A fresh database therefore also
needs the future CIF baseline before the whole application can start. Identity
work must not silently baseline, rewrite, or delete that schema.

V1 creates identities and authentication audit storage. V2 adds public JWT
keys, append-only key audit, revocable authentication sessions, and expanded
authentication audit actions. V3 converts any legacy active public key to
verification-only and removes the single-active-key index so every issued pair
can retain its own public key. V4 invalidates stale optimistic-lock versions and
constrains all future key rows to verification-only or revoked states. V5 adds
a database trigger that makes the identity id, subject binding, actor type, and
creation timestamp immutable. V6 adds authorization-denial audit actions. No
migration stores private keys, raw credentials, or raw tokens.
The V6 constraint replacement locks and validates the authentication-audit
table, so deployment requires an approved lock-timeout and maintenance plan for
a populated environment.
If a deployed migration needs correction, add a later migration; do not edit
an applied migration. Database rollback is forward-only through a new, reviewed
migration.

## Deferred Security And Product Work

Bearer authentication is wired, but authentication is not the same as feature
authorization. Customer identities receive only a non-privileged actor
authority; they never receive `cif:write` or other business permissions. Each
feature still needs application-level actor/action/resource/scope policy.
Existing CIF create/update/close HTTP mutations therefore require `cif:write`;
customer tokens remain denied for those mutations. The reviewed ownership
increment in this change is intentionally read-only and limited to
`GET /api/v1/customers/me`.

Employee and back-office password login is intentionally denied until MFA is
implemented. Also deferred: a single-use customer activation invitation,
explicit KYC eligibility state, email/login ownership verification, recovery
and password reset, logout/all-session revocation API, entitlement/role storage,
step-up authentication, durable concurrent-provisioning idempotency, a durable
multi-node abuse limiter, trusted-proxy source attribution, migration to a
non-exportable KMS/HSM signer, operational alerting, key-table
retention/archival, and governed database privileges. Per-issuance RSA
generation also adds CPU cost to public
authentication flows, so distributed abuse controls and capacity testing are
release gates. Access/session validation fails closed on database/key-state
failure, but those operational controls still need deployment verification.

Legacy self-registration created active retail identities whose `subjectId`
equals their identity id. They cannot be mapped safely to CIF by email or other
heuristics. Runtime authentication rejects that self-binding even when the
stored status is `ACTIVE`; it does not silently relabel the persisted lifecycle
state. Inventory plus an approved mapping or quarantine process is a rollout
gate, and a later append-only migration must implement the governed outcome for
any environment containing those rows.

## Flyway Dependency Review

- Scope: runtime database migration for the isolated identity schema.
- Managed versions: Spring Boot 4.1.0 selects Flyway 12.4.0.
- Source: Maven Central through the existing repository configuration.
- License metadata: Apache License 2.0 in the resolved Flyway parent POM.
- Vulnerability check: OSV returned no advisories for
  `org.flywaydb:flyway-core:12.4.0` or
  `org.flywaydb:flyway-database-postgresql:12.4.0` on 2026-08-04.
- Transitives: Flyway Core resolves Jackson through the existing Spring Boot
  dependency set; the PostgreSQL module adds Flyway Core only.
- Network/telemetry: the resolved embedded open-source artifacts register
  Flyway's `NullFlywayTelemetryManager`; only the configured JDBC destination is
  used. A future Redgate CLI or proprietary plugin requires a separate review
  and explicit telemetry disablement.
- Failure mode: migration or validation failure stops application startup.
- Removal path: retain the SQL history and replace the startup migration runner
  only through a reviewed schema-management change.

## OAuth2 Resource Server Dependency Review

- Dependency: Spring Boot managed
  `spring-boot-starter-security-oauth2-resource-server` 4.1.0.
- Risk class: L4 because it validates and creates security tokens.
- Business need: Spring Security bearer processing, JOSE validation, and
  maintained Nimbus JWT integration; the JDK alone does not provide a safe JWT
  protocol implementation.
- Source/license: Maven Central; Spring Boot, Spring Security JOSE, and resolved
  Nimbus JOSE JWT 10.9 report Apache License 2.0 metadata.
- Resolved runtime: Spring Security OAuth2 Resource Server/JOSE 7.1.0 and Nimbus
  JOSE JWT 10.9 under the Spring Boot BOM. No second JWT library was added.
- Vulnerability review: OSV queries on 2026-08-04 returned no advisories for the
  resolved starter, Spring Security JOSE, or Nimbus versions.
- Network/telemetry: the implementation supplies a database-backed `JWKSource`
  and generates per-issuance RSA material with the JDK security provider; it
  does not configure issuer discovery, a remote JWK URL, telemetry, or a hidden
  network destination.
- Failure mode: invalid claims, unknown/revoked keys, fingerprint mismatch,
  inactive identity or session, and database/key lookup failures deny
  authentication. RSA generation or signing failure returns a safe
  service-unavailable response and rolls back issuance.
- Upgrade/removal: versions remain Boot-managed; replacing the library requires
  preserving the token/claim/key/session validation and negative-test contract.
- Approval: repository implementation review is complete here; formal security
  architecture approval of RS256/key operations is still required before a
  production release.
