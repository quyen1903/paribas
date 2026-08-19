# CIF Module Design

## Scope And Ownership

The CIF bounded context owns the bank's customer profile, customer number,
contact data, customer lifecycle status, risk rating, and customer identity
documents. It does not own passwords, authentication sessions, JWTs, or login
lockout state.

`Customer.id` is the stable internal customer subject identifier. The public
customer number is a business reference and must not be used as an
authentication credential. Customer PII and identifiers are confidential and
must not be logged or accepted as trusted authorization context.

## Identity Binding

Identity and CIF remain separate bounded contexts:

```text
IdentityAccount.id       -> authentication identity / JWT subject
IdentityAccount.actorType -> RETAIL_CUSTOMER
IdentityAccount.subjectId -> Customer.id
```

CIF never exposes a repository to Identity. A trusted CIF/onboarding
coordinator loads the customer through `CustomerRepositoryPort`, derives the
login identifier from server-stored customer data, and calls Identity's stable
`ProvisionCustomerIdentityUseCase` application contract. Identity owns the
credential hash, identity uniqueness, authentication audit, and final subject
binding.

Provisioning currently requires an `ACTIVE` customer. Identity records the
operation under the fixed `cif-onboarding` service audit actor, creates a
distinct `DISABLED` identity with a server-generated unusable credential, and
does not open a session or issue tokens. CIF and back-office code never select
or receive the customer's password. The fixed audit actor is not caller
authorization, so no HTTP endpoint or production caller exposes the internal
command today.

`ACTIVE` is not proof of KYC approval. A public activation flow requires a
separately reviewed, single-use, expiring activation credential, customer
ownership proof, explicit KYC/eligibility policy, and an atomic password-set and
enable transition.

## Customer-Owned Read

`GET /api/v1/customers/me` is the initial customer ownership contract. It:

1. requires the server-derived `actor:retail_customer` authority;
2. resolves JWT `sub` to the current `IdentityAccount` through
   `AuthenticatedSubjectProvider`;
3. obtains `Customer.id` from the stored identity `subjectId`;
4. queries only that customer; and
5. returns the profile with `Cache-Control: no-store`.

The route accepts no customer id, CIF number, role, actor type, or identity
header from the client. CIF application code repeats the actor-type and
resource-scope decision instead of relying only on controller annotations.

Create, update, and close operations remain privileged and require `cif:write`.
Customer tokens do not receive that authority.

## Transaction, Concurrency, And Failure Behavior

The CIF coordinator and Identity provisioner join the current monolith database
transaction. A failure in identity persistence or authentication-audit storage
rolls back provisioning. No external KYC, email, or notification call belongs
inside that transaction.

The coordinator obtains a pessimistic write lock on the customer before it
checks lifecycle eligibility and reads the email used as the login identifier.
Identity treats an exact sequential provision replay for the same customer and
login identifier, while the identity remains `DISABLED`, as the same result.
Unique login and `(actor_type, subject_id)` database constraints guard races; a
concurrent first provision can return a safe conflict and should be retried.
Durable idempotency records are deferred until the activation command contract
is defined.

The identity schema has no foreign key to the CIF table because that would
couple module persistence ownership. Its V5 migration instead makes the stored
identity id, actor type, and subject binding immutable after creation.

Legacy self-registered identities used `subject_id = identity.id`. V5 must not
be treated as approval to guess or freeze those rows into a customer mapping.
Runtime authentication rejects those self-bound customer identities even if the
stored lifecycle state remains `ACTIVE`. An environment containing them still
requires a governed inventory and mapping or quarantine decision before this
increment can be rolled out; because V5 is append-only, any controlled
remediation must be delivered as a later migration.

## Deferred Controls

The current increment does not claim a completed KYC workflow. Still required:

- explicit KYC/eligibility state and privileged audited transitions;
- one-time activation credential issuance, expiry, consumption, and replay
  tests;
- email/phone ownership verification;
- entitlement storage and a production caller for privileged CIF operations;
- customer creation/profile/status audit evidence;
- disable/revoke-session policy when a customer is blocked or closed;
- durable concurrent-provisioning idempotency;
- a forward-only Flyway baseline for the CIF-owned schema; and
- operational alerting for repeated authorization denials.

Existing identity rows whose `subject_id` was historically set to their own
identity id cannot be mapped safely to CIF by email or another heuristic. They
require a governed mapping process; this change does not guess or backfill that
relationship.
