# Live Website Chatbot Integration Design

## Status and scope

This document proposes an implementation sequence for connecting a live website chatbot to the Agent Security Gateway (ASG). It is a design, not implementation authorization. No code, provider credentials, production endpoints, or deployment assumptions are introduced here.

The current ASG has a backend-neutral `ToolExecutor` port, a SQLite implementation, a process-local mock IdP, a process-local broker, a registry of tool argument schemas, default-deny policy, and a synchronous audit logger. A live integration must replace the demo trust assumptions before enabling external actions. It must not turn the executor into a generic URL-fetch facility.

## Target request flow

1. A user authenticates to the website through the organization's chosen identity provider.
2. The website's trusted server-side chatbot/orchestration service obtains the user's access token through the supported authentication flow. The browser does not call provider APIs or hold provider credentials.
3. The orchestration service calls the ASG over an authenticated, TLS-protected service connection and presents the user's access token or a separately designed, cryptographically verifiable delegation token. The ASG validates the issuer, audience, signature, expiry, and required claims; it does not trust a principal supplied in the JSON body or prompt.
4. The ASG maps verified identity claims to a stable principal and tenant context, validates the requested registered tool and arguments, resolves any target object to an authoritative resource/owner, then evaluates a default-deny policy.
5. Only after an allow decision does the gateway create a short-lived, operation/resource-scoped execution grant. The configured adapter obtains the specific provider credential from the broker, applies the server-owned operation definition, and sends a constrained outbound request.
6. The adapter validates and minimizes the provider response. The gateway audits the decision and execution outcome before returning the permitted result to the orchestration service, which then produces a user-facing response.

The browser and LLM are untrusted input sources. Neither is an authorization authority.

## 1. External identity provider and JWKS validation

### Trust configuration

Replace local signing and verification based on `idp.py` with an external token validator configured per environment. Configure the OIDC issuer and JWKS URI out of band (for example, from trusted Auth0 or Clerk tenant configuration); never derive the JWKS URL from a token claim, request parameter, user prompt, or arbitrary `jku`/`x5u` header. Require HTTPS and validate TLS certificates. Treat JWKS retrieval as a fixed-host outbound dependency with its own egress restrictions.

The validator should:

- Verify signature using a strict algorithm allowlist; reject `none`, unexpected algorithms, malformed keys, and unsupported key types.
- Select a key only by the token's `kid` from the configured issuer's JWKS; reject unknown keys and refresh the JWKS once through a bounded, rate-limited path to support key rotation.
- Validate exact configured issuer, the ASG API audience, expiry, not-before when present, and required subject/identity claims. Apply bounded clock skew.
- Cache successfully retrieved keys with bounded freshness. On refresh failure, use only still-eligible cached keys for a limited, explicit stale window; never accept an unverified token or fetch an arbitrary alternate URL as a fallback.
- Bound JWKS response size, parsing time, redirects, and connection/read timeouts. Avoid unbounded refreshes on attacker-selected `kid` values.
- Map the verified, issuer-qualified subject (`iss` + `sub`) to an internal principal; do not assume email or display name is a stable identifier. Validate tenant/organization claims against server-side configuration if multi-tenant operation is enabled.

The mock token signer and demo-token route must be disabled or removed from production configuration. If retained for local development, isolate it behind an explicit development-only mode, make production startup fail if it is enabled, and ensure its signing key cannot be accepted by production validators. Never accept arbitrary caller-selected principal IDs from the demo route in a live deployment.

### Website-to-ASG authentication

Decide whether the ASG validates a user access token directly or validates a short-lived delegation token issued by the trusted chatbot backend. Direct validation is simpler when the token is intended for the ASG audience. A delegation token can reduce exposure of provider tokens, but must be issued by a trusted server identity, have a narrow audience, include the original user and tenant context, and be protected against replay as required by the deployment. Do not forward an ID token as an API access token.

In either model, authenticate the calling service as well as the end user (for example, mTLS or workload identity). The service identity proves which backend is calling; it does not replace the end-user authorization decision. Define token forwarding, revocation, session/logout, and maximum token lifetime before rollout.

## 2. Constrained HTTP tool executor

Implement an `HttpExecutor` behind the existing `ToolExecutor` interface only after the operation and credential contracts are defined. The interface must carry the server-authorized operation identity and resource context, not a model-selected URL. Each operation should be registered by an immutable, server-owned definition containing, at minimum:

- Stable tool/operation ID and allowed action.
- Provider/service ID selected from a finite configuration set.
- HTTP method and fixed path template or a route builder with validated, typed path parameters.
- Argument and response schemas, allowed content types, and maximum request/response sizes.
- Credential audience/scope or broker credential reference, timeout budget, and explicitly approved network destination.
- Retry and idempotency policy, including whether the operation is safe to retry.

The LLM may choose only a registered tool and provide schema-validated business arguments. It must never supply or override scheme, host, port, URL, proxy, headers, authentication data, credential name, raw HTTP method, arbitrary path, SQL, or redirect destination.

### Credential broker boundary

Do not return long-lived provider secrets to the LLM, browser, tool arguments, audit records, or general executor results. Prefer a broker operation that returns a short-lived, least-privilege credential for a configured provider audience and operation, or performs a credential-injecting request through a trusted broker/proxy. Bind issuance/use to the calling ASG workload identity, operation ID, resource/tenant, and a short expiry; record the grant without recording the secret.

Keep the current opaque ASG-to-broker session token concept distinct from a provider credential. The gateway's authorization decision should mint or authorize a narrow execution grant; the HTTP adapter should be unable to use that grant for another operation, resource, tenant, or provider. Provider credentials and broker state must not be stored in user-controlled session fields. Define rotation, revocation, audit, and outage behavior for the selected secret manager before implementation.

### Outbound network controls

- Enforce an explicit destination allow-list outside and inside the application (network egress policy plus adapter configuration). Use separate entries for approved internal services and third-party APIs.
- Resolve and validate destinations safely. Block loopback, link-local, metadata-service, and other prohibited address ranges; where private/internal addresses are intended, enumerate exact approved services rather than allowing all private networks.
- Disable redirects by default. If a provider requires redirects, validate every redirect target against the same scheme/host/port policy and cap redirect count.
- Require HTTPS and certificate validation for external providers. Set connect/read/overall deadlines, connection limits, response size limits, and bounded concurrency.
- Build requests from validated structured values and fixed templates. Encode path/query parameters correctly; never concatenate untrusted input into a URL or header.
- Validate response status, content type, encoding, size, and schema. Return only the minimum fields required by the tool schema; reject or safely truncate unexpected content.
- Redact authorization headers, secrets, sensitive request fields, and sensitive response bodies from logs, errors, traces, and audit records. Return stable domain errors, not raw provider diagnostics.
- Apply provider-specific rate limits and circuit breaking only with an explicit failure contract. Retry only bounded, idempotent operations, with idempotency keys where supported; never automatically retry non-idempotent actions such as sending an email unless the provider contract guarantees deduplication.

### Error contract

Map connection failures, timeouts, provider rejections, malformed responses, credential failures, and policy denials into typed execution-domain errors with safe public messages and internal correlation IDs. Fail closed: no result is returned if authorization, credential retrieval, response validation, or required success auditing fails. A provider timeout must not be represented as success or retried without the configured operation's retry policy.

## 3. Registry and ownership-aware policy

### Tool definitions

Define separate, narrowly scoped operations rather than a generic HTTP tool. Examples:

- `fetch_order`: read one order from a fixed order service route. The model may provide an order reference, but that reference is only a lookup key, not proof of ownership.
- `send_email`: an explicit side-effecting operation with a recipient/content schema, policy constraints, user confirmation where appropriate, provider idempotency strategy, and stronger audit requirements. Do not expose it until abuse cases and consent behavior are decided.

Each tool definition should specify argument schema, fixed resource/action semantics, server-owned backend binding, allowed response fields, sensitivity, side-effect classification, and policy attributes required for authorization. Do not let a registry entry map to a free-form URL or an unrestricted connector identifier.

### Ownership-aware authorization

The present policy request is principally principal/action/resource based. Ownership cannot be safely implemented by trusting a model-supplied `user_id`, `tenant_id`, or an object identifier. Before adding customer data tools:

1. Define a verified principal context from the validated JWT: stable issuer-qualified subject, tenant/org, and any explicitly trusted roles/scopes.
2. Determine object ownership from an authoritative service or repository using a server-side lookup. Treat a supplied order ID as an untrusted selector; do not treat it as an ownership assertion.
3. Extend the authorization input/policy model to include trusted attributes such as tenant, canonical subject, operation, object owner, and sensitivity. The object-owner attribute must come from the authoritative lookup, not the LLM/request body.
4. Require the policy decision to match the verified subject/tenant to the authoritative owner for user-owned data. Keep default deny for missing, ambiguous, stale, or mismatched ownership; do not fall back to a broad role allow.
5. Bind the resulting authorized resource and operation to the broker grant and executor request. The adapter must use that binding, not independently reinterpret an untrusted identifier.
6. Re-check ownership at the data operation when the backend supports it (for example, a query constrained by both object ID and verified tenant/owner), to prevent a time-of-check/time-of-use gap. Prefer an atomic owner-scoped query over a check-then-fetch sequence.

For `fetch_order`, a secure pattern is an owner-scoped server-side operation such as “fetch order by ID where tenant and owner equal the authenticated context,” returning not-found/denied without exposing whether another tenant's object exists. The exact status and response semantics need an API decision. For `send_email`, ownership is not sufficient: define recipient allow-lists, consent, content safeguards, confirmation, rate limits, and abuse handling separately.

Policy should use explicit operation/action/resource semantics and a deny-by-default rule set. Do not use wildcard ALLOW rules for customer data. Document precedence and attribute provenance, test cross-user and cross-tenant access, and ensure policy or ownership-service outages fail closed.

## 4. Security boundaries and anti-hallucination guarantees

The security guarantee must come from deterministic server-side enforcement, not a prompt instruction:

- **No hallucinated URL:** The registry resolves a tool name to a fixed server-owned operation definition. The executor has no API accepting a caller-provided base URL, arbitrary host, or unrestricted path. Network egress is separately allow-listed.
- **No unregistered tool:** Gateway schema validation rejects unknown names and invalid arguments before policy evaluation or execution.
- **No principal spoofing:** Principal and tenant context come only from verified identity claims or a trusted, validated delegation token. Fields in chatbot messages, tool arguments, or browser requests cannot override them.
- **No cross-user object access:** Object ownership and tenant are determined by an authoritative backend and included in a server-side policy decision; the actual backend query/request is constrained to that same binding. Object IDs are selectors only, not authorization proofs.
- **No provider-secret exposure:** Credentials are retrieved/injected through a brokered server-side path scoped to the operation, audience, tenant/resource, and workload. They are never exposed to the model or browser and are redacted from diagnostics.
- **No unauthorized execution:** The gateway applies default-deny policy before issuing an execution grant. The adapter verifies the grant against the configured operation/resource binding.
- **No unsafe result propagation:** Provider response schemas and field allow-lists are enforced; errors and audit events are redacted. Required audit failures withhold results.
- **No network pivot:** Egress controls block unapproved destinations, including redirects and private/metadata addresses unless an exact internal service is explicitly approved.

These controls reduce risk but do not prevent the model from proposing malicious or unauthorized actions. They ensure such proposals cannot escape the configured registry, policy, identity, credential, and network boundaries.

## Decisions required before implementation

- Which IdP(s), issuer(s), audience(s), tenant model, and access-token/delegation-token flow will be supported?
- Which trusted chatbot backend identity calls the ASG, and how is that identity provisioned and rotated?
- What service owns canonical user, tenant, and object ownership data? Is an owner-scoped query available atomically?
- Which providers and exact operations are in the first release? Which HTTP methods, paths, response fields, sensitivity classes, and side effects are allowed?
- Which secret manager/broker will issue or inject provider credentials, and what are the grant scope, lifetime, revocation, and outage semantics?
- Which internal destinations are approved, and what network-level egress controls enforce the allow-list?
- What confirmation, rate limit, idempotency, and audit requirements apply to `send_email` and other side effects?
- What user-visible behavior should represent forbidden, not-found, provider-timeout, and audit-failure results without leaking object existence or provider details?
- What retention, privacy, deletion, and redaction requirements apply to chatbot transcripts, ASG audit events, and provider data?
- What availability, latency, throughput, and deployment model must JWKS caching, broker state, and audit storage support?

## Proposed implementation batches

These batches are proposals. Resolve the decisions above and approve each batch before implementation; passing a design review is not blanket approval to add live providers or side-effecting tools.

### C0 — Threat model and integration contracts

- Decide the identity/delegation flow, calling-service authentication, tenant model, authoritative ownership source, provider scope, egress policy, side-effect rules, and user-visible failure behavior.
- Specify typed identity, authorization-context, operation-definition, execution-grant, and provider-error contracts, including attribute provenance and redaction.
- Define environment separation, secrets handling, audit fields/retention, deployment topology, and measurable verification requirements.
- **Gate:** no production IdP or provider credentials configured until this contract is approved.

### C1 — External IdP validation

- Replace production use of the local mock signer with configured external JWKS verification and strict issuer/audience/claim validation, bounded key caching/rotation, and safe failure behavior.
- Disable arbitrary demo-token issuance in production; retain only an explicitly isolated local-development path if approved.
- Add tests for invalid signature, issuer, audience, expiry, missing subject, unknown `kid`, key rotation, JWKS outage/cache expiry, and malicious token header URL claims.
- **Depends on:** C0. **Gate:** no API execution enabled until identity and service-caller authentication are verified in the target environment.

### C2 — Verified principal and ownership-aware policy

- Introduce a verified principal/tenant context and trusted attribute provenance; extend policy inputs and evaluation for owner- and tenant-scoped decisions.
- Integrate an authoritative ownership lookup or owner-constrained repository operation, with fail-closed behavior and protection against time-of-check/time-of-use gaps.
- Add cross-user, cross-tenant, missing-owner, stale-owner, enumeration, and ownership-service outage tests. Preserve default deny.
- **Depends on:** C0 and C1. **Gate:** data tools remain disabled until owner-scoped enforcement is proven at the actual data operation.

### C3 — Registry operation definitions and brokered credential grants

- Extend server-side tool configuration with immutable operation IDs, fixed provider/service bindings, schemas, resource semantics, side-effect classification, response allow-lists, and credential audience/scope references.
- Define short-lived grants bound to the calling workload, operation, resource, tenant, and approved provider audience. Keep provider credentials out of model-visible and audit data.
- Add tests proving callers cannot supply or override backend IDs, URLs, credential references, or grant scope.
- **Depends on:** C0 and C2. **Gate:** no outbound adapter is exposed while grants can be replayed across operations/resources/tenants.

### C4 — First constrained HTTP adapter

- Implement `HttpExecutor` for one explicitly approved provider and a small set of fixed operations, behind `ToolExecutor`; do not implement a generic fetch tool.
- Enforce destination allow-listing, TLS, redirect policy, timeouts, response size/schema limits, safe errors, redaction, bounded concurrency, and operation-specific retries/idempotency.
- Verify the adapter's actual request destination and resource/owner constraints match the gateway's authorized operation and grant. Test SSRF inputs, redirects, DNS/private-address cases, oversized/malformed responses, provider failures, credential outages, and unauthorized scope.
- **Depends on:** C0, C2, and C3. **Gate:** enable a provider only after security and staging tests pass; additional providers require separate configuration and review.

### C5 — Website chatbot server integration

- Connect the trusted server-side orchestration service to the ASG using the approved user identity/delegation and workload-authentication flow.
- Expose only registry-derived tool schemas to the model; keep browser requests, prompts, and model-generated tool calls untrusted. Do not place provider credentials or authoritative principals in the browser.
- Define confirmation UX for side-effecting operations, rate limits, session isolation, tool-result minimization, transcript privacy, and user-facing safe errors.
- Add end-to-end tests from authenticated website identity through policy, ownership check, broker grant, fixed provider operation, and returned response.
- **Depends on:** C1-C4 for any provider-backed tool; a read-only, non-sensitive prototype may use a separately approved limited scope.

### C6 — Production hardening and rollout

- Validate workload identity, network egress enforcement, secret rotation, JWKS availability, audit durability/observability, rate limits, concurrency, and failure recovery in the deployment topology.
- Conduct adversarial tests for prompt-injected URLs, cross-tenant IDs, token replay, unauthorized operation selection, provider response injection, log/secret leakage, and denial-of-service limits.
- Roll out behind feature flags and provider/tool allow-lists with monitoring and a disable/credential-revocation procedure.
- **Depends on:** the production-bound C1-C5 scope. **Gate:** do not enable live tools until operational owners accept the evidence and rollback plan.

## Out of scope until separately approved

- Arbitrary URL fetching, user/model-controlled network destinations, unrestricted HTTP methods or paths, raw SQL, and model-supplied credentials.
- Any production use of the mock IdP or caller-selected demo-token endpoint.
- Broad provider catalogs, generic connector marketplaces, automatic retries for side effects, and returning raw provider responses.
- An in-browser direct connection from the chatbot to Stripe, Zendesk, internal services, or the ASG using provider secrets.
- Treating prompt instructions, frontend validation, CORS, or possession of a valid user JWT as a substitute for server-side policy and object-level authorization.
