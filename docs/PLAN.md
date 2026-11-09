# Phase 3 — Refactor Plan

## Planning constraints

- Phase 0 is the compatibility floor: `baseline_openapi.json` and every `golden/*.json` must remain byte-identical after each approved batch. A proposed change that alters one is a finding until the user explicitly approves changing that contract/baseline.
- The HTTP endpoints, request/response shapes, and status codes are frozen. No batch below assumes that a security fix may silently remove an endpoint or change its response/status behavior.
- No source/test changes are authorized by this plan. Phase 4 is batch-by-batch and requires explicit approval before execution.
- New regression assertions belong in new test files; existing assertions are not to be edited, deleted, skipped, or renamed. Tests may only receive the import/path adjustments allowed by the instructions if code is moved.
- The first batch is limited to the executor security boundary because it is confirmed, narrowly scoped, and can preserve the current HTTP behavior for valid gateway requests.

## Batch order

### Batch B1 — Bind broker scope to the executor's actual table

- **Intent:** Ensure an executor session scoped to one resource cannot authorize a different table selected by the tool mapping.
- **Findings addressed:** SEC-02.
- **Why grouped:** The token/resource check and tool-to-table selection are adjacent parts of one executor security decision. The direct probe demonstrated a sensitive-table result from a mismatched scope, so a focused negative regression belongs with the guard that prevents it.
- **Scope:** `src/asg/executor.py`, `ControlledToolExecutor.execute_tool` only; add a new focused test module under `tests/` that exercises direct executor calls with mismatched tool, argument resource, and issued broker token. Do not modify existing tests or public HTTP handlers.
- **Contract notes:** Preserve the HTTP API/OpenAPI contract. The normal gateway request path uses a registered matching tool/resource pair, so its status/result should remain unchanged. Reject the mismatched direct call before the SQL sink. If verification reveals any Phase 0 golden change, stop and report rather than updating the golden.
- **Verification:** Run the new focused test and existing executor/gateway tests; run the full `pytest -q` check in Phase 4. Regenerate and compare `baseline_openapi.json` and all five Phase 0 goldens (`jwt`, `hashchain`, `broker`, `policy`, `e2e`). The e2e happy/denial response contract must remain byte-identical. Add a dedicated test proving no client PII is returned for the mismatched direct call.
- **Risk:** Medium. The executor signature need not change, but code that intentionally used a token for one resource with another tool will now fail. The HTTP blast radius should be low because registry validation already rejects that pair.
- **Rollback:** Revert only the B1 commit. The new negative test should be reverted with the implementation if the batch is rolled back; leave all baseline artifacts untouched.

### Batch B2 — Verify persisted audit-chain links

- **Intent:** Make the integrity verifier validate the persisted predecessor link as well as the recomputed digest.
- **Findings addressed:** SEC-04; TST-03 (stored-link/mutation assertion only).
- **Why grouped:** The verifier algorithm and its tampering regression test define one integrity contract; this does not change how records are serialized or hashed.
- **Scope:** `src/asg/audit_store.py`, `PersistentAuditLogger.verify_integrity` only; add a new audit-store test module covering a valid persisted chain and targeted mutations, including a changed `previous_hash`. Do not change the hash payload or schema in this batch.
- **Contract notes:** Deterministic hashes from `golden/hashchain.json` must remain unchanged. The clean-database `/api/v1/audit/verify` response shape and status must remain unchanged; only the boolean result for corrupted/inconsistent rows should differ.
- **Verification:** Run the new tests and existing audit-related tests; compare all Phase 0 goldens and the OpenAPI snapshot. Explicitly confirm that the original five hashes are unchanged and that a valid chain remains `true`.
- **Risk:** Low/Medium. Existing malformed or historically inconsistent databases may now report invalid where the old verifier reported valid.
- **Rollback:** Revert the B2 commit if valid audit databases or the frozen clean-chain behavior differ; retain the new tests only if they continue to describe the intended verifier contract.

### Batch B3 — Make audit append predecessor selection atomic

- **Intent:** Prevent concurrent audit writers from deriving separate rows from the same chain predecessor.
- **Findings addressed:** SEC-05; TST-03 (concurrent-append assertion).
- **Why grouped:** Atomic predecessor selection and append are one persistence invariant; the test must exercise that exact concurrent-write guarantee.
- **Scope:** `src/asg/audit_store.py`, `PersistentAuditLogger.log` and only the transaction/connection helpers needed for its append; add a new audit-store concurrency test. Keep serialization fields, ordering semantics, schema, and hash algorithm unchanged.
- **Contract notes:** The serial `golden/hashchain.json` output must remain byte-identical. No HTTP changes are proposed. Use a concurrency test appropriate to the repository's SQLite deployment model; do not claim cross-process guarantees unless the implementation and test establish them.
- **Verification:** Run the focused audit tests repeatedly enough to detect a flaky race, then the existing audit tests and full suite. Compare OpenAPI and every golden output. Verify chain integrity after concurrent appends under the guarantee explicitly chosen for this batch.
- **Risk:** Medium/High. SQLite locking and transaction boundaries can affect contention, ordering, and failure handling; multi-process correctness may require a different design than a process-local lock.
- **Rollback:** Revert only B3 if the concurrency guarantee is not demonstrated or if serial hash outputs change. Do not weaken the test or claim broader process guarantees to make it pass.

### Batch B4 — Make denial-audit loss observable without changing denial semantics

- **Intent:** Surface audit persistence failures on validation/authorization paths while continuing to deny invalid or unauthorized requests.
- **Findings addressed:** SEC-03; OBS-01 (audit-failure observability only).
- **Why grouped:** The helper is shared by the validation and authorization audit paths; consistent handling and focused failure-injection tests are needed to avoid changing only one denial branch.
- **Scope:** `src/asg/gateway.py`, `ASGGateway._log_audit` and its validation/authorization call sites; add a new gateway test module using an injected logger that fails on those calls. Logging/metrics integration may use the repository's existing facilities; do not add a runtime dependency.
- **Contract notes:** Keep the existing denial and validation response codes and JSON shapes. If the chosen observability behavior changes a response or alters a Phase 0 golden, stop for approval rather than changing the baseline. Do not turn an authorization denial into an allow or allow execution to proceed after a failed decision.
- **Verification:** Test that denied/invalid requests remain denied and that the audit failure is observable; run existing audit/API tests. Compare OpenAPI and all goldens. Check that successful execution audit failure continues to withhold results.
- **Risk:** Medium/High. Surfacing a previously swallowed error can affect reliability and error mapping; an incorrect change could mask the original denial or make access fail open.
- **Rollback:** Revert B4 if denial semantics, success fail-closed behavior, API shape, or golden outputs change unexpectedly.

### Batch B5 — Stop policy rules from being mutated through caller-owned lists

- **Intent:** Make policy-engine ownership of its initial rule set explicit without removing supported `add_rule`/`clear_rules` behavior.
- **Findings addressed:** COR-01.
- **Why grouped:** This is a constructor/state-ownership issue in the policy engine, independently testable from rule matching and dynamic update behavior.
- **Scope:** `src/asg/policy.py`, `DeclarativePolicyEngine.__init__`; add a new policy test module proving external mutation of the constructor's input list cannot silently alter engine decisions, while engine APIs still update decisions.
- **Contract notes:** Preserve first-match-wins, wildcard semantics, empty-rule default deny, dynamic updates, and `golden/policy.json`.
- **Verification:** Run the new policy test and existing policy tests; compare policy golden, all remaining goldens, OpenAPI, and full test counts.
- **Risk:** Low/Medium. Callers that currently rely on mutating the original list after construction would see a behavior change; no such current production call was found.
- **Rollback:** Revert B5 if current documented/tested dynamic update behavior or the policy golden changes.

### Batch B6 — Validate executor argument type before field access

- **Intent:** Return the executor's documented input error for non-dictionary arguments instead of an incidental attribute error.
- **Findings addressed:** COR-02.
- **Why grouped:** This is a small validation-order correction in the executor, with a precise input/error assertion.
- **Scope:** `src/asg/executor.py`, `ControlledToolExecutor.execute_tool` input checks only; add a new executor test for non-dict input. Do not change gateway-level validation or broaden exception handling.
- **Contract notes:** Gateway-valid requests and all Phase 0 goldens remain unchanged. This affects only invalid direct executor calls.
- **Verification:** Run the focused new test and existing executor tests, then full suite and the standard OpenAPI/golden comparisons.
- **Risk:** Low. Direct callers may rely on the incidental exception type, though it is not the declared `ExecutorInputError` contract.
- **Rollback:** Revert B6 if the repository's intended invalid-input contract is different from the explicit executor error type.

### Batch B7 — Require an explicitly provisioned broker service secret

- **Intent:** Remove the source-literal broker credential from application composition without introducing any hardcoded/default fallback.
- **Findings addressed:** CFG-01.
- **Why grouped:** Secret provisioning and fail-fast startup behavior are a single configuration contract; tests and schema/golden harnesses must use an explicitly supplied test/development value.
- **Scope:** `main.py` composition and the exact configuration/documentation/test harness surfaces required to supply the value; no edits to `src/` unless the approved implementation requires a typed configuration boundary. If a new setting changes startup behavior, enumerate every script/test importing `main` before implementation. Do not add a default secret.
- **Contract notes:** This does not inherently change HTTP schema, but missing configuration currently starts the app and would become a startup failure. That is an intentional operational behavior change requiring explicit approval. The Phase 0 harnesses must run with a provisioned test value and produce identical outputs; never embed that value as a fallback in production source.
- **Verification:** Test both successful composition with explicit configuration and startup failure when it is absent; run all baseline harnesses with the explicit test environment and compare OpenAPI/goldens. Confirm no hardcoded replacement remains.
- **Risk:** High. It changes app startup requirements and affects ASGI launch, schema capture, and any caller importing `main`.
- **Rollback:** Revert the B7 commit and its documentation/config tests if deployment cannot provide a secret. Do not restore a hardcoded fallback; pause for a provisioning decision instead.

### Batch B8 — Align the standalone phase runner with current APIs (conditional)

- **Intent:** Make `run_phase5.py` reflect the current gateway/executor/policy construction APIs only if the owner confirms the script is supported.
- **Findings addressed:** STR-02; ERG-01.
- **Why grouped:** The stale imports and constructor calls form one broken invocation path; changing only one call would still leave the runner unusable.
- **Scope:** `run_phase5.py` only, unless a new test is approved; no aliases or compatibility shims in `src/`. First confirm the intended demo tools, policy, broker, and secret configuration because the current script's old call shape does not establish those semantics.
- **Contract notes:** This is not an HTTP API change, but the runner's desired behavior is not known. Do not add `PolicyEvaluator` or `get_default_broker` aliases.
- **Verification:** Only after the runner's intended behavior is confirmed, run it with explicit dependencies/configuration and compare the Phase 0 goldens/OpenAPI to ensure no shared behavior changed.
- **Risk:** Medium. The script may be historical or may encode a now-obsolete workflow.
- **Rollback:** Revert B8 if the owner identifies it as archival or its intended output cannot be established.

### Batch B9 — Type the security-boundary payloads incrementally (conditional)

- **Intent:** Replace broad/unparameterized boundary types with precise types where they encode actual runtime contracts.
- **Findings addressed:** TYP-01.
- **Why grouped:** API payload, executor arguments, broker session state, and audit output form separate boundaries; this batch must be split into cohesive sub-batches during planning if a bounded type-check baseline shows they do not depend on one another.
- **Scope:** Candidate locations are `src/asg/api.py:ToolCallRequest`, `src/asg/executor.py:ControlledToolExecutor.execute_tool`, `src/asg/broker.py:CredentialBroker._sessions`, and `src/asg/audit.py:AuditLogger.get_recent_records`; exact symbols/files must be narrowed before Phase 4 approval. Do not impose full-strict mypy on unrelated modules.
- **Contract notes:** Type annotations alone must not alter runtime behavior or serialized API/golden output.
- **Verification:** Establish the existing type-check baseline/tool first; add no runtime dependencies. Compare per-module diagnostics before/after, run tests, and compare OpenAPI/goldens.
- **Risk:** Medium. Broad annotation changes can hide rather than expose mismatches if types are inaccurate.
- **Rollback:** Revert the smallest failing type-only sub-batch; preserve runtime code and test behavior.

### Batch B10 — Document the supported developer workflow (conditional)

- **Intent:** Add textual setup, test, app-start, and supported-entry-point guidance.
- **Findings addressed:** ERG-02; relevant portions of STR-02 and CFG-01 after those decisions are settled.
- **Why grouped:** Contributor-facing instructions should describe the approved app composition and configuration, not codify unresolved or stale workflows.
- **Scope:** `README.md` only after the owner confirms the supported app runner, secret provisioning, and whether `run_phase5.py` is retained.
- **Contract notes:** Documentation-only; no runtime behavior or golden change.
- **Verification:** Review commands against the actual environment; no test run is necessary unless repository documentation tests are introduced.
- **Risk:** Low.
- **Rollback:** Revert the documentation commit if it describes an unsupported workflow.

## Separate high-risk approval gates

### Approval gate G1 — SEC-01 demo-token route

The route currently appears in the frozen API schema and issues tokens for caller-selected principal IDs. A meaningful restriction changes behavior; removing or relocating the endpoint changes the HTTP contract. **Do not implement SEC-01 as part of another batch.** Before any execution, the owner must explicitly choose and approve one of:

1. **Preserve endpoint and response/status contract:** Define a safe supported principal policy and whether/how unsupported values can be rejected without violating the frozen status/response contract. A behavior change still needs explicit golden/API approval.
2. **Disable/remove the endpoint in a production configuration:** This changes route availability and likely OpenAPI output; requires a specific exception to invariant #3 and approval to update the relevant baseline.
3. **Keep the endpoint demo-only but isolate it at a deployment boundary:** Requires verified deployment controls and evidence that the route cannot be reached in the protected deployment; code-only assumptions are insufficient.

Any approved implementation must not introduce a hardcoded secret or compatibility alias. Its scope and verification are to be written as a standalone batch after the owner decision. Until then, SEC-01 remains an assessment finding, not a scheduled code change.

### Approval gate G2 — COR-03 / OBS-01 request-ID correlation

Propagating one request ID into audit records changes the current runtime response/audit values captured by `golden/e2e.json`, even if OpenAPI remains byte-identical. **Do not alter the e2e golden silently.** If the owner wants correlation fixed, approve a separate batch and explicitly authorize the changed golden behavior; preserve response shape and status codes.

## Week-by-week recommendation

### Week 1

1. Approve and execute B1 first; it is the highest-confidence direct security defect with a narrow non-HTTP implementation surface.
2. Execute B2 with focused tampering tests, then B3 only after choosing the supported concurrency model and demonstrating atomic append behavior.
3. Execute B4 with failure injection, preserving denial semantics and the success-path fail-closed guarantee.
4. Execute B5 and B6 if their focused tests confirm the stated ownership and input contracts.
5. Resolve approval gate G1 early, but do not implement it until route exposure, demo intent, and the HTTP-contract exception are explicitly settled.

### Week 2+

- Resolve the secret provisioning/deployment requirements before B7; do not ship a source-literal fallback.
- Confirm whether `run_phase5.py` is supported before B8, and establish a type-check tool/baseline before splitting B9 into small sub-batches.
- Address B10 after the operational decisions are stable.
- Consider representative concurrency/load and multi-worker tests only after the deployment model and performance target are known.
- Revisit G2 only with explicit approval to change the e2e golden's request-ID behavior.

## What I would not change

- **PERF-01 / synchronous I/O:** Do not convert the current handlers or persistence path to async or introduce a new database/connection architecture without a measured production workload and target. The current prototype's workload is unknown, and changing transaction/ordering behavior could create more risk than a speculative optimization.
- **STR-01 / module-level app composition:** Do not reorganize the app or replace the current composition merely for stylistic reasons. The app factory already provides dependency injection, while module-level `app` is a conventional ASGI entry point and is used by the schema capture harness. Revisit only for a demonstrated startup-isolation or multi-worker requirement.
- **Broad package restructuring:** Do not split modules or add abstractions without a concrete boundary problem; current API, gateway, policy, registry, broker, executor, and audit modules are reasonably separated for this prototype.
- **Frozen dataclasses:** Preserve existing `frozen=True` models. Do not freeze additional models without a specific invariant and evidence.
- **Golden outputs or assertions:** Do not update Phase 0 goldens, soften existing assertions, or exclude failing tests to make a batch pass. Any observed difference is a finding that requires explicit approval.
- **Stale names via aliases:** Do not add aliases to make the old runner import current code; determine whether the runner remains supported and update its caller only if approved.
- **Hash-chain cryptographic redesign:** Do not add key management, external anchoring, or a new storage system until the intended audit threat model and deployment are known.

## Open decisions before affected batches

- Is the demo-token endpoint intended to be reachable outside local development, and which principals may it issue? What specific API/golden change, if any, is approved?
- Can any untrusted or less-trusted module invoke the executor directly, or is it strictly private to the gateway process?
- What deployment model should the audit-chain concurrency guarantee cover: one thread, one process, multiple processes sharing SQLite, or something else?
- Should denial/validation audit persistence failure be logged and still deny, or should the HTTP result expose an audit failure while retaining the denial? The access decision must never become allow.
- Is `main.py` expected to fail startup without an explicitly provisioned service secret, and how will schema/test harnesses receive a non-production value?
- Is `run_phase5.py` a supported runnable workflow or historical material?
- Which type checker and per-module diagnostic baseline, if any, are required?
- Are the current Phase 0 outputs immutable evidence, or may a specifically approved batch revise a golden when the desired behavior intentionally changes?

## Strategic Pivot: Genericization & Chatbot Preparation

### Pivot scope and constraints

This section supersedes the earlier B1-first ordering where it conflicts with the newly approved Generic Agent Security Gateway direction. **B0 must precede B1.5.** The previously discussed executor scope fix is not to be replayed as a standalone pre-pivot change; re-evaluate and carry its security invariant into the generic executor design. No code is changed by this plan.

The user explicitly authorizes changing the OpenAPI and Phase 0 golden baselines only as necessary for this pivot. That authorization is not permission for unrelated API changes, weakening security assertions, or regenerating baselines before the new behavior is reviewed. Preserve the existing `baseline` tag as the original financial-domain reference; do not move or overwrite it.

### Current architecture relevant to the pivot

- **`ControlledToolExecutor` is a concrete SQLite adapter today.** Its constructor requires a `sqlite3.Connection` and `CredentialBroker`; `_TABLES` hard-codes `read_market_data -> market_data` and `read_client_pii -> client_pii`. Execution validates a broker session, interpolates the mapped table into a local SQLite query, and returns row dictionaries (`src/asg/executor.py`). Genericizing names alone will not make it backend-independent.
- **`CredentialBroker` is not intrinsically financial.** It issues in-memory tokens scoped to an opaque `resource_id` string and validates token existence, expiry, and resource equality (`src/asg/broker.py`). Genericization should give that resource a domain-neutral meaning, such as a configured tool/resource scope, without storing third-party credentials in session state. The scope must still constrain the actual backend operation, not merely a caller-supplied argument.
- **`ToolRegistry` is mostly domain-neutral but models input shape, not execution.** `ToolSchema` contains required arguments, optional `resource_arg`, and optional allowed-resource values; it exports tool metadata and validates calls (`src/asg/registry.py`). It has no explicit backend/connector identity or operation binding today. Keep policy, schema validation, and backend execution as distinct responsibilities.
- **Financial assumptions are distributed, not confined to the UI.** The configured principals, tools, resources, descriptions, policy rules, and fixture data appear in `main.py`, `src/asg/database.py`, `src/asg/agent_runtime.py`, `src/asg/executor.py`, tests including `tests/deck.py`, and `templates/index.html`. The template also hard-codes token-fetch defaults, role/tool/resource choices, and the execute payload's `table_name`; changing only visible labels would leave the UI behavior and examples domain-specific.
- **Chatbot integration is not an executor feature by itself.** A website chatbot should call the ASG from a trusted server-side orchestration layer. The browser/model must not choose an authoritative principal, provide provider credentials, or select arbitrary outbound URLs. Tool definitions exposed to a chatbot should be derived from the registry's allow-listed metadata and remain subject to server-side authentication, policy evaluation, and execution authorization.

### Batch B0 — Genericize the ASG domain and establish generic baselines

- **Approval resolution:** The owner approved fixture-value and test-function-name updates for B0, while requiring assertion meanings and negative security coverage to remain unchanged. The selected demo principals are `admin` and `analyst`; the operation is `read_data`; resources are `public_records` and `restricted_records`. The executor may update its fixed SQLite resource mapping, but no backend-neutral abstraction or HTTP adapter is included.
- **Intent:** Replace the financial-services demonstration vocabulary and fixtures with a small, clearly synthetic, domain-neutral example while retaining the gateway's existing security responsibilities.
- **Findings addressed / work carried:** The pivot's generic-domain requirement; relevant context from SEC-02, TST-02, TST-04, and ERG-02. This batch is not an authorization to implement unrelated assessment findings.
- **Why grouped:** The names and sample values are coupled across app composition, registry definitions, policy rules, database fixtures, agent examples, UI form choices, tests, and golden outputs. A partial rename would leave an inconsistent demo or make the golden harnesses describe different behavior from the app.
- **Scope to inventory and update after approval:**
  - `main.py`: replace finance-branded configuration, demo principals, tools/resources, rule reasons, and descriptions with generic example identities and operations.
  - `src/asg/agent_runtime.py`: replace the hard-coded financial mock request with a generic tool/resource request.
  - `src/asg/database.py`: replace financial table names and values, including the synthetic SSN/wealth fixture, with non-sensitive generic records; keep it explicitly a mock database.
  - `src/asg/executor.py`: replace financial-specific tool/table examples. Preserve the executor's narrow configured-operation boundary; do not permit model input to become a table identifier.
  - `templates/index.html`: remove financial-service copy and replace principal/tool/resource options, default principal, labels, and request payload field names/values with the generic demo. Keep it a UI demonstration, not the future website chatbot or a new trust boundary.
  - `tests/` and `tests/deck.py`: the existing Phase 4 test constraint permits import/path adjustments only; it does not permit changing fixture values, assertions, or test names. Those existing tests will refer to finance-specific values after a source/data migration unless the owner explicitly approves a narrow B0 exception to that constraint. Do not add compatibility aliases to keep obsolete financial fixtures passing. New generic-domain assertions may be added in new test files after B0 is approved.
  - Golden generators and outputs: update only fixtures whose serialized behavior intentionally changes. Review all generator inputs and expected output before replacing any checked-in golden.
  - `README.md` and `docs/UNDERSTANDING.md`: update financial-domain descriptions only after runtime scope and generic examples are settled; preserve historical Phase 0 provenance in the plan/assessment.
- **Generic example direction:** Use the approved `admin` and `analyst` principals, the `read_data` operation, and synthetic `public_records` / `restricted_records` resources. Keep default-deny: `admin` may read both resources, while `analyst` may read only `public_records`. Avoid real-looking secrets, identity numbers, or personal data in fixtures.
- **Verification:** First run existing tests against the converted fixtures and identify every failure as either an incomplete rename or an intentional behavior change. Add or retain tests for default-deny, argument/resource validation, issuer/token validation, broker scope, audit behavior, and executor-to-resource binding. Verify the app's tool list and UI examples use consistent generic names. Run schema capture and every golden generator, compare outputs to the original baselines, and inspect each diff before replacing any baseline file. Do not claim the new baselines are equivalent to the old ones; they document the approved generic-domain behavior.
- **API/OpenAPI contract:** Preserve endpoint paths, methods, request/response field shapes, and status codes unless the owner separately approves a contract change. Tool/resource examples may change in returned data or UI without necessarily appearing in OpenAPI because the tool catalog is returned dynamically; inspect the actual schema diff rather than assuming it must change. If an intended public schema difference appears, isolate and explain it before updating `baseline_openapi.json`.
- **Safe baseline/golden update procedure:**
  1. Start from the approved pivot branch with the original baseline commit/tag intact; record the old artifact hashes or copy old artifacts to a temporary comparison directory outside the repo.
  2. Implement B0 and run tests before touching any baseline/golden artifact.
  3. Generate candidate OpenAPI and golden JSON outputs, review the exact diffs file by file, and confirm they reflect only the generic fixtures/behavior that B0 intentionally changes.
  4. Check schema endpoint/method/parameter/response compatibility separately from any intentional schema metadata difference. A name/value-only demo change is not by itself a reason to accept unrelated OpenAPI drift.
  5. Confirm JWT validation, default-deny, broker expiry/scope, hash-chain determinism for the new fixed fixture, e2e allow/deny outcomes, and no sensitive/financial sample values remain in the new fixtures.
  6. Only after that review, replace the same-named current baseline/golden files and commit them in the B0 change with a clear message identifying them as the generic-domain baseline. Do not overwrite or retag the original `baseline` tag; use Git history to retain the original outputs.
  7. Regenerate once more from a clean tree and verify byte-identical output. Record in the commit/Phase 5 changelog which files changed and why; if an unexplained difference remains, stop rather than bless it.
- **Test-invariant gate:** Resolved for B0 by explicit owner approval: fixture values and test function names may be genericized, but assertion meanings and negative security coverage must remain unchanged. The full existing suite must pass after genericization; do not add legacy aliases.
- **Risk:** Medium/High. The vocabulary and test fixture changes span the full demo surface; careless replacements can accidentally remove a negative security case or make tests pass against a weakened boundary.
- **Rollback:** Revert the B0 commit as a unit, including its generated generic baselines, leaving the original `baseline` tag untouched. Do not hand-restore selected golden files from memory.

### Batch B1.5 — Introduce a backend-neutral execution port for chatbot preparation

- **Intent:** Separate gateway authorization from backend execution so configured tools can later be served by local SQLite or fixed HTTP integrations without exposing arbitrary network access.
- **Findings addressed / work carried:** Generic executor abstraction and future chatbot integration readiness; carry forward the SEC-02 invariant that the broker scope and authorized resource must bind to the actual selected operation.
- **Why grouped:** An execution port, the existing SQLite implementation behind it, and its contract tests must move together. Adding an HTTP implementation before defining the port and security boundary would entangle provider-specific behavior with gateway policy and invite arbitrary-request execution.
- **Scope to design and narrow before implementation approval:**
  - Define a small `ToolExecutor` protocol (or existing-project-appropriate interface) around a typed execution request/result and a domain error contract. Keep gateway orchestration dependent on the interface, not on SQLite.
  - Adapt the current SQLite behavior as a concrete implementation behind that interface, retaining a fixed, configured mapping from registered operation to local query/table and parameter-free table selection.
  - Give the registry an explicit, server-owned operation/backend binding only if needed by the adapter design; it must not accept user/model-supplied URLs, SQL, provider credentials, or arbitrary connector identifiers.
  - Define how broker scope is associated with a configured backend operation and resource. Validate that the scope checked by the executor is the scope the adapter actually uses; do not use a model-controlled argument as the sole authority for the protected sink.
  - Keep provider credentials in server-side configuration/secret handling, never in tool arguments, chatbot prompts, browser code, audit records, or broker session payloads.
  - Add only the interface and SQLite adapter in this preparation batch. A Stripe/Zendesk/other HTTP adapter, outbound HTTP call, retry behavior, provider-specific models, new endpoints, and actual website chatbot are explicitly out of scope and require separate design/approval.
- **Chatbot preparation constraints:** The website/browser should communicate with the chatbot's trusted server, which authenticates the user and supplies a verified principal to the ASG. Never trust a principal, authorization decision, or resource ownership claim supplied only by the browser or model. The registry must expose only configured tool schemas; policy remains authoritative for every invocation. Do not implement conversation storage, prompt policy, UI chat widgets, or production identity federation in this batch.
- **HTTP/API contract:** Keep current ASG HTTP paths and request/response shape unchanged in B1.5. If the interface requires an externally visible schema/endpoint/field change, stop and request a separate explicit approval; the pivot's baseline exception is not blanket approval for unrelated API expansion.
- **Verification:** Add tests for an in-memory/fake implementation satisfying the interface, the existing SQLite adapter's current generic allow/deny behavior, adapter error translation, and the executor/broker scope-to-operation binding. Run the full suite and the post-B0 OpenAPI/golden harnesses; these outputs must match the new B0 baseline exactly unless a separately approved behavior difference is documented. Confirm that no arbitrary URL or raw SQL reaches the adapter from tool arguments.
- **Risk:** Medium/High. Interface placement and error translation affect the central execution seam; an overly broad port can leak infrastructure details or create a generic remote-call primitive.
- **Rollback:** Revert only the B1.5 commit, preserving B0's generic names and post-pivot baselines. Do not revert or rewrite B0 artifacts as part of rolling back the adapter abstraction.

### Ordering and relationship to earlier batches

1. **B0 first:** the domain contract and fixtures must be generic before the executor interface is designed around them.
2. **B1.5 second:** introduce the backend-neutral seam and preserve the resource-binding invariant against the actual adapter target.
3. **Reconcile later Phase 4 batches after B0/B1.5:** earlier B1-B10 scopes refer in places to financial fixtures, the concrete executor, and pre-pivot goldens. Do not execute those batches verbatim after this pivot; revise their affected file scopes, test names/fixtures, verification baselines, and dependencies in a later plan update or explicit approval.
4. **No live HTTP integrations yet:** actual external-provider adapters require a separate approved batch with provider credentials, target/host allow-listing, TLS/timeouts, response-size and schema limits, failure/redaction policy, and tests. The tool/model must never select an arbitrary URL. This is a security boundary, not just an implementation detail.

### Explicitly not included in this pivot

- Do not update the template or any other implementation file in this planning turn; the requested UI conversion belongs to B0 and no code is authorized yet.
- Do not build the external website chatbot or add a frontend chat experience.
- Do not add Stripe, Zendesk, or other live HTTP integrations in B1.5.
- Do not introduce a generic “fetch URL” tool or allow arbitrary SQL/table names.
- Do not change JWT identity issuance, SEC-01, or CFG-01 in B0/B1.5; their approval gates remain deferred.
- Do not change endpoint paths or request/response structures under cover of domain renaming.
- Do not change audit concurrency, denial-audit behavior, or other previously planned batches merely because the executor interface is being revised.
