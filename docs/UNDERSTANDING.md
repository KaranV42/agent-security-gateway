# Phase 1 — Understanding

## 1. Purpose

The Agent Security Gateway (ASG) prototype exposes registered data-reading tools through an HTTP API and an in-process gateway. It validates tool arguments, evaluates principal/action/resource policy, authenticates the gateway to an in-process credential broker, obtains a short-lived resource-scoped token, executes a fixed tool-to-table mapping against SQLite, and records authorization and execution outcomes. The included financial-services fixture has public market data and client PII. The deployed-style app is assembled by `main.py`; `asg.api.create_app` provides dependency injection for tests and callers.

## 2. Trust boundaries

### Agent ↔ gateway

- **HTTP path:** A client supplies a JSON `ToolCallRequest` (`tool_name`, `arguments`) and a bearer token to `POST /api/v1/execute` (`src/asg/api.py:14-16,39-43`). FastAPI obtains `principal_id` through `Depends(get_current_principal)`. The tool arguments do not include an accepted principal field; the principal comes from the verified JWT subject (`src/asg/auth.py:24-31`).
- **Authentication:** The HTTP execute route authenticates the caller only through that JWT dependency. `GET /api/v1/tools` and `GET /api/v1/audit` do not declare the dependency (`src/asg/api.py:29-37`). The demo-token endpoint also has no auth dependency and signs the caller-supplied principal (`main.py:80-83`); this weakens the intended identity boundary and is a Phase 2 candidate.
- **In-process path:** `asg.agent_runtime.run_agent` passes a mock request directly to an `ASGGateway` object, with no HTTP or JWT boundary (`src/asg/agent_runtime.py:17-25`). The constructor receives the principal from its caller (`src/asg/gateway.py:12-29`).

### Gateway ↔ IdP

There is no network IdP call. `asg.auth` imports the process-local `idp` singleton and calls `get_public_key_pem()` (`src/asg/auth.py:5,14-15`). The singleton generates an RSA key pair at module import (`src/asg/idp.py:12-20`). JWT signature, algorithm, issuer, audience, and expiry are checked by `jwt.decode` (`src/asg/auth.py:17-22`). The same singleton signs demo tokens, and the unauthenticated route accepts any principal string (`main.py:80-83`, `src/asg/idp.py:38-52`). Key state is process-local and regenerated on restart.

### Gateway ↔ credential broker

This is an in-process object reference, not a network boundary: `main.py` creates one broker and passes it both to the executor and the app (`main.py:17-23,59-66`). The gateway compares its configured service secret through `authenticate_asg`, then issues a resource-scoped token (`src/asg/gateway.py:56-62`; `src/asg/broker.py:11-27`). The secret configured by `main.py` is a source literal (`main.py:17`). The broker stores token sessions in a mutable process-local dictionary; no session survives a process restart (`src/asg/broker.py:14,19-27`).

### Gateway ↔ executor

The gateway passes the tool name, arguments, and broker token to the executor only after registry validation and an allow decision (`src/asg/gateway.py:35-64`). The executor independently checks the broker token and maps tool names through `_TABLES` before querying (`src/asg/executor.py:7-10,17-37`). There is no separate process or transport authentication. A runtime probe confirmed that the token resource is not bound to the tool's mapped table: a token for `market_data` combined with `read_client_pii` and `table_name="market_data"` returned the `client_pii` fixture. This path reaches the data sink without the gateway's registry and policy guards; it is a Phase 2 candidate.

### Gateway ↔ audit logger

The gateway invokes the injected `AuditLogger` synchronously. Authorization/validation-path logging is routed through `_log_audit`; exceptions from that helper are swallowed (`src/asg/gateway.py:35-53,86-99`). Execution-success logging instead wraps failures as `AuditPersistenceError` and withholds the result (`src/asg/gateway.py:72-83`). No separate authentication protects this in-process call.

### Gateway/executor ↔ database

The executor holds a SQLite connection supplied by its caller. The mock database is in-memory and contains `market_data` and `client_pii` (`src/asg/database.py:3-23`). The executor interpolates only a table name selected from its fixed `_TABLES` mapping into its SQL statement (`src/asg/executor.py:8-10,30-38`). The audit logger independently opens the configured SQLite file, defaulting to `audit.db` (`src/asg/audit_store.py:7-14`). Both are local process/filesystem resources; there is no separate database authentication layer in this prototype.

## 3. Request lifecycle

### Success: authorized market-data read

1. `POST /api/v1/execute` validates the request body as `ToolCallRequest` and resolves the JWT subject through FastAPI dependency injection (`src/asg/api.py:14-16,39-45`).
2. The auth dependency validates the signed token. The relevant code is:

   ```python
   payload = jwt.decode(
       token,
       public_key_pem,
       algorithms=["RS256"],
       issuer="https://idp.asg-prototype.local",
       audience="https://api.asg-prototype.local"
   )
   ```

   (`src/asg/auth.py:17-22`). Missing `sub` becomes 401; otherwise the subject is returned (`src/asg/auth.py:24-31`).
3. The route builds an `ASGGateway` with the verified principal and injected dependencies (`src/asg/api.py:46-57`). The gateway validates structure before policy evaluation:

   ```python
   self.__registry.validate(tool_name, args)
   ```

   (`src/asg/gateway.py:35-41`). It then creates an `AuthorizationRequest` with action `"read"` (`src/asg/gateway.py:43-48`).
4. The policy decision is obtained with `decision = self.__policy.evaluate(auth_request)` (`src/asg/gateway.py:48`). The engine uses first-match-wins and returns a default denial when no rule matches:

   ```python
   return AuthorizationDecision(
       effect=Effect.DENY,
       reason="No matching policy rule found; access denied by default."
   )
   ```

   (`src/asg/policy.py:49-50`). The configured `wealth_advisor`/`read`/`market_data` rule allows the request (`main.py:41-54`).
5. After logging the policy result, the gateway enforces the service identity and issues a token:

   ```python
   if not self.__broker.authenticate_asg(self.__asg_secret):
       raise AuthorizationError("ASG failed to authenticate with Credential Broker")
   session_token = self.__broker.issue_session_token(resource_id)
   ```

   (`src/asg/gateway.py:50-62`).
6. The executor verifies the session against `args["table_name"]`, validates the argument set, then independently selects a table from the tool name:

   ```python
   if not self.__broker.validate_session(session_token, table_name):
       raise ExecutorInputError("Invalid or expired session token")
   table = self._TABLES.get(tool_name)
   ```

   (`src/asg/executor.py:22-31`). It queries the selected fixed table (`src/asg/executor.py:35-38`).
7. The gateway writes an execution-success `AuditRecord`; on audit failure it raises `AuditPersistenceError` rather than returning data (`src/asg/gateway.py:72-84`):

   ```python
   self.__audit_logger.log(AuditRecord(
       request_id=request_id,
       principal_id=self.__principal_id,
       tool_name=tool_name,
       resource_id=resource_id,
       phase=AuditPhase.EXECUTION,
       outcome="SUCCESS",
       reason="Operation completed."
   ))
   ```

8. The route returns `{"status": "SUCCESS", "request_id": ..., "result": ...}` (`src/asg/api.py:58-63`). A runtime smoke result was HTTP 200 with the AAPL fixture. The API request ID is generated separately from the gateway's audit request ID (`src/asg/api.py:44`, `src/asg/gateway.py:32`).

### Denial: client portal reads client PII

1. The same HTTP, body, and JWT steps supply `principal_id="client_portal"` and tool arguments for `read_client_pii` (`src/asg/api.py:39-45`).
2. The registry permits the tool/resource shape in the application configuration (`main.py:33-39`), so validation succeeds (`src/asg/gateway.py:35-41`).
3. The gateway evaluates `AuthorizationRequest(principal_id="client_portal", action="read", resource_id="client_pii")` and receives the default-deny decision because `main.py` deliberately defines no matching portal/PII allow rule (`src/asg/gateway.py:43-53`, `main.py:41-55`). The enforcement is:

   ```python
   if decision.effect == Effect.DENY:
       raise AuthorizationError(f"Authorization failed: {decision.reason}")
   ```

   (`src/asg/gateway.py:52-53`).
4. The gateway attempts to log the authorization decision, then raises `AuthorizationError` before broker issuance or executor invocation (`src/asg/gateway.py:50-53`).
5. The API maps that exception to HTTP 403 with `AUTHORIZATION_DENIED` detail (`src/asg/api.py:69-73`):

   ```python
   except AuthorizationError as e:
       raise HTTPException(
           status_code=status.HTTP_403_FORBIDDEN,
           detail={"status": "AUTHORIZATION_DENIED", "error": str(e), "request_id": api_request_id}
       )
   ```

   The captured e2e response had status 403 and the default-deny reason.

## 4. Data model

| Entity | Invariants and construction | Mutation/persistence |
|---|---|---|
| `Effect`, `AuditPhase` | String enums for ALLOW/DENY and AUTHORIZATION/EXECUTION (`src/asg/models.py:5-9`, `src/asg/audit.py:6-8`). | Immutable enum members; not persisted as objects. Their string values are persisted/serialized. |
| `AuthorizationRequest` | Frozen dataclass; enforces string, non-empty principal/action/resource (`src/asg/models.py:12-37`). Constructed by the gateway before policy evaluation (`src/asg/gateway.py:43-47`). | No mutations found; passed as a policy input. |
| `AuthorizationDecision` | Frozen dataclass; requires an `Effect`, string reason, non-empty reason (`src/asg/models.py:39-58`). Constructed by policy evaluation (`src/asg/policy.py:41-50`). | No mutations found; returned to gateway. |
| `PolicyRule` | Frozen dataclass. Optional principal/action/resource are wildcards; effect defaults to DENY (`src/asg/policy.py:5-15`). Constructed in `main.py` and tests. | Rule values are immutable, but the engine's list is mutable via `add_rule` and `clear_rules` (`src/asg/policy.py:23-33`). Rules are in memory only. |
| `ToolSchema` | Frozen dataclass; stores required argument names, resource argument, allowed-resource set and description (`src/asg/registry.py:8-15`). | Registry's `_schemas` dictionary is mutated by `register` (`src/asg/registry.py:18-25`); no persistence. |
| `ToolCallRequest` | Pydantic model containing `tool_name` and `arguments` (`src/asg/api.py:14-17`). Constructed by FastAPI request validation. | Request-scoped; not persisted. No explicit frozen configuration is present. |
| `AuditRecord` | Frozen dataclass with request/principal/tool/resource/phase/outcome/reason (`src/asg/audit.py:10-18`). Constructed by the gateway for authorization, failure, and success events (`src/asg/gateway.py:88-97`). | Immutable record object; persisted by `PersistentAuditLogger` as SQLite columns (`src/asg/audit_store.py:41-68`). |
| Broker session | Mutable dict containing `resource_id`, `expires_at`, and `hash` (`src/asg/broker.py:19-27`). | Created in `_sessions`; expired sessions are deleted by validation (`src/asg/broker.py:29-39`). Process-local, not persisted. The `hash` field is not read by validation. |
| Tool rows | SQLite rows are converted to dictionaries by the executor (`src/asg/executor.py:35-39`). | Mock data is seeded at database creation (`src/asg/database.py:8-23`); connection is in-memory. |
| Audit row | SQLite table columns include the record fields, timestamp, previous hash, and current hash (`src/asg/audit_store.py:16-28`). | Append-only by this code path; persisted in `audit.db` by default. No migration/versioning layer was found. |

The frozen dataclasses are used as value records passed between layers. Tests explicitly verify immutability for the authorization request and decision (`tests/test_models.py:67-73,108-114`). No other requirement for freezing them was verified; their current field usage is read-only.

## 5. State and durability

- **Process-local:** `main.py` creates the broker, mock database connection, executor, registry, policy engine, audit logger, and app at import time (`main.py:17-66`). `idp` creates its RSA key at module import (`src/asg/idp.py:12-20`). Broker sessions, rules, registry entries, and the mock data connection live in memory. Restarting loses these; multiple worker processes would have distinct keys, broker state, policy/registry copies, and in-memory databases.
- **Audit durability:** `PersistentAuditLogger` opens SQLite at `audit.db` by default and enables WAL (`src/asg/audit_store.py:7-14`). Its schema is created if absent. Calls open/close connections rather than retaining one. The audit table's timestamp is generated by SQLite. No backup, retention, migration, or durability policy beyond SQLite commits/WAL was found in the reviewed files.
- **Crash behavior:** A committed audit insert survives process restart subject to filesystem/SQLite durability. In-memory data and broker tokens do not. The IdP key is regenerated, so tokens signed before restart will not verify after restart.
- **Concurrent access:** There are no explicit locks. SQLite connections use `check_same_thread=False` for the data connection and each audit connection (`src/asg/database.py:4`, `src/asg/audit_store.py:13,34,58,77,98`). The FastAPI route functions are declared `async`, but the route body and all gateway/database calls are synchronous and contain no `await` (`src/asg/api.py:29-57`). The audit chain reads the previous hash on one connection and inserts on another, without a transaction spanning both (`src/asg/audit_store.py:41-68`). Concurrent appends can therefore race on the same previous hash; this has not been stress-tested. Cross-process behavior also depends on deployment details not present in the repository.

## 6. Security enforcement map

| Invariant | Enforcement and failure behavior | Guard coverage / candidate |
|---|---|---|
| JWT | `get_current_principal` verifies signature algorithm RS256, issuer, audience, expiry via PyJWT; missing subject and expected JWT failures become HTTP 401 (`src/asg/auth.py:8-51`). Only the execute endpoint declares this dependency (`src/asg/api.py:39-43`). | The unauthenticated demo-token route signs any requested principal (`main.py:80-83`), so an unauthenticated caller can obtain a correctly signed identity token; this undermines the token's identity guarantee. The tools and audit read endpoints are also unauthenticated (`src/asg/api.py:29-37`). |
| Hash chain | `PersistentAuditLogger.log` hashes sorted JSON of audit fields plus the prior digest (`src/asg/audit_store.py:41-68`). `verify_integrity` recomputes sequential expected hashes from `GENESIS` and returns false on mismatch (`src/asg/audit_store.py:75-95`). `main.py` exposes an unauthenticated boolean integrity endpoint (`main.py:85-88`). | This detects inconsistent record content if verification is run; append operations are not serialized across the read/insert pair. Verification derives the previous hash from prior `current_hash` and does not compare the stored `previous_hash` column. A writer able to rewrite the database can recompute the chain; no external anchor/signature was found. |
| Broker session | Gateway authenticates its service secret, issues a resource token, and passes it to executor (`src/asg/gateway.py:56-64`). Broker checks token existence, expiry, and resource equality (`src/asg/broker.py:29-39`). Executor rejects missing/invalid sessions before SQL (`src/asg/executor.py:17-24`). | The token resource is checked against `args["table_name"]`, while the SQL table is selected independently from `tool_name` (`src/asg/executor.py:22-37`). The direct probe successfully retrieved `client_pii` with a token scoped to `market_data`; therefore a path reaches sensitive data without gateway policy/registry checks. The stored session `hash` is not part of validation. |
| Default-deny policy | Policy iterates rules first-match-wins and returns DENY with a fixed reason if none match (`src/asg/policy.py:35-50`). Gateway evaluates before broker/executor (`src/asg/gateway.py:43-64`). | Correct for calls that pass through the gateway with a correctly constructed principal. It does not guard direct executor calls. `PolicyRule`'s `None` fields are wildcards, so a configured wildcard ALLOW intentionally broadens access (`src/asg/policy.py:5-15,53-62`). |
| Audit-before-result | Authorization/validation audit attempts may fail silently; successful execution audit failure becomes an error and withholds the result (`src/asg/gateway.py:35-41,50-53,72-99`). | The success path is fail-closed for a failure in the success audit call. Denials still deny if audit persistence fails, but their audit evidence is lost. |

## 7. Fail-open and fallback candidates

These are observations for the Phase 2 assessment, not changes:

1. **Unauthenticated arbitrary identity minting:** `GET /api/v1/auth/demo-token` calls `idp.generate_token(principal_id)` for a caller-provided identity and has no authentication dependency (`main.py:80-83`). The generated token has the same issuer, audience, and signing key the execute route trusts (`src/asg/idp.py:38-52`, `src/asg/auth.py:17-22`). This is the strongest fail-open candidate.
2. **Resource allow-list is optional:** `ToolSchema.allowed_resources` defaults to `None`, and registry resource membership is checked only when it is not `None` (`src/asg/registry.py:8-15,45-50`). Main's two configured tools do set explicit allow-lists (`main.py:27-39`), but schemas without one skip that guard.
3. **Policy wildcards:** `PolicyRule` uses `None` as a wildcard on principal/action/resource (`src/asg/policy.py:5-15,53-62`). An ALLOW rule with missing attributes can authorize a broader set than a fully specified rule; this is a supported rule feature, so correct use depends on rule configuration.
4. **Empty-string resource fallback:** the gateway uses `args.get("table_name", "")` before registry validation (`src/asg/gateway.py:31-40`). With configured schemas, a missing/invalid resource is rejected, so this is not an observed authorization bypass; it can produce an empty resource in the validation-denial audit record.
5. **Genesis fallback:** an empty audit table uses `"GENESIS"` as the first previous hash (`src/asg/audit_store.py:33-38,81-89`). This is the intended initial chain state, not an allow path.
6. **Empty rules fallback:** `rules=None` becomes an empty list and evaluation denies when nothing matches (`src/asg/policy.py:23-25,35-50`). This default is fail-closed.
7. **Swallowed denial-audit failures:** `_log_audit` catches every exception and does nothing (`src/asg/gateway.py:86-99`). Validation and policy denials continue to fail closed for access, but operational/audit failure is hidden.
8. **Hardcoded service secret:** `main.py` configures `"super-secret-machine-identity"` in source (`main.py:17`); there is no required environment configuration or missing-config failure at this call site. This is a configuration/secrets risk, not a fallback expression.
9. **Executor accepts dynamic argument types at runtime:** `args.get` is called before the executor's `isinstance(args, dict)` guard (`src/asg/executor.py:22-26`). The gateway's registry checks type first, but a direct executor caller can cause an exception; this appears fail-closed for data access, not a fallback.

No other missing environment-variable, dictionary-key, falsy-value, or empty-string fallback that expands access was observed in the specified source files. `get_current_principal` fails for absent/invalid JWT claims; registry rejects missing/extra arguments; broker rejects nonexistent/expired/wrong-resource sessions.

## 8. Error model

- **JWT errors:** PyJWT expiration, issuer, audience, and other `PyJWTError` failures are translated to 401 (`src/asg/auth.py:33-51`). FastAPI request-body/Pydantic validation occurs before the endpoint handler; no custom catch maps it, so framework validation behavior applies (normally 422). `ToolCallRequest` construction is at `src/asg/api.py:14-17`.
- **Registry/policy errors:** `ToolValidationError` is a `ValueError` subclass and raised for unknown tools, non-dict args, missing/extra args, or a disallowed configured resource (`src/asg/registry.py:5,27-49`). The gateway logs and re-raises validation errors (`src/asg/gateway.py:35-41`). Policy denial becomes `AuthorizationError`, a `PermissionError` subclass, then HTTP 403 (`src/asg/gateway.py:8-9,50-53`; `src/asg/api.py:69-73`).
- **Executor errors:** `ExecutorInputError` is a `ValueError` subclass. It rejects unsupported tools, invalid broker sessions, and invalid argument sets (`src/asg/executor.py:4,17-32`). Other exceptions (including SQLite exceptions) may arise at the query (`src/asg/executor.py:35-38`); gateway catches broad `Exception`, attempts a failure audit, and re-raises (`src/asg/gateway.py:64-69`). The API's final broad catch maps exceptions reaching the route to HTTP 500 `EXECUTION_FAILURE` (`src/asg/api.py:79-83`).
- **Audit errors:** `PersistentAuditLogger.log` catches broad `Exception` only around its insert/commit block and wraps it as `AuditPersistenceError` (`src/asg/audit_store.py:58-73`). Errors from `_get_last_hash` occur before that block. Gateway's denial/validation `_log_audit` swallows every exception (`src/asg/gateway.py:86-99`); successful execution audit failures are re-raised as `AuditPersistenceError` (`src/asg/gateway.py:72-83`) and mapped to HTTP 500 `AUDIT_FAILURE` (`src/asg/api.py:74-78`).
- **Inheritance fact:** Runtime inspection confirmed `sqlite3.Error` is neither a `RuntimeError` nor a `ValueError`; therefore a future catch narrowed to either would not catch SQLite failures. `pydantic.ValidationError` is a `ValueError` subclass in the active environment, but the API's `except ToolValidationError` catches only that specific subclass, not all `ValueError`s or Pydantic validation performed before endpoint invocation.
- **Potentially hidden exceptions:** Audit read/verify paths and initial schema setup do not wrap SQLite failures (`src/asg/audit_store.py:12-30,75-105`). In the execution-failure path, failure to persist the failure record is swallowed by `_log_audit`, after which the original execution exception is re-raised. The authorization audit path also continues after failed persistence.

## 9. Concurrency model

The application has async FastAPI endpoint declarations, but each endpoint performs synchronous dependency and gateway work, and there are no `await` statements in the route bodies (`src/asg/api.py:29-57`). The database and audit operations are synchronous. SQLite's `check_same_thread=False` disables the connection's thread-affinity check; it does not itself serialize access. No locks are present around the policy rule list, tool registry dictionary, broker session dictionary, shared SQLite connection, or audit-chain append. The audit writer's read-last-hash and insert are separate operations/connections. A concurrent append can race with another append and produce a chain that fails later verification. Behavior across multiple app workers is unknown because no deployment configuration was provided.

## 10. Test coverage shape

The committed collection baseline reports **51 tests collected** and **51 passed** (`baseline_collect.txt`, `baseline_run.txt`). The collected files cover:

- `tests/test_api.py`: tool listing, unauthenticated execute rejection, successful execution, authorization denial, and invalid issuer.
- `tests/test_models.py`: request/decision validation and frozen behavior.
- `tests/test_phase1.py`: executor reads and input rejection.
- `tests/test_phase2.py`: mock agent/gateway flow and a source-level check that agent runtime does not import executor.
- `tests/test_phase3.py`: gateway structural validation and not executing on validation failure.
- `tests/test_phase4.py`: policy allow/deny cases and principal spoofing via extra argument.
- `tests/test_phase5.py`: authorization/execution audit records, denied-path logging, success audit failure, validation audit, and request IDs.
- `tests/test_policy.py`: default deny, explicit/wildcard allow, first-match-wins, and dynamic policy update.

`tests/deck.py` contains performance, executor bypass, injection, token expiry, and audit-failure tests, but it is not named `test_*.py` and is not included in the 51-test collection. There is no dedicated test module for `audit_store` hash-chain verification or for binding a broker token's resource to the table selected by a different tool. The gateway audit tests use an in-memory logger for most behavior; persistent SQLite audit failures and chain races are not exercised by the collected suite. Auth has API-level cases but no dedicated unit test for every JWT claim/error branch. The current tests establish ordinary behavior, but the confirmed executor mapping mismatch demonstrates a security path the existing passing tests do not cover.

The Phase 1 targeted runtime checks also ran the four golden scripts and e2e smoke script; `git diff -- golden/` was empty. Seven focused policy/audit tests passed. These checks are recorded in Section 12.

## 11. Load-bearing hacks and stale surfaces

- **Fixed table map:** The executor maps tool names to literal table names and uses that mapping in the query (`src/asg/executor.py:8-10,30-38`). This is an important SQL boundary; replacing it with a user-supplied table name would remove that control. The current mapping's independent relationship to the token resource is the candidate finding in Section 6.
- **Broker session between gateway and executor:** The gateway authenticates a service secret and gives the executor a short-lived token rather than directly executing after policy (`src/asg/gateway.py:56-64`). The existing `tests/deck.py` explicitly frames this as executor bypass resistance (`tests/deck.py:83-95`), but that test is not collected by the baseline and does not test cross-tool/resource mismatch.
- **Audit failure asymmetry:** Denial-path audit errors are swallowed to preserve the original denial, while success-audit failure withholds the protected result (`src/asg/gateway.py:72-99`). Changing the broad behavior without separating those semantics could alter the fail-closed property.
- **Module-level app composition:** `main.py` constructs all dependencies at import time and exports `app` (`main.py:17-66`). This lets the ASGI runner import a ready app and supports `scripts/capture_schema.py`; it also means import has database and singleton side effects.
- **`run_phase5.py` appears out of sync:** It imports `PolicyEvaluator`, constructs `ControlledToolExecutor` without the required broker, and constructs the gateway without broker/secret arguments (`run_phase5.py:1-35` versus `src/asg/policy.py:17`, `src/asg/executor.py:13`, `src/asg/gateway.py:12-29`). No compatibility alias should be inferred; the script was read but not run.
- **Dependency declaration gap candidate:** `pyproject.toml` declares FastAPI, Uvicorn, and Jinja2 (`pyproject.toml:7-12`), while reviewed runtime modules import `jwt` and `cryptography` (`src/asg/auth.py:1`, `src/asg/idp.py:1-4`). Whether these arrive transitively or from an environment setup is not established by the listed manifest; no dependency changes were made.

## 12. Prediction and verification

The predictions below were recorded before checking the relevant runtime outputs; the observed outputs matched.

1. **JWT invariant — valid fixture:** Given a JWT signed by the active IdP key with subject `golden-principal`, correct issuer/audience, and a future expiry, I predict `get_current_principal` accepts it and the claims include that subject. `scripts/golden/gen_jwt.py` produced `valid: true` and the expected claims in `golden/jwt.json`.
2. **JWT invariant — invalid fixtures:** Given expiry `1`, a different signing key, or a wrong issuer, I predict validation returns false for each fixture. The generated `golden/jwt.json` records `expired`, `wrong_signature`, and `wrong_issuer` as `valid: false`.
3. **Hash-chain invariant:** Given the five fixed `AuditRecord`s in `scripts/golden/gen_hashchain.py`, I predict five intermediate digests and the fifth digest as final. The script produced five hashes; final was `069934e9fa6837a250f01e14869628f14a238108c735944542cbc5701d93148d` in `golden/hashchain.json`.
4. **Broker invariant:** Given an issued session scoped to `golden-resource`, I predict validation returns true for that resource, false for another resource, and false for a nonexistent token. `golden/broker.json` matched: true, false, false.
5. **Default-deny policy invariant:** Given no rules or a nonmatching ALLOW rule, I predict `Effect.DENY` and reason `No matching policy rule found; access denied by default.`; given a matching ALLOW, I predict ALLOW with the configured reason. `golden/policy.json` matched all three cases.
6. **Happy path:** Given a valid wealth-advisor token, `read_market_data`, and `table_name="market_data"`, I predict gateway validation and policy allow, followed by HTTP 200 with the AAPL fixture. `golden/e2e.json` recorded status 200 and the AAPL row.
7. **Policy failure path:** Given a valid client-portal token requesting `read_client_pii`, I predict registry validation succeeds, policy default-denies, executor is not reached, and the API returns HTTP 403 `AUTHORIZATION_DENIED`. `golden/e2e.json` matched that status and reason.
8. **Audit failure path:** Given an audit logger configured to fail on its second call for an otherwise allowed read, I predict the success-audit failure raises `AuditPersistenceError` and withholds the result. `pytest -q tests/test_policy.py tests/test_phase5.py::test_audit_failure_withholds_result tests/test_phase5.py::test_denied_request_logs_auth_deny_and_skips_execution` passed (7 tests), including the expected audit-failure assertion.
9. **Guard-bypass probe:** Given a broker token scoped to `market_data`, then a direct executor call with `tool_name="read_client_pii"` and `table_name="market_data"`, I predicted the token check would pass while the tool mapping selected the PII table. The focused runtime probe returned the `client_pii` fixture (`client_id` `C-9901`), confirming the policy/registry bypass candidate. This is a finding candidate for Phase 2, not a code change.

## Unknowns

- The intended trust model for `/api/v1/auth/demo-token` is not documented. It may be explicitly demo-only, but it is mounted on the same app and signs caller-selected identities accepted by the execution endpoint.
- There is no deployment configuration in the reviewed files to establish whether the app runs single-process, with multiple workers, behind an external identity proxy, or with filesystem isolation. Those choices affect key rotation, memory state, SQLite contention, and reachability of unauthenticated routes.
- It is unknown whether the source-literal ASG secret is strictly a local prototype value or is reused in any deployment. No secret provisioning mechanism was present in the reviewed app construction.
- The expected lifetime and persistence requirements for IdP signing keys and broker sessions are unspecified. Current behavior is process-local and resets on restart.
- The repository does not establish whether hash-chain tamper evidence is intended only for accidental corruption, malicious local database writers, or a compliance-grade threat model. The implementation has no external checkpoint/key and no concurrent-append guarantee.
- `PersistentAuditLogger` creates a schema but no migration/versioning behavior was found. How existing audit databases should evolve is not established.
- `tests/deck.py` appears intended to contain additional security/performance tests but is outside default pytest discovery. Whether that omission is intentional is unknown.
- `run_phase5.py` does not match the current constructor/import APIs; it is unknown whether it is historical, expected to be runnable, or still part of a documented workflow.
- The declared project dependencies omit direct declarations for the imported JWT and cryptography libraries. Their intended source (transitive dependency, developer environment, or missing manifest entries) is unknown.
- No production database, real IdP, real broker, telemetry/logging backend, deployment manifest, CI workflow, or concurrency/load setup was included in the requested read scope. Conclusions about those operational systems cannot be verified from this repository snapshot.
- The test baseline does not provide coverage evidence for all execution paths, particularly persistent audit-chain verification, audit storage failures outside the insert block, API behavior across multiple workers, and the confirmed direct-executor resource mismatch.
