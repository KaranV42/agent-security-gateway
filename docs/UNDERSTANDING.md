# Architecture Understanding

## Purpose and current domain

The Agent Security Gateway (ASG) exposes registered agent tools through an HTTP API and an in-process gateway. It validates tool arguments, evaluates principal/action/resource policy, issues a short-lived resource-scoped broker token, executes the authorized operation, and records authorization and execution outcomes.

The current demonstration registers one tool, `read_data`, for `public_records` and `restricted_records`. The `admin` principal may read both resources; `analyst` may read public records only. The local SQLite fixture contains synthetic records, not financial or personal data. `main.py` assembles the application; `asg.api.create_app` provides dependency injection for tests and callers.

## Request and trust boundaries

### Agent to gateway

- `POST /api/v1/execute` receives a `ToolCallRequest` (`tool_name`, `arguments`) and obtains its principal from a verified bearer JWT (`src/asg/api.py`, `src/asg/auth.py`).
- The gateway validates the tool and arguments, evaluates a `read` authorization request, logs the decision, authenticates to the broker using the configured service secret, and requests a resource-scoped session before calling the executor (`src/asg/gateway.py`).
- `GET /api/v1/tools` and `GET /api/v1/audit` do not declare the JWT dependency. The demo-token endpoint in `main.py` is also unauthenticated and accepts a requested principal. This is intentionally unchanged in B0; the approval gate for that behavior remains deferred.
- `asg.agent_runtime.run_agent` is an in-process mock path. It calls an `ASGGateway` directly and does not traverse the HTTP/JWT boundary (`src/asg/agent_runtime.py`).

### Gateway to identity provider and broker

- The IdP is a process-local singleton. It generates an RSA key pair at import time, signs demo tokens, and supplies the public key for validation (`src/asg/idp.py`, `src/asg/auth.py`).
- The broker is an in-process object shared by the app and executor. It stores opaque session-token records in a mutable process-local dictionary. Validation checks token existence, expiry, and resource equality (`src/asg/broker.py`).
- Broker tokens and IdP signing keys do not survive process restarts. Multiple worker processes would have separate in-memory state.

### Gateway and executor to data

- `ToolRegistry` checks registered tool names, argument shape, required arguments, and each schema's allowed resource set (`src/asg/registry.py`).
- The gateway derives `resource_id` from the request arguments and supplies it to the policy engine and broker (`src/asg/gateway.py`).
- `ASGGateway` depends on the backend-neutral `ToolExecutor` protocol and passes a typed request/result across that boundary (`src/asg/execution.py`, `src/asg/gateway.py`). The SQLite `ControlledToolExecutor` currently supports `read_data` and resolves the `(tool_name, resource_id)` pair through a fixed operation mapping before constructing its query (`src/asg/executor.py`). It validates the broker session against the resource in that configured binding. There is no arbitrary table-name or SQL argument.
- The mock data connection is in-memory and seeded when `create_mock_database` runs (`src/asg/database.py`). This is still a SQLite-specific executor; B0 does not introduce a backend abstraction or HTTP integration.

### Audit logger

- The gateway synchronously invokes the injected audit logger. Successful execution is not returned if its success-audit write raises; denial/validation audit errors are swallowed by `_log_audit` (`src/asg/gateway.py`).
- The persistent logger uses a local SQLite file, writes a hash chain, and offers an integrity check (`src/asg/audit_store.py`). The chain's append process is not serialized across the predecessor read and insert.

## Request lifecycle

### Authorized read

1. FastAPI validates the request body and resolves the JWT subject.
2. The gateway validates `read_data` arguments, constructs an authorization request for action `read` and the selected `resource_id`, and evaluates policy.
3. If allowed, the gateway authenticates to the broker and issues a token scoped to that resource.
4. The executor checks the token against `resource_id`, resolves that resource using its fixed mapping, and returns rows from the matching SQLite table.
5. The gateway records execution success before returning the result. The HTTP response contains `status`, `request_id`, and `result`.

### Default-denied read

An `analyst` request for `restricted_records` passes the generic tool/resource schema validation, but no matching allow rule exists. The gateway records the authorization denial and raises before issuing a broker token or calling the executor. The API returns HTTP 403 with `AUTHORIZATION_DENIED` details.

## Data and policy model

| Component | Current behavior |
|---|---|
| `ToolSchema` | Frozen schema describing required arguments, resource argument, allowed resources, and tool description. |
| `AuthorizationRequest` / `AuthorizationDecision` | Frozen value records; policy rules are evaluated first-match-wins with default deny. |
| Policy rules | `admin` is allowed `read` on both resources; `analyst` is allowed `read` on `public_records` only. |
| Broker session | Process-local record with `resource_id`, expiry, and a hash field. Validation checks token existence, expiry, and resource equality; the stored hash is not read during validation. |
| Data rows | Synthetic records in two SQLite tables. Rows are returned as dictionaries. |
| Audit row | SQLite columns include audit fields, timestamp, predecessor hash, and current hash. |

## Operational characteristics

- `main.py` constructs the database, executor, broker, registry, policy, audit logger, and app at import time.
- Data and broker state are in memory. Audit state is persisted in SQLite (`audit.db` by default).
- The FastAPI route functions are asynchronous, but gateway, SQLite, and audit calls are synchronous.
- The audit chain reads its previous hash and appends the next record in separate operations. Concurrent appends have not been stress-tested; deployment is assumed single-process for now.
- The public demo-token route remains an identity-minting boundary and is not addressed by B0.

## B0 genericization notes

- The previous demo's separate data-reading tool names became one `read_data` tool with a `resource_id` argument.
- Demo principals are now `admin` and `analyst`; resources are `public_records` and `restricted_records`.
- The executor's resource-to-table mapping remains a fixed SQLite allow-list behind the backend-neutral port. No HTTP adapter or arbitrary remote-call capability is included.
- The HTTP endpoints and request/response structures remain unchanged. Baselines and golden outputs are regenerated only for the approved generic fixtures and operation names.
