import uuid
from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel
from typing import Any

from asg.gateway import ASGGateway, AuthorizationError
from asg.registry import ToolRegistry, ToolValidationError
from asg.audit import AuditPersistenceError, AuditLogger
from asg.executor import ControlledToolExecutor
from asg.policy import PolicyEvaluator
from asg.auth import get_current_principal  # <-- Updated import

class ToolCallRequest(BaseModel):
    """
    OpenAI/LangChain compatible tool call payload.
    Identity is strictly derived from the JWT header, not the body.
    """
    tool_name: str
    arguments: dict[str, Any]

def create_app(
    executor: ControlledToolExecutor,
    registry: ToolRegistry,
    policy: PolicyEvaluator,
    audit_logger: AuditLogger
) -> FastAPI:  # <-- jwt_secret_key removed
    app = FastAPI(title="Agent Security Gateway API", version="2.0.0")

    @app.get("/api/v1/tools")
    async def get_tools():
        """Returns the registry of available tools in OpenAI-compatible schema."""
        return registry.get_openai_tools_schema()

    @app.get("/api/v1/audit")
    async def get_audit_log():
        """Returns the recent audit records."""
        return audit_logger.get_recent_records(limit=50)

    @app.post("/api/v1/execute")
    async def execute_tool(
        req: ToolCallRequest,
        principal_id: str = Depends(get_current_principal)  # <-- Uses global dependency
    ):
        api_request_id = str(uuid.uuid4())

        # Instantiate gateway with the verified principal from the JWT
        gateway = ASGGateway(
            executor=executor,
            registry=registry,
            principal_id=principal_id,
            policy=policy,
            audit_logger=audit_logger
        )

        try:
            # Note: gateway.execute_tool expects 'args', we map 'arguments' from the API model
            result = gateway.execute_tool(req.tool_name, req.arguments)
            return {
                "status": "SUCCESS",
                "request_id": api_request_id,
                "result": result
            }
        except ToolValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"status": "VALIDATION_DENIED", "error": str(e), "request_id": api_request_id}
            )
        except AuthorizationError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"status": "AUTHORIZATION_DENIED", "error": str(e), "request_id": api_request_id}
            )
        except AuditPersistenceError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"status": "AUDIT_FAILURE", "error": str(e), "request_id": api_request_id}
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"status": "EXECUTION_FAILURE", "error": str(e), "request_id": api_request_id}
            )

    return app