import uuid
from fastapi import FastAPI, HTTPException, status, Depends, Request
from pydantic import BaseModel
from typing import Any

from asg.gateway import ASGGateway, AuthorizationError
from asg.registry import ToolRegistry, ToolValidationError
from asg.audit import AuditPersistenceError, AuditLogger
from asg.execution import ToolExecutor
from asg.policy import DeclarativePolicyEngine
from asg.auth import get_current_principal
from asg.broker import CredentialBroker

class ToolCallRequest(BaseModel):
    """OpenAI/LangChain compatible tool call payload."""
    tool_name: str
    arguments: dict[str, Any]

def create_app(
    executor: ToolExecutor,
    registry: ToolRegistry,
    policy: DeclarativePolicyEngine,
    audit_logger: AuditLogger,
    broker: CredentialBroker,
    asg_service_secret: str
) -> FastAPI:
    app = FastAPI(title="Agent Security Gateway API", version="3.0.0")

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
        request: Request,
        principal_id: str = Depends(get_current_principal),
    ):
        api_request_id = str(uuid.uuid4())

        auth_header = request.headers.get("authorization", "")
        user_token = (
            auth_header.split(" ", 1)[1].strip()
            if auth_header.lower().startswith("bearer ")
            else ""
        )

        # Instantiate gateway with the verified principal, broker, and service secret
        gateway = ASGGateway(
            executor=executor,
            registry=registry,
            principal_id=principal_id,
            policy=policy,
            audit_logger=audit_logger,
            broker=broker,
            asg_service_secret=asg_service_secret,
            user_token=user_token,
        )

        try:
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