import uuid
from asg.executor import ControlledToolExecutor
from asg.registry import ToolRegistry, ToolValidationError
from asg.policy import PolicyEvaluator
from asg.models import AuthorizationRequest, Effect
from asg.audit import AuditLogger, AuditRecord, AuditPhase, AuditPersistenceError

class AuthorizationError(PermissionError):
    """Raised when an authorization decision is DENY."""
    pass

class ASGGateway:
    """Mediates tool requests, enforcing validation, authorization, and audit."""
    
    def __init__(
        self,
        executor: ControlledToolExecutor,
        registry: ToolRegistry,
        principal_id: str,
        policy: PolicyEvaluator,
        audit_logger: AuditLogger,
    ) -> None:
        self.__executor = executor
        self.__registry = registry
        self.__principal_id = principal_id
        self.__policy = policy
        self.__audit_logger = audit_logger

    def execute_tool(self, tool_name: str, args: dict) -> list[dict]:
        request_id = str(uuid.uuid4())
        resource_id = args.get("table_name", "")

        # 1. Structural Validation
        try:
            self.__registry.validate(tool_name, args)
        except ToolValidationError as e:
            self._log_audit(request_id, tool_name, resource_id, AuditPhase.AUTHORIZATION, "DENY", f"Validation failed: {e}")
            raise

        # 2. Authorization
        auth_request = AuthorizationRequest(
            principal_id=self.__principal_id,
            action="read",
            resource_id=resource_id,
        )
        decision = self.__policy.evaluate(auth_request)
        
        self._log_audit(request_id, tool_name, resource_id, AuditPhase.AUTHORIZATION, decision.effect.value, decision.reason)
        
        if decision.effect == Effect.DENY:
            raise AuthorizationError(f"Authorization failed: {decision.reason}")
            
        # 3. Execution
        try:
            result = self.__executor.execute_tool(tool_name, args)
        except Exception as e:
            self._log_audit(request_id, tool_name, resource_id, AuditPhase.EXECUTION, "FAILURE", str(e))
            raise
            
        # 4. Strict Audit for Execution Success (Fail-Closed)
        try:
            self.__audit_logger.log(AuditRecord(
                request_id=request_id,
                principal_id=self.__principal_id,
                tool_name=tool_name,
                resource_id=resource_id,
                phase=AuditPhase.EXECUTION,
                outcome="SUCCESS",
                reason="Operation completed."
            ))
        except Exception as e:
            # This explicitly wraps any logger failure in AuditPersistenceError
            raise AuditPersistenceError(f"Audit logging failed, withholding result: {e}") from e
            
        return result

    def _log_audit(self, request_id: str, tool_name: str, resource_id: str, phase: AuditPhase, outcome: str, reason: str) -> None:
        """Attempts to log an audit record. Swallows audit failures for denial paths to preserve the original exception."""
        try:
            self.__audit_logger.log(AuditRecord(
                request_id=request_id,
                principal_id=self.__principal_id,
                tool_name=tool_name,
                resource_id=resource_id,
                phase=phase,
                outcome=outcome,
                reason=reason
            ))
        except Exception:
            pass