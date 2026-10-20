from asg.agent_runtime import run_agent
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.gateway import ASGGateway
from asg.registry import ToolRegistry, ToolSchema
from asg.policy import PolicyEvaluator
from asg.audit import AuditLogger, AuditRecord

class ConsoleAuditLogger(AuditLogger):
    """Simple logger that prints to standard output for the prototype."""
    def log(self, record: AuditRecord) -> None:
        print(f"[AUDIT] {record.phase} | {record.outcome} | {record.tool_name}:{record.resource_id} | {record.reason}")

def main() -> None:
    connection = create_mock_database()
    try:
        executor = ControlledToolExecutor(connection)
        
        registry = ToolRegistry()
        registry.register(
            "read_database",
            ToolSchema(
                required_args=frozenset({"table_name"}),
                resource_arg="table_name",
                allowed_resources=frozenset({"public_data", "restricted_data"})
            )
        )
        
        policy = PolicyEvaluator()
        audit_logger = ConsoleAuditLogger()
        
        gateway = ASGGateway(
            executor=executor,
            registry=registry,
            principal_id="user_1", 
            policy=policy,
            audit_logger=audit_logger
        )
        
        result = run_agent(gateway)
        print("Result:", result)
    finally:
        connection.close()

if __name__ == "__main__":
    main()