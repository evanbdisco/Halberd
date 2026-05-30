from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSSSMStartSession(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1021.007",
                technique_name="Remote Services",
                tactics=["Lateral Movement"],
                sub_technique_name="Cloud Services"
            )
        ]
        super().__init__(
            "SSM Start Session",
            "Pivots to an EC2 instance via AWS Systems Manager by starting an interactive session. "
            "Simulates lateral movement into a protected network subnet using SSM as a proxy. "
            "First enumerates SSM-managed instances, then attempts to start a session to the target.",
            mitre_techniques
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            target_instance_id: str = kwargs.get("target_instance_id", None)
            aws_region: str = kwargs.get("aws_region", "us-east-1")

            # Enumerate SSM-managed instances for discovery signal
            ssm_client = boto3.client("ssm", region_name=aws_region)
            managed_instances = []
            try:
                info_response = ssm_client.describe_instance_information()
                if 200 <= info_response['ResponseMetadata']['HTTPStatusCode'] < 300:
                    for item in info_response.get('InstanceInformationList', []):
                        managed_instances.append({
                            "instance_id": item.get('InstanceId'),
                            "platform": item.get('PlatformName'),
                            "ip_address": item.get('IPAddress'),
                            "ping_status": item.get('PingStatus')
                        })
            except ClientError:
                pass

            if target_instance_id in [None, ""]:
                # Discovery-only mode: just return the managed instances list
                return ExecutionStatus.SUCCESS, {
                    "message": f"Enumerated {len(managed_instances)} SSM-managed instances",
                    "value": {"managed_instances": managed_instances}
                }

            # Attempt SSM session start to generate CloudTrail ssm:StartSession event
            session_response = ssm_client.start_session(
                Target=target_instance_id,
                DocumentName="AWS-StartInteractiveCommand",
                Parameters={"command": ["echo pivot"]}
            )

            if 200 <= session_response['ResponseMetadata']['HTTPStatusCode'] < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully started SSM session to {target_instance_id}",
                    "value": {
                        "session_id": session_response.get("SessionId"),
                        "stream_url": session_response.get("StreamUrl"),
                        "token_value": session_response.get("TokenValue"),
                        "managed_instances_discovered": managed_instances
                    }
                }

            return ExecutionStatus.FAILURE, {
                "error": session_response.get('ResponseMetadata', 'N/A'),
                "message": f"Failed to start SSM session to {target_instance_id}"
            }

        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to start SSM session"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to start SSM session"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target_instance_id": {"type": "str", "required": False, "default": None, "name": "Target Instance ID", "input_field_type": "text"},
            "aws_region": {"type": "str", "required": False, "default": "us-east-1", "name": "AWS Region", "input_field_type": "text"}
        }
