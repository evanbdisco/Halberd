from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSGetSecretValue(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1555.006",
                technique_name="Credentials from Password Stores",
                tactics=["Credential Access"],
                sub_technique_name="Cloud Secrets Management Stores"
            )
        ]
        super().__init__(
            "Get Secret Value",
            "Retrieves a secret from AWS Secrets Manager. "
            "Simulates an attacker reading credentials, API keys, flags, or other sensitive values "
            "stored in Secrets Manager after obtaining sufficient IAM permissions.",
            mitre_techniques
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            secret_id: str = kwargs.get("secret_id", None)
            aws_region: str = kwargs.get("aws_region", "us-east-1")
            version_stage: str = kwargs.get("version_stage", None)

            if secret_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error": "Invalid Technique Input"},
                    "message": {"Error": "Invalid Technique Input"}
                }

            sm_client = boto3.client("secretsmanager", region_name=aws_region)

            get_kwargs = {"SecretId": secret_id}
            if version_stage not in [None, ""]:
                get_kwargs["VersionStage"] = version_stage

            raw_response = sm_client.get_secret_value(**get_kwargs)

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully retrieved secret: {secret_id}",
                    "value": {
                        "secret_name": raw_response.get("Name"),
                        "secret_arn": raw_response.get("ARN"),
                        "secret_string": raw_response.get("SecretString"),
                        "version_id": raw_response.get("VersionId"),
                        "created_date": str(raw_response.get("CreatedDate", "N/A"))
                    }
                }

            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata', 'N/A'),
                "message": f"Failed to retrieve secret: {secret_id}"
            }

        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to retrieve secret value"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to retrieve secret value"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "secret_id": {"type": "str", "required": True, "default": None, "name": "Secret ID or ARN", "input_field_type": "text"},
            "aws_region": {"type": "str", "required": False, "default": "us-east-1", "name": "AWS Region", "input_field_type": "text"},
            "version_stage": {"type": "str", "required": False, "default": None, "name": "Version Stage (e.g. AWSCURRENT)", "input_field_type": "text"}
        }
