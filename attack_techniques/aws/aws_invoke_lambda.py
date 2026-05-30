from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
import json
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSInvokeLambdaFunction(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1648",
                technique_name="Serverless Execution",
                tactics=["Execution"],
                sub_technique_name=None
            )
        ]
        super().__init__(
            "Invoke Lambda Function",
            "Invokes an AWS Lambda function to execute attacker-controlled or scenario-defined serverless code. "
            "Useful for reaching VPC-gated resources (e.g., Secrets Manager endpoints, RDS, internal APIs) "
            "that are not directly reachable from outside the VPC.",
            mitre_techniques
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            function_name: str = kwargs.get("function_name", None)
            aws_region: str = kwargs.get("aws_region", "us-east-1")
            payload: str = kwargs.get("payload", None)

            if function_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error": "Invalid Technique Input"},
                    "message": {"Error": "Invalid Technique Input"}
                }

            lambda_client = boto3.client("lambda", region_name=aws_region)

            invoke_kwargs = {
                "FunctionName": function_name,
                "InvocationType": "RequestResponse",
                "LogType": "None"
            }

            if payload not in [None, ""]:
                try:
                    invoke_kwargs["Payload"] = json.dumps(json.loads(payload)).encode()
                except json.JSONDecodeError:
                    invoke_kwargs["Payload"] = payload.encode()

            raw_response = lambda_client.invoke(**invoke_kwargs)

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] < 300:
                function_error = raw_response.get("FunctionError")
                response_payload = {}
                if "Payload" in raw_response:
                    try:
                        response_payload = json.loads(raw_response["Payload"].read())
                    except Exception:
                        response_payload = {}

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully invoked Lambda function: {function_name}",
                    "value": {
                        "function_name": function_name,
                        "status_code": raw_response.get("StatusCode"),
                        "function_error": function_error,
                        "response_payload": response_payload
                    }
                }

            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata', 'N/A'),
                "message": f"Failed to invoke Lambda function: {function_name}"
            }

        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to invoke Lambda function"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to invoke Lambda function"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "function_name": {"type": "str", "required": True, "default": None, "name": "Function Name or ARN", "input_field_type": "text"},
            "aws_region": {"type": "str", "required": False, "default": "us-east-1", "name": "AWS Region", "input_field_type": "text"},
            "payload": {"type": "str", "required": False, "default": None, "name": "Invocation Payload (JSON)", "input_field_type": "text"}
        }
