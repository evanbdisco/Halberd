# Halberd Maintenance Reference

This document is the single reference for maintaining Evan's fork of the [Halberd multi-cloud attack tool](https://github.com/evanbdisco/Halberd). The tool runs in a locally-built Docker container — **do not pull the upstream `ghcr.io` image**.

---

## Docker Setup

| Setting | Value |
|---|---|
| Container name | `halberd` |
| Image | `halberd:local` (locally built) |
| Port binding | `0.0.0.0:8050:8050` |
| Volume | `~/SecurityTools/halberd/:/app/data` |
| Restart policy | `unless-stopped` |
| UI | http://localhost:8050 |

### Full Rebuild

Run this sequence any time the image needs to be rebuilt from source:

```bash
cd ~/Documents/Halberd
docker build -t halberd:local .
docker stop halberd && docker rm halberd
mkdir -p ~/SecurityTools/halberd/{local,output,report}
docker run -d --name halberd \
  -p 0.0.0.0:8050:8050 \
  -v ~/SecurityTools/halberd/local:/app/local \
  -v ~/SecurityTools/halberd/output:/app/output \
  -v ~/SecurityTools/halberd/report:/app/report \
  --restart unless-stopped \
  halberd:local
```

The three mounts persist all state across `docker restart`:
- `local/` — AWS sessions (`aws_sessions.json`), MSFT tokens, app logs
- `output/` — exfil'd files, S3 downloads
- `report/` — execution reports

---

## Adding a New Technique

New techniques live in `attack_techniques/aws/` as individual Python files. Each file must define a class that inherits from `AttackTechniqueTemplate` and implements an `execute` method:

```python
class MyNewTechnique(AttackTechniqueTemplate):
    def execute(self, **kwargs) -> dict:
        # ... implementation ...
        return {"success": True, "message": "Description of result"}
```

After creating the file, register it in `attack_techniques/aws/__init__.py` — you need both an `import` statement and the class name added to `__all__`. Skipping either step will cause the technique to be invisible to the UI.

### Docker Workflow for New Techniques

Copy the file into the running container, then restart — **the restart is mandatory**:

```bash
docker cp <local_file> halberd:/app/attack_techniques/aws/<filename>.py
docker restart halberd
```

Without the restart, Python's `sys.modules` cache will silently serve the old code, which is a common source of confusion when testing a technique update.

To verify the import loaded correctly after restart:

```bash
docker exec halberd python -c "from attack_techniques.aws.<module> import <ClassName>; print('OK')"
```

---

## Custom Techniques

These five techniques were written for this fork and are not in the upstream repo.

| File | Class | MITRE ID | Notes |
|---|---|---|---|
| `aws_ssrf_imds_credential_theft.py` | `AWSSSRFIMDSCredentialTheft` | T1552.005 | Uses `requests.POST` with JSON body `{"url": "..."}` — **not** GET |
| `aws_ssh_imds_credential_theft.py` | `AWSSSHIMDSCredentialTheft` | T1552.005 | Must use `paramiko.RSAKey.from_private_key_file()` explicitly; paramiko 5.x fails on PKCS#1 RSA keys with the generic key loader |
| `aws_ssm_start_session.py` | `AWSSSMStartSession` | T1021.007 | Uses `DocumentName="AWS-StartInteractiveCommand"` |
| `aws_invoke_lambda.py` | `AWSInvokeLambdaFunction` | T1648 | — |
| `aws_get_secret_value.py` | `AWSGetSecretValue` | T1555.006 | — |

---

## Corp_Cloud_Breach Playbook

The playbook lives at `automator/Playbooks/Corp_Cloud_Breach.yml` and defines a 13-step end-to-end AWS attack chain. It targets the corp-cloud-breach firing range infrastructure — see the **Security Firing Range Setup** project for details on that infrastructure.

To run it, open the **Automator** tab in the Halberd UI at http://localhost:8050 and select the playbook from the list.

---

## Common Issues

**Technique not found in Automator** — You forgot `docker restart halberd` after `docker cp`. The container is serving cached module state. Restart and check again.

**ImportError on restart** — There's a syntax error in the technique file. Check `docker logs halberd` to see the traceback and fix the file before restarting again.

**SSRF step fails** — The SSRF technique relies on a proxy application on the target web server. Verify the `proxy-app` systemd service is running on that host.

**paramiko key error** — The generic paramiko key loader fails on PKCS#1 RSA keys in paramiko 5.x. The SSH IMDS technique must call `paramiko.RSAKey.from_private_key_file()` directly rather than using the generic key loader.

State directories are mounted from the Mac:

| Mount (host) | Mount (container) | Contents |
|---|---|---|
| `~/SecurityTools/halberd/local` | `/app/local` | sessions, credentials |
| `~/SecurityTools/halberd/output` | `/app/output` | exfil'd files, S3 downloads |
| `~/SecurityTools/halberd/report` | `/app/report` | execution reports |

**AWS session persistence** — `SessionManager` now saves all sessions to `/app/local/aws_sessions.json` whenever a session is created, activated, or removed. On the next container start, `Bootstrapper.initialize()` calls `SessionManager.load_from_disk()` which restores valid sessions and silently skips any whose temporary credentials have expired.

**Credential file:** `~/SecurityTools/halberd/local/aws_sessions.json` — plaintext, mode 0600. For long-lived IAM user keys this survives indefinitely. For temporary STS/IMDS credentials the token will be stale after the role's `MaxSessionDuration` (typically 1–6 h).

**`~/.aws` passthrough** — To use your Mac's local AWS profiles inside the container without entering keys through the UI, add `-v ~/.aws:/root/.aws:ro` to the docker run command. boto3 will fall back to the credential chain automatically. You still need to run `AWSEstablishAccess` once to register a named session in Halberd's `SessionManager` (which will then be persisted), but you can pass `profile_name` instead of explicit keys if you add profile support to that technique in the future.

---

## Day-to-day commands

```bash
# Check container health
docker ps --filter name=halberd
docker inspect --format='{{.State.Health.Status}}' halberd

# Tail logs
docker logs -f halberd

# Open a shell inside the container
docker exec -it halberd bash
```

---

## Rebuilding the image from source

The local image is tagged `halberd:local`. Build from the repo root (`~/Documents/Halberd`):

```bash
cd ~/Documents/Halberd

docker build -t halberd:local .
```

The Dockerfile is a multi-stage build (wheel-builder → azure-base → builder → final). It installs Azure CLI manually to work around the `trixie` → `bookworm` Debian codename mismatch.

To recreate the running container after a rebuild — use the Full Rebuild command above.

---

## Deploying technique file changes to a running container

**Critical:** Dash loads all technique modules at startup. Changing a `.py` file inside a running container will be visible in `docker exec` sessions, but the Automator engine runs from the cached import — changes have **no effect** until the container restarts.

```bash
# 1. Copy changed file(s) into the container
docker cp attack_techniques/aws/my_new_technique.py halberd:/app/attack_techniques/aws/

# 2. Copy the updated __init__.py
docker cp attack_techniques/__init__.py halberd:/app/attack_techniques/__init__.py

# 3. MANDATORY restart — without this the app runs the old bytecode
docker restart halberd

# 4. Verify the container came back healthy (~45 s)
docker inspect --format='{{.State.Health.Status}}' halberd
# should return: healthy
```

You can also copy an entire directory:

```bash
docker cp attack_techniques/aws/ halberd:/app/attack_techniques/aws/
docker cp attack_techniques/__init__.py halberd:/app/attack_techniques/__init__.py
docker restart halberd
```

Verify the technique is registered after restart by checking the Attack UI — it should appear in the AWS technique list.

---

## Adding a new technique module

### 1. Create the file

Place it in `attack_techniques/aws/` (or the appropriate cloud subdirectory). Use the naming convention `aws_<verb>_<noun>.py`. Copy an existing simple technique as a starting template — `aws_get_secret_value.py` or `aws_invoke_lambda.py` are the cleanest examples.

### 2. Class structure

Every technique must:

- Import from `..base_technique` and `..technique_registry`
- Decorate the class with `@TechniqueRegistry.register`
- Inherit from `BaseTechnique`
- Call `super().__init__(display_name, description, mitre_techniques)` — the display name is what appears in the UI
- Implement `execute(self, **kwargs) -> Tuple[ExecutionStatus, Dict[str, Any]]`
- Implement `get_parameters(self) -> Dict[str, Dict[str, Any]]`

Minimal skeleton:

```python
from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSMyNewTechnique(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1234",
                technique_name="Technique Name",
                tactics=["Tactic"],
                sub_technique_name=None  # or "Sub-technique Name"
            )
        ]
        super().__init__("My New Technique", "What it does.", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            my_param: str = kwargs.get("my_param", None)
            if my_param in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error": "Invalid Technique Input"},
                    "message": {"Error": "my_param is required"}
                }
            # ... do work ...
            return ExecutionStatus.SUCCESS, {
                "message": "Succeeded",
                "value": {"result": "..."}
            }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {"error": str(e), "message": "Failed"}
        except Exception as e:
            return ExecutionStatus.FAILURE, {"error": str(e), "message": "Failed"}

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "my_param": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "My Parameter",
                "input_field_type": "text"   # text | number | bool
            }
        }
```

### 3. Register in `__init__.py`

Add an import line to `attack_techniques/__init__.py`:

```python
from .aws.aws_my_new_technique import AWSMyNewTechnique
```

The `@TechniqueRegistry.register` decorator handles registry insertion at import time. The `__init__.py` import is what triggers that import.

### 4. Deploy

Follow the `docker cp` + `docker restart halberd` procedure above.

### 5. Session management in techniques that steal credentials

Techniques that acquire new IAM credentials should register them as a new Halberd session using `SessionManager` from `core.aws.aws_session_manager`:

```python
from core.aws.aws_session_manager import SessionManager

manager = SessionManager()
result = manager.create_session(
    session_name=session_name,
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    aws_session_token=token,      # omit for long-term keys
    region_name=aws_region
)
if set_as_active_session:
    manager.set_active_session(session_name)
```

Subsequent techniques in the same Automator playbook run will use whichever session is active at the time they execute.

---

## The 5 custom technique modules

These are not in the upstream Halberd repo. They live in `attack_techniques/aws/` and are registered in `attack_techniques/__init__.py`.

### AWSSSRFIMDSCredentialTheft (`aws_ssrf_imds_credential_theft.py`)

Exploits the SSRF proxy on the ACME web server to reach IMDSv1 and steal IAM role credentials.

- Sends `POST http://<web_server_ip>:<port>/proxy` with body `{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>"}`.
- **Must be POST, not GET** — the proxy app only handles `POST /proxy`.
- Parses `AccessKeyId`, `SecretAccessKey`, `Token` from the JSON response.
- Registers a new Halberd session and optionally sets it active.
- MITRE: T1552.007 (Credentials from Password Stores — Container API)

Key parameter: `port` defaults to `3000` (the proxy-app port on the ACME web server).

### AWSSSHIMDSCredentialTheft (`aws_ssh_imds_credential_theft.py`)

Proxy-jumps through the web server (bastion) into the app server over SSH, queries IMDSv1 locally, and steals credentials.

- Uses `paramiko` for the SSH tunnel chain.
- **Loads the key explicitly as `paramiko.RSAKey.from_private_key_file()`** — do not use `from_private_key_file` on the generic `PKey` class. Paramiko 5.x auto-detection tries Ed25519 first and throws `SSHException` on PKCS#1 RSA keys instead of falling through. The explicit RSAKey load is intentional and must be preserved.
- Automatically fixes key file permissions to `0600` if the file is world-readable (SSH rejects those).
- Relative `pem_key_path` values are resolved against `/app` (the container working dir).
- MITRE: T1021.004 (SSH), T1552.007

The `pem_key_path` fed by the Corp_Cloud_Breach playbook is the deterministic output path from the S3 exfil step: `output/s3_bucket_download/<bucket_name>/internal/ssh-keys/app-server.pem`.

### AWSSSMStartSession (`aws_ssm_start_session.py`)

Enumerates SSM-managed instances and optionally starts a session to a target instance.

- If `target_instance_id` is omitted, runs in discovery-only mode and returns all SSM-managed instances.
- When a target is given, calls `ssm:StartSession` with `AWS-StartInteractiveCommand` to generate the CloudTrail event (the actual interactive session isn't used — Halberd runs as a non-interactive agent).
- MITRE: T1021.007 (Cloud Services)

### AWSInvokeLambdaFunction (`aws_invoke_lambda.py`)

Invokes any Lambda function by name or ARN.

- Accepts an optional JSON payload string; non-JSON payloads are passed through as raw bytes.
- Returns the Lambda response payload and any `FunctionError` field.
- Used in the Corp_Cloud_Breach scenario to invoke `acme-flag-getter`, which is VPC-gated in the data subnet and reads Secrets Manager internally.
- MITRE: T1648 (Serverless Execution)

### AWSGetSecretValue (`aws_get_secret_value.py`)

Retrieves a secret from AWS Secrets Manager by name or ARN.

- Accepts an optional `version_stage` (e.g., `AWSCURRENT`).
- Returns the full secret string in the result output.
- Used as the final step of Corp_Cloud_Breach to generate the `secretsmanager:GetSecretValue` CloudTrail event.
- MITRE: T1555.006 (Cloud Secrets Management Stores)

---

## The Corp_Cloud_Breach playbook

**File:** `automator/Playbooks/Corp_Cloud_Breach.yml`

A 13-step end-to-end simulation of the ACME Corp AWS attack scenario. All credentials and IPs are hardcoded to the live infrastructure — update them after a `terraform destroy` + `terraform apply` cycle.

### What it does

| Stage | Steps | Description |
|---|---|---|
| 0 — Initial Access | 1 | Establish session using `acme-dev-ci` IAM keys found in the exposed `.git/config` |
| 1 — Cloud Recon | 2–6 | Enumerate IAM user info, EC2 instances, all S3 buckets; list and exfil the public bucket |
| 2 — SSRF + Private Bucket | 7–9 | SSRF through the web server IMDS → steal `acme-web-role` creds → enumerate + exfil the private bucket (downloads the app-server PEM key) |
| 3 — SSH Pivot + SSM | 10–11 | SSH proxy-jump web → app server → steal `acme-app-role` creds → SSM session to the data bastion |
| 4 — Flag Capture | 12–13 | Invoke `acme-flag-getter` Lambda → call `secretsmanager:GetSecretValue` directly on `acme-flag` |

### Values to update after a redeploy

After `terraform destroy` + `terraform apply`, the following values change and must be updated in `Corp_Cloud_Breach.yml`:

| Field | Step(s) | What to check |
|---|---|---|
| `access_key`, `secret` (acme-dev-ci) | 1 | `terraform output dev_ci_access_key_id` / `dev_ci_secret_access_key` |
| `bucket_name` (public) | 5, 6 | `terraform output public_bucket_name` |
| `web_server_ip` | 7, 10 | `terraform output web_server_public_ip` |
| `bucket_name` (private) | 8, 9 | `terraform output private_bucket_name` |
| `pem_key_path` | 10 | Derived from private bucket name: `output/s3_bucket_download/<private_bucket>/internal/ssh-keys/app-server.pem` |
| `target_host_ip` | 10 | `terraform output app_server_private_ip` |
| `target_instance_id` | 11 | `terraform output data_bastion_instance_id` |

Run `terraform output -json` from `tf/scenarios/corp-cloud-breach/` for all values at once.

### Running the playbook

In the Halberd UI at `http://127.0.0.1:8050`:

1. Automator → Browse Playbooks → Corp Cloud Breach → Load
2. Review the loaded steps
3. Execute

The playbook takes roughly 3–5 minutes end-to-end (built-in `Wait` delays between steps).

---

## Troubleshooting

### "The UI doesn't reflect my code change"

Python module caching. The Dash app imported all techniques at container start. Always `docker restart halberd` after any file change — `docker exec` will show the new code but the running process uses the cached import.

### SSRF step fails intermittently

The `proxy-app` systemd unit on the web server can flap if `node` isn't ready at boot. The unit has `Restart=always` and `RestartSec=5`. SSH to the web server and check:

```bash
systemctl status proxy-app
journalctl -u proxy-app -n 50
```

If dead, `sudo systemctl restart proxy-app`. The unit file is in `/etc/systemd/system/proxy-app.service`.

### SSH step fails with paramiko SSHException on the PEM key

Paramiko 5.x's auto-detection tries Ed25519 first. The technique explicitly loads the key as `paramiko.RSAKey` — if this is breaking, confirm the key file is actually RSA PKCS#1 format (`-----BEGIN RSA PRIVATE KEY-----`). The Terraform-generated key (`tls_private_key.app_ssh`) is always RSA 4096.

### SSH step fails with "Key file not found"

The private bucket exfil step (step 9) must complete successfully before step 10. Check `output/s3_bucket_download/` in the container:

```bash
docker exec halberd ls output/s3_bucket_download/acme-app-private-data-971950500244/internal/ssh-keys/
```

If the file is missing, re-run step 9 manually.

### Container unhealthy

The health check is `curl -f http://localhost:8050/`. If it fails repeatedly:

```bash
docker logs halberd | tail -50
```

Common causes: import error in a newly-added technique (check for syntax errors or missing `__init__.py` registration), or port conflict on the host.
