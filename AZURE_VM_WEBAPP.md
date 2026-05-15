# Azure Linux VM Deployment Guide

This guide runs the SecOps Innovation workbench as a self-contained internal web app on an Azure Linux VM. After setup, day-to-day use is browser-only:

- Generate threat digests.
- Review generated reports.
- Generate disabled Sentinel analytic rule YAML drafts.
- Copy/paste YAML for manual review.

The current app is an internal workbench. Do not expose it anonymously to the public internet.

## Architecture

```text
User browser
  -> Azure NSG / VPN / trusted IP allowlist
  -> Linux firewall, if enabled
  -> SecOps Workbench on TCP 8765
  -> Python app
      -> public RSS / CISA feeds
      -> Azure OpenAI or Anthropic
      -> local output/ reports and detection drafts
```

Recommended first deployment:

- Ubuntu Server 22.04 LTS or 24.04 LTS.
- Private access over VPN, Bastion, or trusted corporate IP allowlist.
- Port `8765` exposed only to trusted source IPs.
- `systemd` keeps the workbench running after reboot.
- Secrets stay in `/opt/secops-innovation/.env`.

Useful Microsoft references:

- Azure NSG traffic filtering: https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works
- Manage Azure NSGs: https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group
- Azure Key Vault: https://learn.microsoft.com/en-us/azure/key-vault/
- Managed identities for VMs: https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-managed-identities-work-vm

## 1. Create The VM

Suggested VM baseline:

- Image: Ubuntu Server 24.04 LTS, or Ubuntu Server 22.04 LTS.
- Size: `Standard_B2s` for light use; `Standard_D2s_v5` if several users will generate reports.
- Disk: Standard SSD is fine for early internal use.
- Public IP: avoid if you can use VPN/private access. If public IP is required, restrict source IPs.
- Inbound ports:
  - SSH `22` only from your admin IP or via Bastion.
  - App `8765` only from trusted source IPs/VPN ranges.

## 2. Configure Azure Network Security Group

Create an inbound NSG rule for the web app only if remote users need browser access.

Recommended rule:

```text
Source: your corporate public IP range or VPN subnet
Source port ranges: *
Destination: VM private IP or Any
Destination port: 8765
Protocol: TCP
Action: Allow
Priority: 1010
Name: Allow-SecOps-Workbench-8765
```

Avoid:

```text
Source: Internet
Destination port: 8765
Action: Allow
```

## 3. SSH To The VM

From your workstation:

```bash
ssh <admin-user>@<vm-public-ip-or-private-dns>
```

Update the server:

```bash
sudo apt update
sudo apt upgrade -y
```

Install required OS packages:

```bash
sudo apt install -y git python3 python3-venv python3-pip curl
```

Optional, useful for PDF support and future reverse proxy:

```bash
sudo apt install -y nginx ufw
```

Confirm:

```bash
python3 --version
git --version
```

## 4. Create A Service User

Create a low-privilege user:

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin secops
```

Create the app directory:

```bash
sudo mkdir -p /opt/secops-innovation
sudo chown -R "$USER":"$USER" /opt/secops-innovation
```

## 5. Place The Project On The VM

If using Git:

```bash
cd /opt
git clone <your-repo-url> secops-innovation
cd /opt/secops-innovation
```

If copying files manually, copy the project into:

```text
/opt/secops-innovation
```

Then:

```bash
cd /opt/secops-innovation
```

## 6. Configure Secrets

Create `.env`:

```bash
cp .env.example .env
nano .env
```

Minimum Azure OpenAI values:

```text
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com
AZURE_OPENAI_KEY=your-key
AZURE_OPENAI_DEPLOYMENT=your-deployment-name
AZURE_OPENAI_API_VERSION=2024-12-01-preview
```

Optional:

```text
LLM_PROVIDER=openai
DIGEST_MAX_COMPLETION_TOKENS=16384
COMPANY_PROFILE=company_profile.yaml
```

Corporate TLS inspection:

```text
LLM_CA_BUNDLE=/opt/secops-innovation/certs/corp-root-ca.pem
```

Last resort only:

```text
LLM_SSL_VERIFY_DISABLE=true
```

Lock down `.env`:

```bash
chmod 600 .env
```

Do not commit `.env`.

## 7. Configure Company Profile

Edit:

```bash
nano company_profile.yaml
```

Make sure it reflects:

- Organisation name.
- Sector.
- Regions.
- Security tooling.
- Cloud estate.
- Priority threats.
- Intended audience.

## 8. Run Initial Setup

```bash
cd /opt/secops-innovation
chmod +x setup.sh generate_digest.sh start_workbench.sh cleanup_workspace.sh
./setup.sh
```

This will:

- Create `.venv`.
- Install Python dependencies.
- Create output folders.
- Create `.env` / `company_profile.yaml` from examples if missing.
- Compile-check the Python modules.

## 9. Generate A First Digest

Use feed-only mode first:

```bash
./generate_digest.sh --days 1 --no-llm
```

Then test LLM mode:

```bash
./generate_digest.sh --days 7
```

Expected outputs:

```text
output/threat_digest/index.html
output/threat_digest/history.html
output/threat_digest/latest.html
output/actor_watch/index.html
```

## 10. Run The Web App Manually

Start the workbench:

```bash
./start_workbench.sh --host 0.0.0.0 --port 8765 --no-open
```

From the VM:

```bash
curl http://127.0.0.1:8765/api/health
```

Expected:

```json
{
  "status": "ok",
  "service": "secops-workbench"
}
```

From your workstation:

```text
http://<vm-private-ip-or-dns>:8765/
```

Stop manual mode with `Ctrl+C`.

## 11. Optional Linux Firewall

If using UFW:

```bash
sudo ufw allow from <trusted-source-ip-or-cidr> to any port 8765 proto tcp
sudo ufw allow from <trusted-admin-ip-or-cidr> to any port 22 proto tcp
sudo ufw enable
sudo ufw status verbose
```

If Azure NSG already restricts access and UFW is not enabled, this step can wait. Defence in depth is still preferable.

## 12. Install Fire-And-Forget systemd Service

Set ownership:

```bash
sudo chown -R secops:secops /opt/secops-innovation
```

Install the service file:

```bash
sudo cp /opt/secops-innovation/secops-workbench.service.example /etc/systemd/system/secops-workbench.service
```

Review it:

```bash
sudo nano /etc/systemd/system/secops-workbench.service
```

Default service command:

```text
ExecStart=/opt/secops-innovation/.venv/bin/python -m secops web --host 0.0.0.0 --port 8765 --no-open
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable secops-workbench
sudo systemctl start secops-workbench
```

Check status:

```bash
sudo systemctl status secops-workbench --no-pager
curl http://127.0.0.1:8765/api/health
```

View logs:

```bash
sudo journalctl -u secops-workbench -f
```

After reboot, the workbench should start automatically.

## 13. Browser-Only Operating Workflow

Once systemd is running, users should not need shell access.

In the browser:

1. Open `http://<vm-private-ip-or-dns>:8765/`.
2. Choose the digest look-back window.
3. Press `Generate Digest`.
4. Wait for completion.
5. Review loaded digest items.
6. Select an item worth detecting.
7. Press `Generate Draft`.
8. Review generated YAML.
9. Copy YAML for manual Sentinel/detection-as-code review.

Generated outputs stay on the VM:

```text
output/threat_digest/
output/actor_watch/
output/detections/drafts/
```

## 14. Updating The App

Stop service:

```bash
sudo systemctl stop secops-workbench
```

Update source:

```bash
cd /opt/secops-innovation
sudo chown -R "$USER":"$USER" /opt/secops-innovation
git pull
./setup.sh
sudo chown -R secops:secops /opt/secops-innovation
```

Start again:

```bash
sudo systemctl start secops-workbench
curl http://127.0.0.1:8765/api/health
```

## 15. Backup And Retention

Back up:

```text
/opt/secops-innovation/.env
/opt/secops-innovation/company_profile.yaml
/opt/secops-innovation/Templates/AnalyticRuleGuide
/opt/secops-innovation/output/
```

Suggested retention:

- Keep digest HTML/Markdown for 90 days.
- Keep detection drafts until reviewed or moved into detection-as-code.
- Periodically archive `output/detections/drafts`.

Example backup:

```bash
sudo tar -czf /opt/secops-backup-$(date +%F).tgz \
  /opt/secops-innovation/.env \
  /opt/secops-innovation/company_profile.yaml \
  /opt/secops-innovation/Templates \
  /opt/secops-innovation/output
```

## 16. Troubleshooting

### App does not load remotely

Check local health on VM:

```bash
curl http://127.0.0.1:8765/api/health
```

If local works but remote does not:

- Check Azure NSG inbound rule.
- Check UFW/firewalld if enabled.
- Confirm service uses `--host 0.0.0.0`.
- Confirm you are using a reachable private IP/DNS.

Check listener:

```bash
sudo ss -ltnp | grep 8765
```

### systemd service does not start

```bash
sudo systemctl status secops-workbench --no-pager
sudo journalctl -u secops-workbench -n 100 --no-pager
```

Common fixes:

```bash
cd /opt/secops-innovation
./setup.sh
sudo chown -R secops:secops /opt/secops-innovation
sudo systemctl restart secops-workbench
```

### LLM generation fails

Check `.env`:

```bash
sudo -u secops cat /opt/secops-innovation/.env
```

Confirm:

- `AZURE_OPENAI_ENDPOINT`
- `AZURE_OPENAI_KEY`
- `AZURE_OPENAI_DEPLOYMENT`
- corporate CA bundle if required

Generate feed-only:

```bash
./generate_digest.sh --no-llm
```

### Port already in use

```bash
sudo ss -ltnp | grep 8765
```

Stop service or change port:

```bash
sudo systemctl stop secops-workbench
./start_workbench.sh --host 0.0.0.0 --port 8788 --no-open
```

## 17. Security Hardening Checklist

Before shared internal use:

- Restrict NSG source IPs.
- Use VPN/private access where possible.
- Avoid public anonymous exposure.
- Keep `.env` off source control.
- Rotate LLM keys periodically.
- Run as the `secops` service user.
- Enable VM patching and Defender for Cloud where available.
- Add HTTPS/reverse proxy before wider rollout.
- Add Entra ID authentication before broad internal use.

## 18. Optional Reverse Proxy / HTTPS

For broader internal access, put Nginx in front and terminate TLS.

Basic reverse proxy shape:

```nginx
server {
    listen 443 ssl;
    server_name secops-workbench.example.com;

    ssl_certificate /etc/ssl/certs/secops-workbench.crt;
    ssl_certificate_key /etc/ssl/private/secops-workbench.key;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

If using a reverse proxy, change the systemd service to bind to localhost:

```text
ExecStart=/opt/secops-innovation/.venv/bin/python -m secops web --host 127.0.0.1 --port 8765 --no-open
```

Then expose only Nginx on `443`.

## 19. Path To True SaaS

This VM deployment is the bridge. A true SaaS version should add:

- Entra ID sign-in.
- Role-based access control.
- Background job queue for long-running LLM tasks.
- Database-backed report/detection state.
- Azure Key Vault secret retrieval.
- Audit logs for report/rule generation.
- Container/App Service deployment.
- ADO integration for reviewed rules.

