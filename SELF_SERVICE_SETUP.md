# Self-Service Setup

This guide is the shortest path to run the threat intel dashboard and detection workbench without help.

For an Azure Linux VM deployment, use `AZURE_VM_WEBAPP.md`.

## Linux Quick Start

```bash
chmod +x setup.sh generate_digest.sh start_workbench.sh cleanup_workspace.sh
./setup.sh
./generate_digest.sh --days 7
./start_workbench.sh --host 0.0.0.0 --port 8765 --no-open
```

## Windows First-Time Setup

1. Open PowerShell in the project folder.

2. If scripts are blocked on your machine, allow scripts for this PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

3. Run setup:

```powershell
.\setup.ps1
```

4. Edit `.env` and set at least:

```text
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com
AZURE_OPENAI_KEY=your-api-key
AZURE_OPENAI_DEPLOYMENT=your-deployment-name
```

5. Check `company_profile.yaml` and update the organisation profile if needed.

## Weekly Use

Generate the latest threat digest:

```powershell
.\generate_digest.ps1
```

Start the browser workbench:

```powershell
.\start_workbench.ps1
```

The workbench opens at:

```text
http://127.0.0.1:8765/
```

From there you can:

- Review digest items.
- Generate disabled Sentinel analytic rule YAML drafts.
- Copy the YAML for manual review/use.

## Useful Commands

Generate a feed-only digest if the LLM is unavailable:

```powershell
.\generate_digest.ps1 -NoLlm
```

Generate a 14-day digest:

```powershell
.\generate_digest.ps1 -Days 14
```

Start the workbench on another port:

```powershell
.\start_workbench.ps1 -Port 8788
```

Run the workbench on an Azure VM interface:

```powershell
.\start_workbench.ps1 -HostName 0.0.0.0 -Port 8765
```

Before exposing it to other users, read `AZURE_VM_WEBAPP.md`.

Clean transient local files:

```powershell
.\cleanup_workspace.ps1
```

Clear generated reports as well:

```powershell
.\cleanup_workspace.ps1 -ClearOutput
```

Use the guided command-line menu:

```powershell
.\.venv\Scripts\python.exe -m secops ui
```

## Output Locations

- Latest digest: `output/threat_digest/index.html`
- Digest history: `output/threat_digest/history.html`
- Actor Watch: `output/actor_watch/index.html`
- Detection review page: `output/detections/index.html`
- Detection YAML drafts: `output/detections/drafts/YYYY-MM-DD/`

## Troubleshooting

If Python is not found, install Python 3.11 or newer and tick `Add python.exe to PATH`.

If dependency installation fails, rerun:

```powershell
.\setup.ps1
```

If the LLM call fails, check `.env` values and VPN/corporate certificate settings. You can still generate a feed-only digest with:

```powershell
.\generate_digest.ps1 -NoLlm
```
