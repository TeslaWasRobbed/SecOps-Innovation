# Linux Self-Service Setup

This guide is the shortest path to run the threat intel dashboard and detection workbench on Linux without help.

For an Azure Linux VM deployment, use `AZURE_VM_WEBAPP.md`.

## Quick Start

```bash
chmod +x setup.sh generate_digest.sh start_workbench.sh cleanup_workspace.sh
./setup.sh
./generate_digest.sh --days 7
./start_workbench.sh --host 0.0.0.0 --port 8765 --no-open
```

## First-Time Setup

1. Open a shell in the project folder.

2. Run setup:

```bash
chmod +x setup.sh generate_digest.sh start_workbench.sh cleanup_workspace.sh
./setup.sh
```

3. Edit `.env` and set at least:

```text
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com
AZURE_OPENAI_KEY=your-api-key
AZURE_OPENAI_DEPLOYMENT=your-deployment-name
```

4. Check `company_profile.yaml` and update the organisation profile if needed.

## Weekly Use

Generate the latest threat digest:

```bash
./generate_digest.sh --days 7
```

Start the browser workbench:

```bash
./start_workbench.sh --host 0.0.0.0 --port 8765 --no-open
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

```bash
./generate_digest.sh --days 7 --no-llm
```

Generate a 14-day digest:

```bash
./generate_digest.sh --days 14
```

Start the workbench on another port:

```bash
./start_workbench.sh --host 0.0.0.0 --port 8788 --no-open
```

Run the workbench on an Azure VM interface:

```bash
./start_workbench.sh --host 0.0.0.0 --port 8765 --no-open
```

Before exposing it to other users, read `AZURE_VM_WEBAPP.md`.

Clean transient local files:

```bash
./cleanup_workspace.sh
```

Clear generated reports as well:

```bash
./cleanup_workspace.sh --clear-output
```

Use the guided command-line menu:

```bash
.venv/bin/python -m secops ui
```

## Output Locations

- Latest digest: `output/threat_digest/index.html`
- Digest history: `output/threat_digest/history.html`
- Actor Watch: `output/actor_watch/index.html`
- Detection review page: `output/detections/index.html`
- Detection YAML drafts: `output/detections/drafts/YYYY-MM-DD/`

## Troubleshooting

If Python is not found, install Python 3.11 or newer with your Linux package manager.

If dependency installation fails, rerun:

```bash
./setup.sh
```

If the LLM call fails, check `.env` values and VPN/corporate certificate settings. You can still generate a feed-only digest with:

```bash
./generate_digest.sh --days 7 --no-llm
```
