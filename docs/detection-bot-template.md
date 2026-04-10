# Detection Bot — Sentinel scheduled rule template

The Detection Bot generates Microsoft Sentinel scheduled analytics rules that follow the YAML shape in `detection_bot/ScheduledRuleTemplate.yaml`, so outputs stay aligned with a git-managed rule posture.

## Template reference

- **Canonical template file:** `detection_bot/ScheduledRuleTemplate.yaml`
- **Generated rules:** `output/detection_bot/<TechniqueID>.kql`
- **Markdown copy:** `output/detection_bot/<TechniqueID>.md`

## CLI examples

```bash
python -m detection_bot T1078
python -m detection_bot T1078 --severity High
python -m detection_bot T1078 --data-sources "SigninLogs" "AuditLogs"
```

## What the generator fills in

- Full scheduled-rule YAML (query, schedule, tactics, `relevantTechniques`, entity mappings, incident settings, tags, etc.)
- Placeholder `id` (replace with a real GUID before production deploy)
- KQL under `query:` using sensible Sentinel table names for the technique

## After generation

1. Replace the zero GUID with a unique id (e.g. from guidgen).
2. Confirm `requiredDataConnectors` / tables match your workspace.
3. Ensure every column used in `entityMappings`, `customDetails`, and `alertDetailsOverride` is projected in the KQL.
4. Test in a non-production workspace before promoting.

For installation, configuration, and VPN/TLS notes, see the main [README.md](../README.md).
