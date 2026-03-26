# Detection Bot - ScheduledRuleTemplate.yaml Integration

## Overview

The Detection Bot now generates Microsoft Sentinel detection rules that strictly follow the `ScheduledRuleTemplate.yaml` structure. This ensures all generated rules are production-ready and consistent with organizational standards.

## Template Compliance

### Key Features Implemented:

1. **Complete YAML Structure**: All generated rules include the full template structure with proper metadata
2. **Standard Naming Convention**: Rules follow `[Tactic] Alert Name` format
3. **Production Metadata**: Includes all required fields for enterprise deployment
4. **Entity Mappings**: Proper entity mappings for Account, Host, IP, etc.
5. **Alert Customization**: Dynamic alert titles and descriptions
6. **Incident Configuration**: Standard grouping and suppression settings

### Template Fields Included:

- ✅ `id`: Placeholder GUID (needs manual replacement)
- ✅ `name`: Standardized format with tactic prefix
- ✅ `description`: Multi-line with management notice
- ✅ `enabled`: Always true for generated rules
- ✅ `status`: Set to "Available"
- ✅ `severity`: Configurable via CLI parameter
- ✅ `requiredDataConnectors`: Based on technique data sources
- ✅ `queryFrequency`/`queryPeriod`: Standard 1H/2H timing
- ✅ `query`: Production KQL with proper table references
- ✅ `triggerOperator`/`triggerThreshold`: Standard > 0 threshold
- ✅ `tactics`/`relevantTechniques`: From MITRE ATT&CK data
- ✅ `tags`: Standard organizational tags
- ✅ `entityMappings`: Contextual entity mappings
- ✅ `alertDetailsOverride`: Dynamic alert formatting
- ✅ `customDetails`: Key investigation fields
- ✅ `eventGroupingSettings`: SingleAlert aggregation
- ✅ `incidentConfiguration`: Standard incident handling
- ✅ `suppressionEnabled`: Disabled by default
- ✅ `version`: Semantic versioning (1.0.0)
- ✅ `kind`: Scheduled rule type

## Usage Examples

### Basic Rule Generation
```bash
python -m detection_bot T1078
```

### With Custom Severity
```bash
python -m detection_bot T1078 --severity High
```

### With Custom Data Sources
```bash
python -m detection_bot T1078 --data-sources "SigninLogs" "AuditLogs"
```

## Generated Rule Structure

Each generated rule follows this exact structure:

```yaml
id: 00000000-0000-0000-0000-000000000000  # ⚠️ Replace with unique GUID
name: "[InitialAccess] <Technique-specific name>"
description: |
  DO NOT EDIT IN PORTAL - MANAGED VIA GIT REPO.
  
  <AI-generated description of what the detection finds>
  <Explanation of why it matters and risk context>
  <Expected SOC analyst actions>

# ... (full template structure)

query: |
  // AI-generated KQL query using appropriate Sentinel tables
  // Includes proper column references for entity mappings
```

## Post-Generation Steps

After generating a rule, you should:

1. **Replace the GUID**: Generate a unique ID from guidgen.com
2. **Review the KQL**: Ensure the query logic matches your environment
3. **Validate Entity Mappings**: Confirm column names exist in query output
4. **Test the Rule**: Deploy to a test environment first
5. **Update Tags**: Modify category and ownership tags as needed

## File Locations

- **Template Reference**: `detection_bot/ScheduledRuleTemplate.yaml`
- **Generated Rules**: `output/detection_bot/<TechniqueID>.kql`
- **Documentation**: `output/detection_bot/<TechniqueID>.md`

## Benefits

- **Consistency**: All rules follow the same enterprise structure
- **Production-Ready**: Includes all metadata required for deployment
- **Maintainable**: Clear ownership and versioning information
- **Traceable**: Links back to MITRE ATT&CK techniques
- **Scalable**: Standardized format enables automation and bulk operations

The Detection Bot now generates rules that can be directly imported into your Sentinel workspace with minimal manual adjustments!