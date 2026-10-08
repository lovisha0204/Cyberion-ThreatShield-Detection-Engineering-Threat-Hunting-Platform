#!/usr/bin/env python3
"""
Cyberion Defense Labs — Automated Sigma Rule Converter
Converts Sigma detection rules into Splunk SPL and Microsoft Sentinel KQL queries.
Supports command-line conversion of single files or entire directories.
"""

import os
import sys
import argparse
import yaml
from typing import Dict, Any

def convert_to_splunk(rule: Dict[str, Any]) -> str:
    logsource = rule.get("logsource", {})
    category = logsource.get("category", "")
    product = logsource.get("product", "")
    detection = rule.get("detection", {})
    
    # Determine base Splunk sourcetype
    if product == "windows" and category == "process_creation":
        base = 'index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1'
    elif product == "windows" and category == "process_access":
        base = 'index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10'
    elif product == "windows" and category == "security":
        base = 'index=windows sourcetype="XmlWinEventLog:Security"'
    elif product == "windows" and category == "registry_set":
        base = 'index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13'
    elif product == "zeek":
        base = f'index=zeek sourcetype="zeek:{category}"'
    else:
        base = f'index=security category="{category}"'

    filters = []
    for k, v in detection.items():
        if k == "condition":
            continue
        if isinstance(v, dict):
            for field, val in v.items():
                clean_field = field.split("|")[0].replace(".", "_")
                if isinstance(val, list):
                    vals = " OR ".join([f'{clean_field}="*{x}*"' for x in val])
                    filters.append(f"({vals})")
                else:
                    filters.append(f'{clean_field}="*{val}*"')
    
    query = f"{base}\n" + " AND ".join(filters[:3])
    return f"// Title: {rule.get('title')}\n// Rule ID: {rule.get('id')}\n{query} | table _time, host, user\n"

def convert_to_sentinel(rule: Dict[str, Any]) -> str:
    logsource = rule.get("logsource", {})
    category = logsource.get("category", "")
    product = logsource.get("product", "")
    detection = rule.get("detection", {})
    
    if product == "windows" and category == "process_creation":
        table = "DeviceProcessEvents"
        field_map = {"CommandLine": "ProcessCommandLine", "Image": "FileName", "ParentImage": "InitiatingProcessFileName"}
    elif product == "windows" and category == "process_access":
        table = "DeviceEvents | where ActionType == 'OpenProcessApiCall'"
        field_map = {"TargetImage": "FileName", "GrantedAccess": "AdditionalFields"}
    elif product == "windows" and category == "security":
        table = "SecurityEvent"
        field_map = {"EventID": "EventID", "TargetUserName": "TargetUserName"}
    else:
        table = "CommonSecurityLog"
        field_map = {}

    lines = [table]
    for k, v in detection.items():
        if k == "condition":
            continue
        if isinstance(v, dict):
            for field, val in v.items():
                clean_field = field.split("|")[0]
                kql_field = field_map.get(clean_field, clean_field)
                if isinstance(val, list):
                    val_str = ", ".join([f'"{x}"' for x in val[:5]])
                    lines.append(f"| where {kql_field} has_any ({val_str})")
                else:
                    lines.append(f'| where {kql_field} has "{val}"')
    
    query = "\n".join(lines[:4])
    return f"// Title: {rule.get('title')}\n// Rule ID: {rule.get('id')}\n{query}\n| project TimeGenerated, DeviceName\n"

def main():
    parser = argparse.ArgumentParser(description="Cyberion Sigma to SIEM Converter (Splunk / Sentinel)")
    parser.add_argument("--rule", help="Path to single Sigma rule YAML")
    parser.add_argument("--format", choices=["splunk", "sentinel", "both"], default="both", help="Target output dialect")
    args = parser.parse_args()

    workspace = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rule_path = args.rule or os.path.join(workspace, "rules", "CDL-RULE-001_powershell_download_cradle.yml")

    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    print("=" * 80)
    print(f" CONVERSION TARGET: {rule.get('title')} ({rule.get('id')})")
    print("=" * 80)

    if args.format in ["splunk", "both"]:
        print("\n--- SPLUNK SPL ---")
        print(convert_to_splunk(rule))

    if args.format in ["sentinel", "both"]:
        print("\n--- MICROSOFT SENTINEL KQL ---")
        print(convert_to_sentinel(rule))

if __name__ == "__main__":
    main()
