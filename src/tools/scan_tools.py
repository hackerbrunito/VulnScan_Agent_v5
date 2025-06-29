"""
scan_tools.py
developed by = Carlos Val Souto
Vulnerability Scanning Tools for CrewAI Agents
This module provides tools for executing nmap scans and searching for exploits
"""

import subprocess
import json
import re
from pathlib import Path
from datetime import datetime
from lxml import etree
from typing import Any, Optional, Type
from pydantic import BaseModel, Field


class NmapToolInput(BaseModel):
    """Input schema for nmap tool"""
    command: str = Field(description="The complete nmap command to execute")


class SploitToolInput(BaseModel):
    """Input schema for searchsploit tool"""
    cves: str = Field(description="Comma-separated list of CVE identifiers to search")


class StructuredTool:
    """A simple tool structure that CrewAI can understand"""
    
    def __init__(self, name: str, description: str, func: callable, args_schema: Optional[Type[BaseModel]] = None):
        self.name = name
        self.description = description
        self.func = func
        self.args_schema = args_schema
    
    def run(self, *args, **kwargs):
        """Execute the tool function"""
        return self.func(*args, **kwargs)
    
    def __call__(self, *args, **kwargs):
        """Make the tool callable"""
        return self.run(*args, **kwargs)


def nmap_scan_function(command: str) -> str:
    """
    Execute 'nmap vulnerability scan' and extract CVEs from XML output.
    
    Args:
        command: Full nmap command (e.g., "nmap -sV --script vuln localhost -p 80 -oX outputs/nmap_output.xml")
        
    Returns:
        String containing found CVEs or status message
    """
    # Step 1: Create outputs directory if it doesn't exist
    outputs_dir = Path("outputs")
    outputs_dir.mkdir(exist_ok=True)
    
    # Step 2: Execute the nmap command
    print(f"\n  Executing: {command}")
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )
    
    # Step 3: Print the output for debugging
    print("\n Nmap Output:")
    print(result.stdout)
    if result.stderr:
        print("  Nmap stderr:", result.stderr)
    
    # Step 4: Find the XML file path from the command
    xml_match = re.search(r'-oX\s+(\S+)', command)
    if not xml_match:
        return "Error: No XML output file specified in command"
    
    xml_path = Path(xml_match.group(1))
    
    # Step 5: Wait a moment for file to be written
    import time
    time.sleep(1)
    
    # Step 6: Parse the XML file and extract CVEs
    if not xml_path.exists():
        return f"Error: XML file {xml_path} not found"
    
    print(f"\n Parsing XML file: {xml_path}")
    
    # Parse XML using lxml
    tree = etree.parse(str(xml_path))
    root = tree.getroot()
    
    # Step 7: Find all CVE references in the XML
    cves = set()
    
    # Search in all text content and attributes
    for element in root.iter():
        # Check element text
        if element.text:
            cve_matches = re.findall(r'CVE[-:]?\d{4}[-:]?\d{4,5}', element.text, re.IGNORECASE)
            for cve in cve_matches:
                normalized = cve.upper().replace(':', '-')
                cves.add(normalized)
        
        # Check all attributes
        for attr_value in element.attrib.values():
            cve_matches = re.findall(r'CVE[-:]?\d{4}[-:]?\d{4,5}', attr_value, re.IGNORECASE)
            for cve in cve_matches:
                normalized = cve.upper().replace(':', '-')
                cves.add(normalized)
        
        # Check script output in table elements
        if element.tag == "elem":
            for child in element:
                if child.text:
                    cve_matches = re.findall(r'CVE[-:]?\d{4}[-:]?\d{4,5}', child.text, re.IGNORECASE)
                    for cve in cve_matches:
                        normalized = cve.upper().replace(':', '-')
                        cves.add(normalized)
    
    # Step 8: Return results
    if cves:
        cve_list = sorted(list(cves))
        result_msg = f" Found {len(cve_list)} CVEs: {', '.join(cve_list)}"
        print(f"\n{result_msg}")
        return result_msg
    else:
        return " No CVEs found in the scan results"


def sploit_search_function(cves: str) -> str:
    """
    Search for exploits using searchsploit for given CVEs.
    
    Args:
        cves: Comma-separated list of CVE IDs
        
    Returns:
        JSON string with exploit information
    """
    # Step 1: Parse the CVE list from the input
    # Handle case where the CVE list comes with prefix
    if "Found" in cves and "CVEs:" in cves:
        # Extract CVEs from a string like "Found 2 CVEs: CVE-2011-3192, CVE-2005-3299"
        cves_part = cves.split("CVEs:")[1].strip()
        cve_list = [cve.strip() for cve in cves_part.split(',')]
    else:
        # Direct comma-separated list
        cve_list = [cve.strip() for cve in cves.split(',') if cve.strip()]
    
    if not cve_list:
        return json.dumps({"error": "No CVEs provided"})
    
    print(f"\n🔎 Searching exploits for {len(cve_list)} CVEs...")
    
    # Step 2: Create outputs directory
    outputs_dir = Path("outputs")
    outputs_dir.mkdir(exist_ok=True)
    
    # Step 3: Search for each CVE
    all_exploits = {}
    
    for cve in cve_list:
        print(f"\n  Searching {cve}...")
        
        # Execute searchsploit
        cmd = f"searchsploit --cve {cve} -j"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        
        # Step 4: Parse the JSON output
        if result.returncode == 0 and result.stdout:
            try:
                exploit_data = json.loads(result.stdout)
                
                if "RESULTS_EXPLOIT" in exploit_data:
                    exploits = exploit_data["RESULTS_EXPLOIT"]
                    if exploits:
                        all_exploits[cve] = [
                            {
                                "title": exp.get("Title", ""),
                                "path": exp.get("Path", ""),
                                "date": exp.get("Date", ""),
                                "type": exp.get("Type", ""),
                                "platform": exp.get("Platform", ""),
                                "port": exp.get("Port", ""),
                                "author": exp.get("Author", ""),
                                "edb_id": exp.get("EDB-ID", ""),
                                "codes": exp.get("Codes", ""),
                                "application": exp.get("Application", "")
                            }
                            for exp in exploits
                        ]
                        print(f"     Found {len(exploits)} exploits")
                    else:
                        all_exploits[cve] = "No exploits found"
                        print(f"     No exploits found")
                else:
                    all_exploits[cve] = "No results"
                    
            except json.JSONDecodeError:
                all_exploits[cve] = "Error parsing searchsploit output"
        else:
            all_exploits[cve] = "Searchsploit command failed or returned no output"
    
    # Step 5: Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = outputs_dir / f"searchsploit_results_{timestamp}.json"
    
    with open(json_path, 'w') as f:
        json.dump(all_exploits, f, indent=2)
    
    # Step 6: Return summary
    summary = {
        "total_cves_searched": len(cve_list),
        "cves_with_exploits": sum(1 for v in all_exploits.values() if isinstance(v, list)),
        "results": all_exploits,
        "json_file": str(json_path)
    }
    
    return json.dumps(summary, indent=2)


# Create tool instances that CrewAI can use
nmap_tool = StructuredTool(
    name="nmap_tool",
    description="Execute nmap vulnerability scan and extract CVEs from XML output. Pass the command as a string.",
    func=nmap_scan_function,
    args_schema=NmapToolInput
)

sploit_tool = StructuredTool(
    name="sploit_tool",
    description="Search for exploits using searchsploit for given CVEs. Pass comma-separated CVE IDs as a string.",
    func=sploit_search_function,
    args_schema=SploitToolInput
)