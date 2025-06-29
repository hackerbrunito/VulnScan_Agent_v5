"""
main.py
developed by = Carlos Val Souto
Vulnerability Scanner Main Entry Point
This script orchestrates the AI-powered vulnerability scanning workflow
"""

import os
import sys
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Add src to Python path so imports work correctly
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.crew import VulnScanCrew


def create_directories():
    """
    Create necessary directories for outputs and reports
    """
    # Read directory names from environment or use defaults
    outputs_dir = Path(os.getenv("OUTPUTS_DIR", "outputs"))
    reports_dir = Path(os.getenv("REPORTS_DIR", "reports"))
    
    # Create directories if they don't exist
    outputs_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)
    
    print(f"✓ Output directory ready: {outputs_dir}")
    print(f"✓ Reports directory ready: {reports_dir}")
    
    return outputs_dir, reports_dir


def get_user_input():
    """
    Get the nmap command from the user
    
    Returns:
        str: The complete nmap command
    """
    print("\n" + "="*60)
    print("AI-Powered Vulnerability Scanner v5")
    print("="*60)
    print("\nThis tool will:")
    print("1. Execute your nmap command")
    print("2. Extract CVE vulnerabilities")
    print("3. Search for available exploits")
    print("4. Generate a comprehensive report")
    print("\n" + "-"*60)
    
    # Get the nmap command
    print("\nEnter the complete nmap command:")
    print("Example: nmap -sV --script vuln localhost -p 80 -oX outputs/nmap_output.xml")
    print()
    
    command = input("Command: ").strip()
    
    # Validate the command
    if not command:
        print("Error: No command provided")
        sys.exit(1)
    
    if "nmap" not in command:
        print("Error: Command must start with 'nmap'")
        sys.exit(1)
    
    if "-oX" not in command:
        print("Error: Command must include '-oX' for XML output")
        sys.exit(1)
    
    return command


def save_report(content: str, reports_dir: Path) -> Path:
    """
    Save the vulnerability report to a markdown file
    
    Args:
        content: The report content
        reports_dir: Directory to save reports
        
    Returns:
        Path: Path to the saved report
    """
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vulnerability_report_{timestamp}.md"
    filepath = reports_dir / filename
    
    # Save the report
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return filepath


def main():
    """
    Main execution function
    """
    # Step 1: Load environment variables
    load_dotenv()
    print("✓ Environment variables loaded")
    
    # Step 2: Create necessary directories
    outputs_dir, reports_dir = create_directories()
    
    # Step 3: Get user input
    nmap_command = get_user_input()
    
    # Step 4: Initialize and run the crew
    print("\n" + "="*60)
    print("Starting vulnerability scan...")
    print("="*60 + "\n")
    
    # Create the crew
    crew = VulnScanCrew()
    
    # Run the vulnerability scanning workflow
    print("--> Executing nmap scan...")
    result = crew.run(nmap_command)
    
    # Step 5: Save the report
    print("\n" + "="*60)
    print("Saving report...")
    print("="*60)
    
    report_path = save_report(str(result), reports_dir)
    print(f"\n--> Report saved to: {report_path}")

    # Step 6: Display the report
    print("\n" + "="*60)
    print("VULNERABILITY ASSESSMENT REPORT")
    print("="*60 + "\n")

    # Read and display the report
    with open(report_path, 'r', encoding='utf-8') as f:
        report_content = f.read()
        print(report_content)

    # Step 7: Display summary
    print("\n" + "="*60)
    print("Scan Complete!")
    print("="*60)
    print(f"\nReport saved to: {report_path}")
        
    # # Step 6: Display summary
    # print("\n" + "="*60)
    # print("Scan Complete!")
    # print("="*60)
    # print(f"\nReport location: {report_path}")
    # print("\nYou can view the report with:")
    # print(f"  cat {report_path}")
    # print("\nProject execution has finaized all processes")


if __name__ == "__main__":
    main()