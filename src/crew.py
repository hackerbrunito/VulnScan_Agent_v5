"""
crew.py
developed by = Carlos Val Souto
CrewAI Agent Configuration
Defines the AI agents, their tasks, and the crew orchestration
"""

import os
from crewai import Agent, Task, Crew
from crewai import LLM
from .tools.scan_tools import nmap_tool, sploit_tool


class VulnScanCrew:
    """
    Creates and manages the vulnerability scanning crew
    """
    
    def __init__(self):
        """Initialize the crew with agents and tasks"""
        # Step 1: Configure the LLM (Language Model)
        self.llm = LLM(
            model=os.getenv("MODEL_NAME", "ollama/deepseek-r1:8b"),
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        )
        
        # Step 2: No need to initialize tools - they're just functions
        
        # Step 3: Create the agents
        self.nmap_agent = self._create_nmap_agent()
        self.sploit_agent = self._create_sploit_agent()
        
        # Step 4: Define the tasks
        self.scan_task = self._create_scan_task()
        self.exploit_task = self._create_exploit_task()
        self.report_task = self._create_report_task()
        
        # Step 5: Create the crew
        self.crew = self._create_crew()
    
    def _create_nmap_agent(self) -> Agent:
        """
        Create the nmap scanning agent
        
        This agent specializes in:
        - Running network scans
        - Identifying vulnerabilities
        - Extracting CVE information
        """
        return Agent(
            role="Network Security Scanner",
            goal="Execute nmap scans and identify all CVE vulnerabilities in the target system",
            backstory="""You are an expert penetration tester with 15 years of experience 
            in network security. You specialize in using nmap to discover vulnerabilities 
            and have deep knowledge of CVE databases. You are meticulous in your scanning 
            and never miss a vulnerability.""",
            tools=[nmap_tool],
            llm=self.llm,
            verbose=True
        )
    
    def _create_sploit_agent(self) -> Agent:
        """
        Create the exploit research agent
        
        This agent specializes in:
        - Searching for exploits
        - Analyzing exploit databases
        - Correlating CVEs with available exploits
        """
        return Agent(
            role="Exploit Research Specialist",
            goal="""Generate enterprise-grade vulnerability assessment reports that provide:
            - Comprehensive technical analysis of each vulnerability with CVSS scoring
            - Clear business impact assessment and risk quantification
            - Detailed, actionable remediation steps with implementation timelines
            - Strategic recommendations aligned with security best practices
            - Evidence-based priority rankings that consider exploit availability and asset criticality
            Your reports must be suitable for technical teams, management, and compliance auditors.""",
            # goal="Find and analyze all available exploits for discovered CVEs",
                        
            backstory="""You are a Senior Security Analyst with over 20 years of experience in cybersecurity, 
            specializing in vulnerability assessment and penetration testing for Fortune 500 companies and 
            government agencies. You hold certifications including CISSP, CEH, and OSCP.
            

            Your expertise includes:
            - Deep knowledge of CVE databases and exploit development
            - Experience with MITRE ATT&CK framework and threat modeling
            - Proficiency in analyzing exploit code and understanding attack vectors
            - Track record of discovering zero-day vulnerabilities
            - Published research on vulnerability remediation strategies

            You've written hundreds of security reports for C-level executives, technical teams, and 
            compliance auditors. You understand the importance of balancing technical accuracy with 
            business impact analysis. Your reports have helped organizations prevent major breaches 
            and pass stringent security audits.

            You approach each vulnerability with a hacker's mindset but a defender's purpose, always 
            considering both the technical exploit details and the real-world implications for the 
            organization. You never underestimate a vulnerability and always provide actionable, 
            prioritized recommendations based on actual risk.""",
            
            # backstory="""You are a senior security researcher who specializes in exploit 
            # development and analysis. You have extensive experience with ExploitDB and 
            # other vulnerability databases. You excel at finding practical exploits and 
            # understanding their impact.""",
            tools=[sploit_tool],
            llm=self.llm,
            verbose=True
        )
    
    def _create_scan_task(self) -> Task:
        """
        Create the vulnerability scanning task
        
        This task:
        - Takes the nmap command from user
        - Executes the scan
        - Extracts CVE information
        """
        return Task(
            description="""Execute the nmap vulnerability scan using this command: {nmap_command}
            
            You must:
            1. Use the nmap_tool to run the exact command provided
            2. The tool expects the command as a direct string input
            3. Wait for the scan to complete fully
            4. The tool will parse the XML output and return all CVE identifiers found
            5. Verify that all CVEs are properly formatted (CVE-YYYY-NNNNN)
            6. Note any additional security findings even if they don't have CVE IDs

            IMPORTANT: Ensure you capture ALL vulnerabilities detected, including:
            - CVEs explicitly mentioned
            - Security misconfigurations
            - Version-specific vulnerabilities
            - Service banners that indicate vulnerable versions

            The quality of the final report depends on thorough initial scanning.""",
            # You must:
            # 1. Use the nmap_tool to run the exact command provided
            # 2. The tool expects the command as a direct string input
            # 3. Wait for it to complete
            # 4. The tool will automatically parse the XML output and return all CVE identifiers found
            
            # Be thorough and use the exact command provided.""",
            expected_output="A detailed list of all CVE identifiers found in the scan",
            agent=self.nmap_agent
        )
    
    def _create_exploit_task(self) -> Task:
        """
        Create the exploit search task
        
        This task:
        - Takes CVEs from the scan task
        - Searches for exploits
        - Analyzes the results
        """
        return Task(
            description="""Search for exploits for all CVEs found in the scan.

            You must:
            1. Take the complete CVE list from the previous task
            2. Use the sploit_tool with the CVEs as a comma-separated string
            3. For each CVE, note:
            - Total number of exploits found
            - Exploit types (local, remote, DoS, privilege escalation)
            - Exploit reliability and maturity
            - Whether Metasploit modules exist
            4. Analyze the severity based on exploit availability:
            - Public exploit = High risk
            - Multiple exploits = Critical risk
            - No exploit = Lower risk (but still important)
            5. Pay attention to exploit dates - newer exploits may indicate active development

            This information is crucial for risk prioritization in the final report.""",

            # description="""Search for exploits for all CVEs found in the scan.
            
            # You must:
            # 1. Take the CVE list from the previous task
            # 2. Use the sploit_tool with the CVEs as a comma-separated string
            # 3. The tool will search for exploits for each CVE using searchsploit
            # 4. Analyze and summarize which CVEs have available exploits
            
            # Provide details about each exploit found.""",
            expected_output="""A comprehensive 8-12 page vulnerability assessment report in markdown format that includes:
            - Executive summary with business impact analysis
            - Detailed technical analysis of each CVE with CVSS scores
            - Risk assessment matrix with quantified risk scores
            - Prioritized remediation roadmap with timelines and ownership
            - Technical appendices with exploit analysis
            - Professional formatting with tables, badges, and clear sections
            - Actionable recommendations suitable for both technical and executive audiences
            The report must be ready for immediate use in enterprise security programs.""",
            # expected_output="A comprehensive analysis of available exploits for each CVE",
            agent=self.sploit_agent,
            context=[self.scan_task]  # This task depends on scan_task results
        )
    
    def _create_report_task(self) -> Task:
        """
        Create the final report generation task
        
        This task:
        - Combines all findings
        - Creates recommendations
        - Generates the final report
        """
        return Task(
            description="""Generate a comprehensive enterprise-grade vulnerability 
            assessment report that meets professional security consulting standards.

            ## REPORT REQUIREMENTS:

            ### 1. EXECUTIVE SUMMARY (1-2 pages)
            - High-level overview of the security posture
            - Total vulnerabilities by severity (Critical/High/Medium/Low)
            - Key business risks identified
            - Top 3-5 priority recommendations
            - Compliance implications (PCI-DSS, HIPAA, SOC2, etc.)

            ### 2. DETAILED VULNERABILITY ANALYSIS
            For EACH CVE discovered, provide:

            #### Technical Details:
            - CVE ID and publication date
            - CVSS v3.1 Base Score with vector string
            - Affected components and versions
            - Attack vector and complexity
            - Authentication requirements
            - Confidentiality, Integrity, and Availability impact

            #### Exploit Analysis:
            - Number of public exploits available
            - Exploit maturity (Proof of Concept, Functional, or Weaponized)
            - Ease of exploitation
            - Known usage in the wild
            - Metasploit modules or automated tools available

            #### Business Impact:
            - Potential data exposure risk
            - Service availability impact
            - Regulatory compliance violations
            - Reputation damage potential
            - Financial loss estimates

            ### 3. RISK ASSESSMENT MATRIX
            Create a risk matrix considering:
            - CVSS Score
            - Exploit availability
            - Asset criticality
            - Environmental factors
            - Compensating controls

            Use this formula: Risk = (CVSS Score x Exploit Availability x Asset Value) / Mitigating Factors

            ### 4. DETAILED REMEDIATION ROADMAP

            For each vulnerability, provide:

            #### Immediate Actions (0-24 hours):
            - Emergency mitigation steps
            - Temporary workarounds
            - Monitoring requirements

            #### Short-term Fixes (1-30 days):
            - Patch deployment plan
            - Configuration changes
            - Testing requirements

            #### Long-term Improvements (30+ days):
            - Architecture changes
            - Process improvements
            - Security control enhancements

            ### 5. TECHNICAL APPENDICES

            Include:
            - Detailed exploit code analysis (where applicable)
            - Proof of concept scenarios
            - Network topology considerations
            - Dependencies and downstream effects

            ### 6. PRIORITIZED ACTION PLAN

            Rank all findings by:
            1. Exploitability (Has exploit: Critical, No exploit but vulnerable: High)
            2. Business impact (Critical systems: x2 multiplier)
            3. Remediation complexity (Easy fixes first for quick wins)

            Present as a table with columns:
            | Priority | CVE ID | Risk Score | Remediation Effort | Timeline | Owner | Status |

            ### FORMATTING REQUIREMENTS:
            - Use professional markdown formatting
            - Include severity badges (🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low)
            - Add visual separators between sections
            - Use tables for structured data
            - Include a table of contents
            - Number all sections and subsections

            ### TONE AND STYLE:
            - Professional but accessible
            - Avoid unnecessary jargon
            - Define technical terms on first use
            - Use active voice
            - Be specific and actionable
            - Include confidence levels for assessments

            ### DATA TO INCORPORATE:
            - Use the actual nmap scan results from the previous task
            - Include all exploit details from searchsploit
            - Reference the specific services and versions identified
            - Correlate vulnerabilities with the actual target (localhost:80)

            Remember: This report may be used for:
            - Board presentations
            - Compliance audits
            - Insurance assessments
            - Budget justifications
            - Legal documentation

            Make it comprehensive, accurate, and actionable.""",
            
            # description="""Generate a comprehensive vulnerability assessment report.
            
            # The report must include:
            # 1. Executive Summary
            # 2. List of all CVEs discovered
            # 3. Available exploits for each CVE
            # 4. Risk assessment for each vulnerability
            # 5. Detailed remediation recommendations
            # 6. Prioritized action items
            
            # Format the report in clear, professional markdown.""",
            expected_output="""A comprehensive 8-12 page vulnerability assessment 
            report in markdown format that includes:
            - Executive summary with business impact analysis
            - Detailed technical analysis of each CVE with CVSS scores
            - Risk assessment matrix with quantified risk scores
            - Prioritized remediation roadmap with timelines and ownership
            - Technical appendices with exploit analysis
            - Professional formatting with tables, badges, and clear sections
            - Actionable recommendations suitable for both technical and executive audiences
            The report must be ready for immediate use in enterprise security programs.""",
            
            # expected_output="A complete vulnerability assessment report in markdown format",
            agent=self.sploit_agent,  # The exploit agent has context from both scans
            context=[self.scan_task, self.exploit_task]
        )
    
    def _create_crew(self) -> Crew:
        """
        Create the crew that orchestrates all agents and tasks
        """
        return Crew(
            agents=[self.nmap_agent, self.sploit_agent],
            tasks=[self.scan_task, self.exploit_task, self.report_task],
            verbose=True
        )
    
    def run(self, nmap_command: str) -> str:
        """
        Execute the vulnerability scanning workflow
        
        Args:
            nmap_command: The complete nmap command to execute
            
        Returns:
            The final vulnerability report
        """
        result = self.crew.kickoff(inputs={"nmap_command": nmap_command})
        return result