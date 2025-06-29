# AI-Powered Vulnerability Scanner

An automated vulnerability assessment tool that leverages AI agents to perform network scanning, exploit research, and generate professional security reports.

##  Project Overview

This project uses the CrewAI framework to orchestrate multiple AI agents that work together to:
- Execute Nmap vulnerability scans on target systems
- Search for available exploits using SearchSploit
- Generate comprehensive security assessment reports

Built as part of the Master's in Applied AI in Cybersecurity program, Module 4, Assignment 2.

##  Dependencies

### Core Requirements
- Python 3.12
- Docker (for running target applications)
- Nmap (network scanner)
- SearchSploit (exploit database search)
- Ollama with DeepSeek-r1:8b model

### Python Dependencies
```toml
crewai==0.98.0
python-dotenv>=1.0.0
lxml>=4.9.0
pydantic>=2.5.0
psutil>=5.9.0
setuptools>=68.0.0
```

##  Project Structure

```
03_vulnscan_05/
├── .env                    # Environment configuration
├── .gitignore             # Git ignore rules
├── pyproject.toml         # Project dependencies and metadata
├── README.md              # This file
├── src/                   # Source code
│   ├── __init__.py       # Package initializer
│   ├── main.py           # Application entry point
│   ├── crew.py           # AI agents and task definitions
│   └── tools/            # Tool implementations
│       ├── __init__.py   # Package initializer
│       └── scan_tools.py # Nmap and SearchSploit tools
├── outputs/              # Generated scan results (created at runtime)
│   ├── nmap_output.xml   # Nmap XML output
│   └── searchsploit_*.json # SearchSploit results
└── reports/              # Generated security reports (created at runtime)
    └── vulnerability_report_*.md # Final reports
```

##  Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/03_vulnscan_05.git
   cd 03_vulnscan_05
   ```

2. **Create and activate virtual environment**
   ```bash
   python3.12 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install uv
   uv pip install -e .
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env  # Edit with your configuration
   ```

##  Usage

1. **Ensure Docker containers are running**:
   - Ollama: `http://localhost:11434`
   - Target application (e.g., OWASP Juice Shop): `http://localhost:80`

2. **Run the scanner**:
   ```bash
   python src/main.py
   ```

3. **Enter the Nmap command when prompted**:
   ```
   nmap -sV --script vuln localhost -p 80 -oX outputs/nmap_output.xml
   ```

4. **View the generated report**:
   - Reports are saved in the `reports/` directory
   - The tool displays the report in the terminal and saves it as a markdown file

##  AI Agents

### 1. Network Security Scanner
- **Role**: Executes Nmap scans and identifies CVEs
- **Tools**: nmap_tool
- **Output**: List of discovered vulnerabilities

### 2. Exploit Research Specialist
- **Role**: Searches for exploits and generates security reports
- **Tools**: sploit_tool
- **Output**: Exploit analysis and comprehensive security assessment

##  Sample Output

The tool generates professional security reports including:
- Executive summary with risk overview
- Detailed CVE analysis with CVSS scores
- Available exploits and their impact
- Risk assessment matrix
- Prioritized remediation recommendations
- Technical appendices

##  Features

- **Automated Scanning**: AI-driven vulnerability detection
- **Exploit Correlation**: Automatic matching of CVEs to available exploits
- **Professional Reports**: Enterprise-grade security assessments
- **Flexible Architecture**: Easy to extend with new tools and agents
- **Real-time Output**: See scan progress and results as they happen

##  Security Notes

- Never scan systems without proper authorization
- The `.env` file contains sensitive configuration - do not commit it
- Use responsibly and ethically
- This tool is for educational and authorized testing only

##  License

This project is part of an academic assignment. Please refer to your institution's policies regarding code sharing and usage.

## 👤 Author

Carlos Val Souto  
carlosvalsouto@gmail.com
Master's in Applied AI in Cybersecurity Student  


## 🙏 Acknowledgments

- CrewAI framework for agent orchestration
- Nmap project for vulnerability scanning capabilities
- ExploitDB for the SearchSploit database
- OWASP for providing Juice Shop as a testing target
