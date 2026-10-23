# Automated Web Security Scanner

**Student:** Brithi  
**Program:** IBM SkillsBuild National Cybersecurity Bootcamp  
**Organization:** BharatCares (CSRBOX Group)

## Project description
This project is a lightweight Python command-line scanner for reviewing selected web security configuration signals. It sends a normal HTTP GET request to one user-supplied URL, follows redirects, checks whether the final URL uses HTTPS, reviews six common security response headers, notes the `Server` response header, and checks returned cookies for `Secure`, `HttpOnly`, and `SameSite` attributes. Results are saved as an HTML report and a JSON file with severity levels, evidence, and recommendations.

## Dataset
No dataset is required or used. This is a rule-based web configuration scanner, not a machine-learning project. The target website is provided at runtime. The recorded demonstration used `https://example.com`; results can vary between runs.

## Technologies used
- Python 3
- Requests library
- HTML/CSS for the report
- JSON for structured output
- Visual Studio Code and PowerShell

## Setup on Windows
Open this folder in VS Code and run the following commands in the terminal:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, you can use Command Prompt:
```bat
.venv\Scripts\activate.bat
```

## Run
```powershell
python Brithi_Automated_Web_Security_Scanner.py https://example.com --out demo_report
```

The command creates:
- `demo_report.html` — human-readable report to open in a browser
- `demo_report.json` — structured scan output

Only scan websites you own or have explicit permission to assess.

## Recorded demonstration result
The successful run shown during development reported HTTP status `200`, with 7 findings: 2 High, 2 Medium, 3 Low, and 0 Informational. These values describe that specific run only; a later run or different target may produce different results.

## Scope and limitations
This is a lightweight configuration review, not a penetration test. It does not exploit vulnerabilities, brute-force, crawl, or run intrusive tests. A missing header is not by itself proof of an exploitable vulnerability. It does not test authentication, authorization, business logic, injection flaws, or every OWASP risk. Findings require manual review and application context.

## References
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- Requests documentation: https://requests.readthedocs.io/
