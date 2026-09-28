# MailRakhwala

### Passive Email Security & Cryptographic Assessment Platform

**SIH26159 — SecureMailScope**

MailRakhwala is a passive network-security analysis platform designed to assess email communication captured in PCAP files. It analyzes observed email traffic, transport security, TLS/STARTTLS behavior, cryptographic parameters, and protocol evidence without modifying or actively probing the network.

The platform converts packet-level observations into an evidence-first security assessment, security findings, a posture score, and downloadable forensic reports.

---

## 1. Project Overview

Email security failures are often visible in network traffic through protocol behavior, plaintext communication, weak or missing transport protection, and TLS configuration.

MailRakhwala provides a workflow for:

- Uploading an email-related PCAP capture
- Identifying the observed email protocol
- Extracting relevant network and TLS evidence
- Detecting security weaknesses
- Mapping observations to security rules
- Calculating a security posture score
- Presenting findings through a web dashboard
- Generating forensic JSON and PDF reports

The application is intended for **passive forensic/security assessment** of captured traffic.

---

## 2. Core Analysis Pipeline

```text
PCAP File
   ↓
Upload & Analysis Job
   ↓
Packet / Stream Analysis
   ↓
Protocol Classification
   ↓
Email & TLS Evidence Extraction
   ↓
Security Rule Evaluation
   ↓
Findings & Deductions
   ↓
Security Posture Score
   ↓
Dashboard / Findings / Reports
```

The backend performs the security analysis and the frontend visualizes the resulting evidence.

---

## 3. Key Capabilities

### PCAP Analysis
- Upload packet captures for analysis
- Process analysis as a backend job
- Track analysis status
- Maintain an analysis/session identifier

### Email Protocol Analysis
The analysis pipeline can work with observed email protocols such as:

- SMTP
- IMAP
- POP3

Protocol classification uses protocol-specific evidence rather than treating generic authentication strings as sufficient proof of an email protocol.

### TLS / STARTTLS Assessment
The platform examines observed transport-security behavior, including:

- Whether TLS is present
- STARTTLS advertisement
- Whether an advertised upgrade was actually followed by encryption
- TLS version information when available
- Cipher-suite information when available
- Key-exchange information when available

### Evidence-First Findings
Findings are based on packet/stream observations. The application keeps technical evidence associated with security findings so that a result can be traced back to the observed traffic.

### Security Posture
The platform converts rule-based security deductions into a posture score.

The score is calculated from the backend analysis rather than being independently invented by the frontend.

### Reports
The application provides:

- Interactive dashboard
- Detailed findings
- Security posture analysis
- JSON forensic report
- PDF forensic report

---

## 4. Application Workflow

```text
1. Open MailRakhwala
        ↓
2. Choose a PCAP or run the demo PCAP
        ↓
3. Backend creates an analysis job
        ↓
4. PCAP is analyzed
        ↓
5. Security Dashboard becomes available
        ↓
6. Review Stream Analysis
        ↓
7. Review Findings & CVEs
        ↓
8. Review Security Posture / Score Analysis
        ↓
9. Open Forensic Reports
        ↓
10. Export JSON or PDF report
```

Normal in-app navigation keeps the active analysis available.

Refreshing the main analysis pages starts a fresh capture flow by returning the user to the Home page.

---

## 5. Technical Architecture

```text
                    ┌──────────────────────┐
                    │      React / Vite    │
                    │      Frontend       │
                    └──────────┬───────────┘
                               │
                         REST API Calls
                               │
                    ┌──────────▼───────────┐
                    │       FastAPI        │
                    │       Backend        │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┼─────────────┐
                 │             │             │
          ┌──────▼─────┐ ┌────▼──────┐ ┌────▼─────────┐
          │ PCAP /     │ │ Protocol  │ │ TLS / Email  │
          │ Packet     │ │ Analysis  │ │ Evidence     │
          │ Analysis   │ │           │ │ Extraction   │
          └──────┬─────┘ └────┬──────┘ └────┬─────────┘
                 │             │             │
                 └─────────────┼─────────────┘
                               ▼
                    ┌──────────────────────┐
                    │ Compliance / Rule    │
                    │ Evaluation Engine     │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │ Findings + Posture   │
                    │ Score + Evidence     │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │ Dashboard / Reports  │
                    └──────────────────────┘
```

---

## 6. Frontend Modules

### Home
Entry point for:

- PCAP upload
- Demo PCAP
- Demo video
- Documentation

### Dashboard
Provides:

- Security posture overview
- Score analysis
- Key findings
- Report access
- Analysis navigation

### Stream Analysis
Displays observed communication and security information such as:

- Protocol
- TLS state
- STARTTLS behavior
- Cipher suite
- Key exchange
- Stream information

### Findings & CVEs
Provides detailed security findings with:

- Severity
- Finding description
- Evidence
- Status
- Related security information

### Forensic Reports
Provides access to generated analysis reports and report export.

### Documentation
Contains the project's technical and user-facing documentation inside the application.

---

## 7. Security Evaluation

MailRakhwala uses rule-based security evaluation over the evidence extracted from the capture.

A simplified posture calculation is:

```text
Starting Score = 100

Final Score = 100 - Total Security Deductions

Final Score is bounded between 0 and 100.
```

Each deduction contains information such as:

- Rule ID
- Security finding
- Penalty
- Observed value/evidence
- Explanation

For example, if a security rule detects an email communication weakness, the corresponding deduction contributes to the final posture score.

The exact score shown to the user comes from the backend posture report.

---

## 8. Evidence & Findings

The application follows an evidence-first approach.

Instead of presenting only a generic warning, a finding can include:

```text
Finding
   ↓
Observed behavior
   ↓
Technical evidence
   ↓
Security rule
   ↓
Penalty / impact
   ↓
Posture score
```

This makes the result easier to inspect and explain during forensic analysis or a technical demonstration.

---

## 9. Passive Analysis Model

MailRakhwala is designed around passive observation.

It analyzes traffic that is already available in the supplied PCAP rather than actively connecting to or attacking the target mail server.

This allows the platform to assess:

- Observed protocol behavior
- Observed email communication
- Observed TLS negotiation
- Observed STARTTLS behavior
- Observed cryptographic parameters
- Security implications of the captured traffic

The quality of an assessment depends on the traffic and evidence contained in the supplied PCAP.

---

## 10. Technology Stack

### Frontend

- React
- Vite
- React Router
- Tailwind CSS
- Axios
- Lucide React

### Backend

- Python
- FastAPI
- Uvicorn
- PCAP / packet analysis components
- Rule-based compliance and posture evaluation

### Reporting

- JSON forensic reports
- PDF forensic reports

### Development

- Git
- GitHub
- VS Code

---

## 11. API Flow

The frontend communicates with the FastAPI backend through REST endpoints.

Typical flow:

```text
Frontend
   │
   ├── Upload PCAP
   │
   ▼
Backend Analysis Job
   │
   ├── Analyze capture
   │
   ├── Generate findings
   │
   └── Generate posture report
   │
   ▼
Frontend
   │
   ├── Dashboard
   ├── Stream Analysis
   ├── Findings
   └── Reports
```

Report endpoints include:

```text
GET /api/v1/analysis/{session_id}/report/json
GET /api/v1/analysis/{session_id}/report/pdf
```

---

## 12. Running Locally

### Backend

From the project root:

```powershell
cd backend
uvicorn app.main:app --reload --port 8001
```

The backend runs on:

```text
http://127.0.0.1:8001
```

### Frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

The Vite development server will provide the frontend URL shown in the terminal.

---

## 13. Frontend API Configuration

The frontend uses:

```text
VITE_API_URL
```

If the environment variable is not provided during local development, the application falls back to:

```text
http://127.0.0.1:8001
```

For deployment, the frontend should use the deployed backend URL through `VITE_API_URL`.

Example:

```text
VITE_API_URL=https://your-backend-domain
```

---

## 14. Project Structure

```text
MailRakhwala/
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── analysis.py
│   │   ├── compliance_engine.py
│   │   ├── protocol_classifier.py
│   │   └── ...
│   └── ...
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Home.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   ├── Analysis.jsx
│   │   │   ├── Findings.jsx
│   │   │   ├── Reports.jsx
│   │   │   └── Documentation.jsx
│   │   ├── services/
│   │   │   └── api.js
│   │   └── App.jsx
│   ├── public/
│   └── package.json
│
├── README.md
└── ...
```

---

## 15. Demo

The application includes a demo PCAP flow for demonstrating the analysis pipeline without requiring the user to prepare a capture manually.

The demo follows the same upload and backend-analysis workflow as a normal PCAP submission.

After the analysis completes:

```text
Try Demo PCAP
      ↓
Analysis Complete
      ↓
View Security Dashboard
      ↓
Dashboard → Analysis → Findings → Reports
```

---

## 16. Design Principles

### Evidence First
Security conclusions are connected to observed traffic evidence.

### Backend as the Source of Truth
Security findings and posture values originate from the backend analysis and rule evaluation.

### Passive Assessment
The platform analyzes captured traffic rather than actively probing the target.

### Explainable Results
The dashboard presents both plain-language explanations and technical evidence.

### Separation of Concerns

```text
Frontend
→ Presentation and user interaction

Backend
→ Analysis and security logic

Compliance Engine
→ Rule evaluation and deductions

Reports
→ Structured forensic output
```

---

## 17. Project Status

MailRakhwala currently provides a complete working prototype covering:

- PCAP upload
- Demo PCAP analysis
- Backend analysis jobs
- Email protocol analysis
- TLS / STARTTLS assessment
- Evidence extraction
- Rule-based security findings
- Security posture calculation
- Dashboard visualization
- Findings interface
- Forensic JSON reporting
- Forensic PDF reporting
- In-app documentation
- Git/GitHub version control

The project is structured so that future security rules and analysis capabilities can be added without redesigning the complete application.

---

## 18. Disclaimer

MailRakhwala is a security-analysis and forensic-assessment prototype intended for authorized use.

Results depend on the traffic captured in the supplied PCAP and the evidence available to the analysis pipeline. The platform should not be treated as a replacement for a complete enterprise security audit, incident-response investigation, or penetration test.

---

## 19. Team / Project

**Project:** MailRakhwala  
**Problem Statement:** SIH26159 — SecureMailScope  
**Category:** Cybersecurity / Network & Email Security

