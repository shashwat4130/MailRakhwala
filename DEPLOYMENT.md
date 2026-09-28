MailRakhwala — Deployment
Final Deployment Setup

We deployed MailRakhwala using:

GitHub → Render → Docker

What we did
The complete project was pushed to the main branch of GitHub.
We connected the GitHub repository to Render.
Render was configured as a Docker Web Service.
Render used the project's root Dockerfile.
The Docker image builds:
React frontend
FastAPI backend
Python dependencies
TShark
Security rules
Demo PCAP
The frontend and backend run together in the same container.
Render provides the public HTTPS URL.
The /health endpoint is used to verify that the backend is running.
The deployed application can then be tested through:
Home
Demo PCAP
Dashboard
Stream Analysis
Findings
Forensic Reports
Why Docker

Docker was used because MailRakhwala's PCAP analysis requires TShark. The Docker image packages TShark together with the backend and frontend, so the production environment has the required packet-analysis tools. This matches the deployment audit's verified architecture.

Final Architecture
GitHub
   ↓
Render
   ↓
Docker Container
   ├── React Frontend
   ├── FastAPI Backend
   ├── TShark
   ├── Security Rules
   └── Demo PCAP
   ↓
Live MailRakhwala
Deployment Verification

Before deployment, we verified:

Frontend production build
Backend tests
Docker configuration
TShark installation
PCAP processing
Demo PCAP availability
React routing
API communication
JSON/PDF reports
/health endpoint

The audit reports 597 backend tests passing and the production frontend build passing without errors.