<p align="center">
  <img alt="OpenCVE" src="https://raw.githubusercontent.com/opencve/opencve/v2/logo.png" width="400px;">
</p>

<p align="center">
  <a href="https://github.com/opencve/opencve/actions?query=workflow%3ATests">
    <img alt="Tests" src="https://github.com/opencve/opencve/actions/workflows/tests.yml/badge.svg?branch=master">
  </a>
  <a href="https://www.python.org/">
    <img alt="Python versions" src="https://img.shields.io/badge/python-3.10%2B-blue.svg">
  </a>
  <a href="https://github.com/python/black">
    <img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg">
  </a>
</p>

## What is OpenCVE?

OpenCVE is a Vulnerability Intelligence Platform that helps you monitor and manage CVEs efficiently.

It aggregates vulnerabilities from multiple sources (MITRE, NVD, RedHat, Vulnrichment...) and lets you filter, track, and organize them by vendor, product, severity, and more.

You can subscribe to products, receive alerts, analyze changes, and collaborate with your team — all through a simple and powerful interface. Assign members to CVEs to track progress (e.g. under analysis, risk accepted) and keep everyone aligned.

<p align="center">
   <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve3.png" width="800" alt="OpenCVE Dashboards">
</p>

## Key Features

### 📚 Explore, Filter and Organize
- Filter CVEs by vendor, product, CVSS, KEV, EPSS, CWE, publication date, and more.
- Subscribe to vendors and products, and organize your monitoring with projects and organizations.
- Save complex filters as reusable Views.

### 🔖 Tag, Prioritize and Get Notified
- Classify CVEs with custom tags (e.g. unread, critical, assigned-to-dev).
- Assign users and statuses to CVEs to track progress (under analysis, risk accepted, etc.).
- Receive alerts instantly via email or webhook (Slack and Teams coming soon).

### 🔁 Track Changes and Generate Reports
- Access the complete change history of CVEs: scores, descriptions, references, etc.
- Generate daily reports by project to stay ahead.
- Get AI-powered report summaries to see priorities and immediate actions at a glance.

### 📊 Customize Your Dashboard
- Create multiple dashboards to organize your work the way you want.
- Build your own dashboard with widgets like "CVEs per project" or "Recent Reports".
- Drag, resize, and save layouts per organization.

### ✨ OpenCVE Enrichment
- Automatically associate CVEs with vendors, products, and affected versions.
- Advanced AI-powered analysis, including impact assessment and remediation insights, is available in OpenCVE Cloud.

## OpenCVE Community vs OpenCVE Cloud

OpenCVE is available as both a self-hosted Community edition and a hosted Cloud platform.

The Community edition allows you to track CVEs, organize your monitoring, and build your own workflows.

For teams that need more advanced capabilities, OpenCVE Cloud provides additional features such as:

- AI-powered CVE analysis and remediation insights
- Enterprise-grade security (SAML SSO, MFA enforcement)
- Managed, scalable infrastructure
- Advanced audit, SIEM & threat intelligence (coming soon)

👉 Learn more: [https://www.opencve.io/pricing](https://www.opencve.io/pricing)

## How to Use OpenCVE

### ✅ SaaS (Recommended)
Use the hosted version at [https://www.opencve.io](https://www.opencve.io) — no setup required, with access to advanced features and enterprise capabilities.

### 🐳 Self-Hosted
Run OpenCVE on your own infrastructure using Docker. See the [installation guide](https://docs.opencve.io/deployment/) for more details.

## Screenshots

<p align="center">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve1.png" width="350" height="215">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve2.png" width="350" height="215">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve3.png" width="350" height="215">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve4.png" width="350" height="215">
</p>

## Stay Updated

OpenCVE is actively developed and regularly improved.

⭐ Star this repository and 🔔 watch releases to be notified of future updates.

<p align="center">
   <img src="https://raw.githubusercontent.com/opencve/opencve/master/github-star-watch.gif" width="600" alt="How to Star and Watch the repository">
</p>

## License

OpenCVE Community is released under a Business Source License (BSL), allowing free usage with some limitations for commercial use.

See the [LICENSE](LICENSE) file for more details.
