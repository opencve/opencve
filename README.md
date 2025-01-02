<p align="center">
  <img alt="OpenCVE" src="https://raw.githubusercontent.com/opencve/opencve/v2/logo.png" width="400px;">
</p>
<p align="center">
  <a href="https://github.com/opencve/opencve/actions?query=workflow%3ATests"><img alt="Tests" src="https://github.com/opencve/opencve/workflows/Tests/badge.svg"></a>
  <a href="https://www.python.org/"><img alt="Python versions" src="https://img.shields.io/badge/python-3.10%2B-blue.svg"></a>
  <a href="https://github.com/python/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve1.png" width="350" height="215">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve2.png" width="350" height="215">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve3.png" width="350" height="215">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve4.png" width="350" height="215">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve5.png" width="350" height="215">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve6.png" width="350" height="215">
</p>

----------------

Try **for free** OpenCVE on [https://www.opencve.io](https://www.opencve.io) or check [documentation](https://docs.opencve.io) to install it yourself.

## What is OpenCVE

OpenCVE is a platform designed to help you **manage and monitor** the CVE database. It synchronizes the list of CVE (Common Vulnerabilities and Exposures) and allows you to **search, filter, and organize** them based on various criteria.

Users can **subscribe** to specific vendors or products and **receive notifications** when a new CVE is added or an existing one is updated. These notifications can be delivered via **Email or Webhook** (additional notification methods, such as **Slack**, are planned for future releases).

OpenCVE cross-references information from multiple reliable sources such as **MITRE**, **Vulnrichment**, **NVD**, and **RedHat**. This ensures that the vulnerability data remains accurate and up-to-date, even if one of the sources is temporarily unavailable.

## Features

- **Explore** the CVE database and filter the results by Vendor, Product, CVSS score or CWE
- **Subscribe** to vendors and products extracted from CPE
- **Organize** your subscription in your organizations and your projects
- **Invite** other members into your organizations
- **Be notified** for new CVE and for CVE updates based on subscriptions
- **Analyse** all CVE details (vendors, products, CVSS score, CPE, CWE, References...)
- **Create** custom tags (unread, important, devteam...) to organize the CVE list
- **Display** the history of each CVE and see their last changes in the homepage
- **Retrieve** the last changes in custom reports
- **Customize** the notification settings (type of change, filter by score...)
- **Integrate** OpenCVE with your own tools using the Webhook notification or the Rest API

You can use **for free** these features on the public instance: [https://www.opencve.io](https://www.opencve.io).

## How to Use OpenCVE

1. **Self-Hosted**: You can install and configure OpenCVE on your own server using Docker. This provides full control over your instance.
2. **SaaS Version**: Alternatively, you can use the hosted version of OpenCVE, available at [https://www.opencve.io](https://www.opencve.io). This option requires no setup and is ready to use out of the box.

You can explore the [documentation](https://docs.opencve.io) for detailed instructions like the installation, the notifications configuration or the API usage.
