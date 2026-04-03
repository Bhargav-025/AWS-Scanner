# 🛡️ AWS Cloud Security Posture Manager (CSPM)

AWS Cloud Security Posture Manager is a lightweight, high-performance security scanner inspired by Prowler. Built for AWS environments, it identifies misconfigurations, security risks, and compliance gaps in real-time, providing actionable remediation steps for developers and cloud architects.

## 🚀 Features

- **Automated AWS Scanning:** Scans S3, IAM, and EC2 for common security pitfalls.
- **Real-time Compliance:** Tracks your infrastructure against industry-standard benchmarks.
- **Interactive Dashboard:** A modern, React-based UI with dark-theme optimization for clear visibility.
- **Single-Click Remediation:** Clear instructions for fixing identified vulnerabilities.
- **AWS-Focused:** Optimized specifically for AWS environments, removing multi-cloud bloat for faster performance.

## 🛠️ Tech Stack

- **Frontend:** React.js, Vite, CSS3 (Custom Dark Theme)
- **Backend:** Python (FastAPI / Boto3)
- **Environment:** WSL2 (Ubuntu), VS Code
- **Testing/Sandbox:** LocalStack (Local AWS Emulator) & AWS Educate

## 📸 Dashboard Preview

To be added soon

>

## 🏗️ Architecture

SkyScan uses a "Thin-Wrapper" architecture. The React frontend communicates with a Python-based engine that queries the AWS API (or LocalStack) via the Boto3 SDK.

## 🚦 Getting Started

### Prerequisites

- Python 3.10+
- Node.js & npm
- Docker (for LocalStack testing)
- AWS CLI

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Bhargav-025/AWS-Scanner.git
    cd AWS-Scanner
    ```

2.  **Setup Backend:**

    ```bash
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3.  **Setup Frontend:**

    ```bash
    cd ../frontend
    npm install
    npm run dev
    ```

## 🛡️ Security Benchmarks

Currently, SkyScan checks for:

- **S3:** Publicly accessible buckets and missing encryption.
- **IAM:** Users without MFA and weak password policies.
- **EC2:** Security groups with Port 22 (SSH) open to `0.0.0.0/0`.

## 📈 Roadmap

- [ ] Integration with AWS Security Hub.
- [ ] Exportable PDF Security Reports.
- [ ] Support for automated remediation scripts.

---

## **Contribution by Bhargav**
