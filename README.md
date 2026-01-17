<div align="center">

# 🌐 VulnX Security Scanner

### **Real-time Port Analysis • Service Fingerprinting • Live Threat Intelligence**

A high-performance Python + Flask based security scanner that performs real-time port scanning, banner grabbing, severity scoring, threat mapping, and subdomain enumeration — all via a modern dark dashboard UI.

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Backend-black.svg)](https://flask.palletsprojects.com/)
[![Security](https://img.shields.io/badge/Security-Scanning-red.svg)](https://github.com/shubhushubhu99/vulnXscanner)
[![Status](https://img.shields.io/badge/Project-Live-brightgreen.svg)](https://vulnx-scanner-production.up.railway.app/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

### 🌎 [Live Demo](https://vulnx-scanner-production.up.railway.app/)

</div>

---

## 🚀 About VulnX

VulnX Scanner is a professional-grade **cybersecurity auditing tool** built using **Python + Flask**. It performs:

- ✔ Port scanning
- ✔ Banner grabbing
- ✔ Service detection
- ✔ Severity scoring
- ✔ Threat assessment
- ✔ AI-based analysis
- ✔ Subdomain enumeration
- ✔ Fully responsive UI

**Designed for:** Security analysts, penetration testers, red teams, researchers, and students.

---

## ⚙️ Features

### ⚡ High-speed Port Scan Engine
- Multi-threaded scanning
- Deep scan up to 1024 ports
- Common scan mode

### 🔍 Fingerprinting Engine
- Banner capture
- Web protocol detection
- Threat intelligence mapping

### 🤖 AI Model Analysis
- Attack vectors identification
- Security recommendations
- Exploit scenarios
- Severity scoring

### 🌐 Subdomain Finder
- DNS-based resolver
- Smart default list

### 🎨 UI / UX
- Dark theme design
- Modern card layout
- Terminal logs display
- Fully responsive layout

---

## 📂 Tech Stack

| Technology | Purpose |
|------------|---------|
| Python 3.9+ | Backend language |
| Flask | Web framework |
| Socket | Network communication |
| Multithreading | Concurrent scanning |
| HTML/CSS/JavaScript | Frontend |
| Jinja2 | Template engine |

---

## 📥 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/shubhushubhu99/vulnxscanner.git
cd vulnxscanner
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Configure Environment Variables
Set a strong secret key before starting the app:

**macOS/Linux**
```bash
export FLASK_SECRET_KEY="change_me_to_a_long_random_value"
```

**Windows (PowerShell)**
```powershell
$Env:FLASK_SECRET_KEY="change_me_to_a_long_random_value"
```

### 4️⃣ Run the Application
```bash
python src/app.py
```

### 5️⃣ Open in Browser
Navigate to:
```
http://127.0.0.1:5000
```

---

## 📚 Documentation

- 📖 [Project Overview](docs/overview.md)
- 🏗️ [Project Architecture](docs/architecture.md)

---

## 📁 Project Structure

```text
vulnXscanner/
│
├── src/
│   ├── app.py
│   └── core/
│       └── scanner.py
│
├── static/
│   ├── css/
│   │   └── main.css
│   └── js/
│       ├── main.js
│       └── scanner.js
│
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── history.html
│   └── subdomain.html
│
├── docs/
│   ├── overview.md
│   └── architecture.md
│
├── Config/
│   └── Procfile
│
├── Images/
├── Dockerfile
├── requirements.txt
├── CODE_OF_CONDUCT.md
└── README.md
```

---


<div align="center">

### 👤 Project Author
**Team SilentXploit**

### 💻 Lead Developer & Maintainer
**Shubham Yadav**

### 👥 Core Development Team
**Md Farhan** • **Uday Shankar Singh**

</div>

---

## 🤝 Contributing

We welcome contributions from the community! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before submitting pull requests.

For detailed contribution instructions, see [CONTRIBUTING.md](CONTRIBUTING.md)

---

## ⚠️ Ethical Use Policy

**VulnX Scanner** is designed for **authorized security testing only**. Users must:

- ✅ Obtain proper authorization before scanning any network
- ✅ Comply with all applicable laws and regulations
- ✅ Use the tool for legitimate security research and testing
- ❌ Never use for unauthorized access or malicious purposes

**Disclaimer:** The authors are not responsible for misuse of this tool.

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 📬 Contact & Support

- 🐛 [Report Issues](https://github.com/shubhushubhu99/vulnXscanner/issues)
- 💡 [Request Features](https://github.com/shubhushubhu99/vulnXscanner/issues/new)
- 📧 Contact: [Open an Issue](https://github.com/shubhushubhu99/vulnXscanner/issues)

---

<div align="center">

### ⭐ If you like this project, please give it a star on GitHub! ⭐

**Made with ❤️ by Team SilentXploit**

[Live Demo](https://vulnx-scanner-production.up.railway.app/) • [Documentation](docs/overview.md) • [Report Bug](https://github.com/shubhushubhu99/vulnXscanner/issues)

</div>