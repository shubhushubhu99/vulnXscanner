\# 🏗 Project Architecture



VulnX follows a simple and modular architecture centered around a Flask web application.



\## 🧩 High-Level Components



\### 1. Web Interface (Flask)

\- Handles user input and routing

\- Renders dashboard and results using HTML templates

\- Manages scan requests and responses



\### 2. Scanning Engine

\- Performs TCP port scanning using sockets

\- Supports common and deep scan modes

\- Uses multi-threading for performance



\### 3. Banner \& Service Detection

\- Identifies services running on open ports

\- Attempts banner grabbing where applicable

\- Maps services to known security risks



\### 4. Subdomain Enumeration Module

\- Resolves common subdomains via DNS lookups

\- Displays valid subdomains linked to a target domain



\## 🔄 Data Flow

User Input → Flask Routes → Scanner Logic → Analysis → UI Rendering



\## 🛠 Technologies Used

\- Python

\- Flask

\- Socket programming

\- Threading

\- HTML, CSS, JavaScript



This architecture keeps the system lightweight, extensible, and easy to understand for contributors.



