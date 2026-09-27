# Network Security Monitor with AI-Assisted Anomaly Detection

A web-based network traffic monitoring system built to analyze PCAP/PCAPNG files, detect suspicious activity using rule-based methods, and provide AI-assisted anomaly detection results through a modern dashboard.

## Project Overview

This project was developed as an academic software solution for monitoring captured network traffic. It allows users to upload packet capture files, inspect protocol activity, view suspicious alerts, and review AI-based anomaly detection results in a clear and user-friendly interface.

The system supports:

- Network traffic analysis from **PCAP / PCAPNG** files
- Rule-based suspicious activity detection
- AI-assisted anomaly detection
- History tracking of previous analyses
- Security alerts management
- Admin dashboard with charts and statistics

---

## Key Features

### User Features
- Secure login system
- Upload network capture files
- Analyze traffic from PCAP / PCAPNG files
- View protocol statistics (TCP, UDP, ICMP, Other)
- Review packet details
- View AI anomaly prediction results
- Access analysis history
- Review generated security alerts

### Admin Features
- Dashboard with summary statistics
- Total analyses, packets, alerts, and anomalies
- Protocol distribution chart
- Alert severity chart
- Recent analysis records
- Overview of system activity

### Detection Features
- Rule-based detection of suspicious activity
- Alert severity classification (High / Medium / Low)
- AI-based anomaly scoring
- AI risk level display
- Capture-wise analysis tracking

---

## Technologies Used

- **Backend:** Python, Flask
- **Database:** SQLite
- **Frontend:** HTML, CSS, JavaScript, Jinja2
- **Charts / Visualization:** Chart.js
- **Packet Analysis:** PCAP / PCAPNG processing
- **AI / ML:** Feature extraction + anomaly detection model
- **Version Control:** Git & GitHub

---

## System Workflow

1. User logs into the system
2. User uploads a **PCAP / PCAPNG** file
3. The system analyzes the network traffic
4. Protocol statistics are generated
5. Rule-based checks detect suspicious behavior
6. AI model evaluates anomaly patterns
7. Results are stored in the database
8. User/Admin can review:
   - Analysis results
   - Packet details
   - Security alerts
   - Analysis history
   - Dashboard reports

---

## AI-Assisted Anomaly Detection

The system includes an AI-based anomaly analysis module that helps identify unusual traffic behavior.  
It generates:

- **Prediction** (Normal / Anomalous)
- **Anomaly Score**
- **Risk Level**

This improves the system by adding an intelligent layer on top of the traditional rule-based security checks.

> Note: The AI result is a prototype-based decision support feature and should be interpreted as an analysis aid, not as a final security judgment.

---

## Screenshots

### Login Page
![Login Page](Assets/screenshots/login.png)

---

### Network Analyzer / Upload Page
![Analyzer Page](Assets/screenshots/Analyzer%20page.png)

---

### Network Analysis Results

#### Traffic Statistics & AI Analysis
![Analysis Result](Assets/screenshots/Analyze%20result1.png)

#### Security Alerts
![Analysis Alerts](Assets/screenshots/Analyze%20result2.png)

#### Packet Details
![Packet Details](Assets/screenshots/Analyze%20result3.png)

---

### Analysis History
![Analysis History](Assets/screenshots/Analyze%20history.png)

---

### Security Alerts Page
![Security Alerts](Assets/screenshots/Analyze%20Alters.png)

---

### Admin Dashboard

#### Dashboard Overview
![Admin Dashboard Overview](Assets/screenshots/Admin%20dashboard1.png)

#### Protocol & Alert Charts
![Admin Dashboard Charts](Assets/screenshots/Admin%20dashboard2.png)

#### Recent Analyses
![Recent Analyses](Assets/screenshots/Admin%20dashboard3.png)
---

## Project Structure

```text
network-security-monitor/
│
├── assets/
│   └── screenshots/
│
├── static/
│   └── css/
│
├── templates/
│   ├── login.html
│   ├── index.html
│   ├── upload.html
│   ├── result.html
│   ├── history.html
│   ├── alerts.html
│   ├── dashboard.html
│   └── analysis_detail.html
│
├── training/
├── models/
├── uploads/
├── app.py
├── database.py
├── analyzer.py
├── detector.py
├── ai_detector.py
├── feature_extractor.py
├── requirements.txt
└── README.md