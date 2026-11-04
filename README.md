# 🛡️ AI Phishing Email Detection & Investigation Agent

An AI-assisted cybersecurity project that analyzes suspicious email files (`.eml`), identifies potential phishing indicators, calculates a deterministic risk score, and generates an investigation report.

## 📌 Project Overview

The AI Phishing Email Detection & Investigation Agent combines rule-based email analysis with Google's Gemini API to support phishing investigation.

The application extracts email information, analyzes sender details, URLs, message content, attachments, and email headers. It then calculates a risk score and uses Gemini to generate an evidence-based investigation report.

## ✨ Key Features

- **Email Parsing:** Extracts sender, recipient, subject, date, email body, URLs, and attachment filenames from `.eml` files.
- **Sender Analysis:** Identifies suspicious sender characteristics and potential brand impersonation.
- **URL Analysis:** Detects potentially suspicious URLs using heuristic checks.
- **Content Analysis:** Identifies suspicious phrases and social engineering indicators.
- **Attachment Analysis:** Flags potentially risky attachment extensions and double extensions.
- **Header Analysis:** Examines SPF, DKIM, DMARC, Reply-To, Return-Path, and Received headers.
- **IOC Extraction:** Extracts email addresses, domains, URLs, IP addresses, and attachment filenames.
- **Risk Scoring:** Calculates a deterministic risk score out of 100.
- **AI Investigation:** Uses Google Gemini to generate an evidence-based investigation report.
- **PDF Reporting:** Generates downloadable PDF investigation reports.
- **Streamlit Interface:** Provides an interactive interface for email analysis.

## 🏗️ System Architecture

```text
       Upload .eml File
              |
              v
         Email Parser
              |
              v
      Analysis Components
       /    |    |    \
  Sender   URL  Content Header
       \    |    |    /
              |
              v
       Attachment Analysis
              |
              v
         IOC Extraction
              |
              v
         Risk Engine
              |
              v
      Gemini Investigation
              |
              v
       PDF Report Generator
              |
              v
        Streamlit Interface
```

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Streamlit | Web application interface |
| Google Gemini API | AI-assisted investigation |
| Python Email Library | Email parsing |
| Regex | Indicator extraction |
| ReportLab | PDF report generation |
| Pytest | Automated testing |
| Git & GitHub | Version control |

## 📂 Project Structure

```text
AI_Phishing_Agent/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── src/
│   ├── parser/
│   ├── tools/
│   ├── scoring/
│   ├── llm/
│   └── report/
│
└── tests/
```

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd AI_Phishing_Agent
```

### 2. Create a virtual environment

Python 3.13 is the project's recommended environment.

```bash
python -m venv venv
```

### 3. Activate the environment

Windows Command Prompt:

```cmd
venv\Scripts\activate.bat
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Configure the Gemini API key

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your_gemini_api_key
```

Keep `.env` out of version control. Never publish your API key.

### 6. Run the application

```bash
python -m streamlit run app.py
```

The application will open in your browser.

## 🚀 How to Use

1. Launch the Streamlit application.
2. Upload an email file in `.eml` format.
3. Review the extracted email information.
4. Examine sender, URL, content, attachment, and header analysis.
5. Review the calculated risk score and extracted IOCs.
6. View the Gemini investigation report when the service is available.
7. Download the PDF investigation report.

## 📊 Risk Scoring Methodology

The deterministic risk engine calculates a score out of 100 using four categories.

| Category | Maximum Score |
|---|---:|
| Sender Analysis | 25 |
| URL Analysis | 25 |
| Content Analysis | 35 |
| Attachment Analysis | 15 |
| **Total** | **100** |

The score is heuristic-based and is not a probability of phishing.

## 🧪 Testing

Run the automated test suite:

```bash
python -m pytest -q
```

The current test suite contains 47 passing tests.

## ⚠️ Limitations

- Detection relies on heuristic rules and supplied email evidence.
- The application does not execute or detonate attachments.
- SPF, DKIM, and DMARC results depend on available email-header evidence.
- Gemini report generation depends on external API availability.
- A high risk score is not proof of malicious activity.
- The application is a portfolio-level investigation tool, not a replacement for a production email security platform.

## 🔮 Future Improvements

- Improve detection accuracy using additional test datasets.
- Expand suspicious domain and URL detection.
- Add more robust error handling and investigation logging.
- Improve report presentation and evidence traceability.

## 👨‍💻 Author

**Prasuna Sanapala**

Cybersecurity | Python | AI-assisted Threat Investigation

---

*This project was developed for educational and portfolio purposes.*