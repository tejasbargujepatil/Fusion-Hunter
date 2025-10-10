
# 🔥 Fusion Hunter – AI-Powered Vulnerability Scanner

**Fusion Hunter** is an advanced AI-driven vulnerability scanning engine designed to **automatically detect, analyze, and learn** from security weaknesses across web applications.
It combines automated crawling, adaptive payload generation, and a self-learning engine to improve detection accuracy with every scan.

---

## 🚀 Features

* 🌐 **Smart Crawler** – Automatically discovers hidden endpoints and parameters.
* 🧠 **Adaptive Learning Engine** – Improves detection success rate with every test using reinforcement learning.
* 🧪 **Advanced Vulnerability Detection** – Detects SQLi, XSS, CSRF, SSRF, IDOR, Authentication Bypass, and more.
* 📊 **Real-Time Dashboard** – Visualizes scan progress, success rates, and vulnerability severity.
* 📁 **Report Generation** – Auto-generates scan reports (JSON/PDF) with remediation suggestions.
* 📚 **Per-Endpoint Strategy Optimization** – Tailors payload strategies for each endpoint.
* ☁️ **Database Integration** – Stores all scan results and reports for future reference.

---

## 🛠️ Tech Stack

* ⚛️ **Frontend**: React + TypeScript + Vite
* 🎨 **UI**: Tailwind CSS + shadcn-ui
* 🔙 **Backend**: FastAPI + SQLModel + Uvicorn
* 🗄️ **Database**: SQL  – can be replaced with PostgreSQL/MySQL
* 🤖 **Learning Layer**: UCB1 Bandit Algorithm + Adaptive Strategy Selection

---

## 📂 Project Structure

```
fusion-hunter/
├── frontend/                  # React frontend
│   ├── components/           # UI components
│   ├── pages/                # Main scanner & dashboard
│   └── ...
├── backend/                  # FastAPI backend
│   ├── app/
│   │   ├── main.py           # API & WebSocket server
│   │   ├── db.py             # Database config
│   │   ├── models.py         # Database models
│   │   └── routes.py         # API routes
│   └── ...
└── README.md
```

---

## 🧪 Run Locally

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/tejasbargujepatil/Fusion-Hunter
cd fusion-hunter
```

### 2️⃣ Install Frontend Dependencies

```bash
cd frontend
npm install
npm run dev
```

Frontend will start on [http://localhost:3000](http://localhost:3000)

### 3️⃣ Set Up Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate  # (Windows)
source .venv/bin/activate  # (macOS/Linux)

pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

Backend will start on [http://localhost:8080/docs](http://localhost:8080/docs)

---

## 📊 Example Use Case

1. Enter your **target URL** into the crawler.
2. Fusion Hunter will automatically start scanning endpoints.
3. Vulnerabilities are analyzed, scored, and stored in the database.
4. Generate a detailed security report with remediation guidance.

---

## 📈 Future Enhancements

* 🔐 Integrate with CI/CD pipelines for continuous security testing.
* 🤝 Add GitHub Actions for automated vulnerability scans on push.
* 📡 Enable remote scans across multiple targets concurrently.
* 📊 AI-driven vulnerability prediction based on historical data.

---

## 📜 License

This project is licensed under the **MIT License** – feel free to use and modify it.

---

