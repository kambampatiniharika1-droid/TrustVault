# TrustVault — Python, HTML & SQL Implementation

A secure document custody application built with **Python (Flask)**, **HTML5/Tailwind**, and **SQL (SQLite/MySQL)**.

---

## 🚀 How to Run in VS Code

### Step 1: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Run the Server
```bash
python app.py
```

### Step 3: Open in Browser
Open `http://localhost:5000` in your browser.

- The SQLite database (`trustvault.db`) and tables are initialized automatically using `schema.sql` on first launch.
- Use the identity bar at the top right to switch between **Alice (Admin)**, **Bob (Owner)**, **Carol (Owner)**, **David (Auditor)**, and **Eve (Suspicious)**.
