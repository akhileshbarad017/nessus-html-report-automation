# 🛡️ Nessus HTML Report → Excel Automation

> *"Security fades. Attackers evolve. The only constant is the fight."*

A Python tool that converts **Nessus HTML scan reports** into professional, color-coded **Excel (.xlsx)** files — with risk-based styling, CVE mapping, CVSS scores, and sorted severity output.

Built during real-world **VAPT assessments** to replace hours of manual reporting with one command.

---

## 🚀 What It Does

- Parses one or multiple Nessus HTML reports
- Extracts: Vulnerability Name, Risk Factor, Affected IP:Port, CVSS v3.0, CVE IDs
- **Color-coded Excel output** by severity level
- Sorts findings: **CRITICAL → HIGH → MEDIUM → LOW**
- Merges multiple HTML files into one unified report

---

## 🎨 Color-Coded Output

| Risk Level | Color |
|---|---|
| 🔴 Critical | Dark Red `#91243E` |
| 🟠 High | Red `#DD4B50` |
| 🟡 Medium | Orange `#F18C43` |
| 🟢 Low | Yellow `#F8C851` |

---

## ⚙️ Installation

```bash
git clone https://github.com/akhileshbarad017/nessus-html-report-automation.git
cd nessus-html-report-automation
pip install -r requirements.txt
```

### Requirements
```
pandas
openpyxl
beautifulsoup4
lxml
```

---

## 💻 Usage

### Basic
```bash
python nessus_html_to_xlsx.py report.html output.xlsx
```

### Multiple HTML files merged
```bash
python nessus_html_to_xlsx.py report1.html report2.html output.xlsx
```

### Custom minimum risk
```bash
python nessus_html_to_xlsx.py report.html output.xlsx --min-risk high
```

### One row per host
```bash
python nessus_html_to_xlsx.py report.html output.xlsx --split-hosts
```

---

## 🔧 Options

| Flag | Default | Description |
|---|---|---|
| `--min-risk` | `medium` | Minimum risk: `critical`, `high`, `medium`, `low` |
| `--split-hosts` | Off | One row per affected host |

---

## 🧠 How It Works

```
Nessus HTML Report(s)
        ↓
BeautifulSoup Parsing
        ↓
Host + Plugin Extraction (IP, Risk, CVSS, CVE, Port)
        ↓
Deduplication + Severity Sorting
        ↓
Color-Coded Excel Report (openpyxl + pandas)
```

---

## ⚠️ Legal Disclaimer

> This tool is built for **authorized penetration testing and VAPT assessments only**.
> Use only on systems you have explicit written permission to test.
> Unauthorized use is illegal and unethical.

---

## 👤 Author

**Akhilesh Barad**
Penetration Tester | VAPT Analyst | Bug Bounty Hunter

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/akhilesh-barad-39091a3a1)

---

## ⭐ If this saved your time — give it a star! 
