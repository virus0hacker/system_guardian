# 🛡️System Guardian

**System Guardian** is a professional, real-time system monitoring and security analysis tool built in Python.  
It helps you detect suspicious system activity, analyze resource usage, and safely terminate risky processes — all locally and securely.

---

## ✨ Features :

- 🔍 **Live Process Monitoring**
  - Displays all active processes with PID, user, CPU%, RAM%, and status.
  - Auto-updates in real time.

- 🧠 **Smart Threat Analysis :**
  - Uses heuristic detection to identify potential threats:
    - ✅ Safe
    - ⚠️ Suspicious
    - 🚫 Dangerous

- ⚔️ **Process Control :**
  - Kill selected processes directly.
  - Auto-clean all suspicious or dangerous ones in one click.

- 📊 **Real-Time CPU & RAM Graph :**
  - Displays live CPU and memory usage (powered by `matplotlib`).

- 💾 **Export Reports :**
  - Save all analysis results as `.json` or `.csv` reports.

- 🌙 **Dark Modern GUI :**
  - Stylish black-and-green interface with professional typography.

---

## 🧰 Requirements :

Install dependencies before running:
```bash
pip install psutil matplotlib
```
---
🚀 How to Run:
---
---
Clone this repository :
---

```bash
git clone https://github.com/virus0hacker/system_guardian.git
```

---
Run the tool :
---

```bash
python system_guardian.py
```

---
Interface Overview :
---

Start Monitoring → Begin scanning live processes

Stop → Pause monitoring

Kill Selected → Terminate chosen process

Clean Suspicious → Automatically kill risky processes

Export Report → Save current scan as JSON/CSV


---
🧠 Example Output :
---

PID    Name            CPU%   Memory%   Status
1204   chrome.exe      8.2    12.4      Safe
2736   miner_x.exe     85.1   22.7      Dangerous
3140   unknown.exe     45.3   5.1       Suspicious


---
⚠️ Legal Disclaimer :
---

This software is 100% local and does not collect or send any data externally.
It is intended for personal system analysis, research, and educational use only.
Use responsibly — terminating critical system processes may cause instability.


---
MIT License :
---

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
(…standard MIT text continues…)




👤 Author

Developed by virus-hacker
🇸🇦 Saudi Developer — passionate about cybersecurity, privacy, and automation.
