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

