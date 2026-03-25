# 🔐 SecureVault — OWASP-Hardened Flask Web Application

> **Cybersecurity Portfolio Project** | Built to demonstrate OWASP Top 10 defenses in a real Flask application.

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Flask](https://img.shields.io/badge/Flask-3.0-green) ![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red) ![JWT](https://img.shields.io/badge/Auth-JWT-orange)

---

## 🎯 Project Objective

Build a secure note-taking web application that demonstrates practical implementation of OWASP Top 10 security controls — not just talk about them, but actually code them.

---

## 🛡️ Security Controls Implemented

| OWASP ID | Risk | Defense Implemented |
|----------|------|---------------------|
| A01 | Broken Access Control | JWT tokens + role-based access (admin/user) + ownership checks |
| A02 | Cryptographic Failures | PBKDF2-SHA256 password hashing (bcrypt-grade), short-lived JWTs |
| A03 | Injection | SQLAlchemy ORM (parameterised queries — no raw SQL ever) |
| A03 | XSS | `bleach` input sanitisation strips all HTML from user input |
| A05 | Security Misconfiguration | CSP headers, HSTS, X-Frame-Options, X-XSS-Protection |
| A07 | Auth Failures | Rate limiting (flask-limiter), 5-strike account lockout (15 min) |
| A08 | Data Integrity | CSRF-safe session cookies (SameSite=Lax, HttpOnly) |

---

## 🗂️ Project Structure

```
secure-web-app/
├── app.py                  # Main Flask application + all security logic
├── requirements.txt
├── templates/
│   ├── base.html           # Shared layout
│   ├── login.html
│   ├── register.html
│   └── dashboard.html      # Notes CRUD + security status panel
└── security_events.log     # Auto-generated security event log
```

---

## ⚡ Quick Start

```bash
# 1. Clone and install
git clone https://github.com/YOUR_USERNAME/secure-web-app
cd secure-web-app
pip install -r requirements.txt

# 2. Run
python app.py

# 3. Open browser
# http://127.0.0.1:5000
# Demo credentials: admin / Admin@1234
```

---

## 🔍 Key Security Code Snippets

### SQL Injection Prevention (ORM)
```python
# VULNERABLE (never do this):
# user = db.execute(f"SELECT * FROM user WHERE username='{username}'")

# SECURE (parameterised via SQLAlchemy ORM):
user = User.query.filter_by(username=username).first()
```

### XSS Prevention
```python
from bleach import clean
def sanitize(text, max_len=500):
    return clean(str(text), tags=[], strip=True)[:max_len]
```

### JWT Authentication
```python
token = jwt.encode({
    'user_id': user.id,
    'exp': datetime.utcnow() + timedelta(hours=1)  # short-lived
}, app.config['SECRET_KEY'], algorithm='HS256')
```

### Account Lockout
```python
if user.failed_logins >= 5:
    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
```

---

## 🧪 Testing the Defenses

```bash
# Test rate limiting (should get 429 after 10 attempts):
for i in {1..15}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://localhost:5000/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}'
done

# Test SQL injection (should return 401, not expose data):
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1--","password":"anything"}'

# Check security headers:
curl -I http://localhost:5000/
```

---

## 📚 Skills Demonstrated

- Secure coding practices (OWASP Top 10)
- JWT authentication implementation
- Password hashing (PBKDF2/bcrypt)
- Input validation and sanitisation
- HTTP security headers (CSP, HSTS)
- Rate limiting and brute-force protection
- Security event logging
- RESTful API design

---

## 👨‍💻 Author

**Yash** | Final Year B.Tech CSE | DBATU Lonere  
Cybersecurity Enthusiast | SOC Analyst Aspirant  
🔗 [LinkedIn](https://linkedin.com/in/YOUR_PROFILE) | 📧 your@email.com
