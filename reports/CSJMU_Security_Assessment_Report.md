# CSJMU Web Infrastructure — Security Assessment Report

**Project:** Bug Bounty / Security Research  
**Target Organization:** Chhatrapati Shahu Ji Maharaj University (CSJMU), Kanpur  
**Primary Domain:** https://csjmu.ac.in/  
**Assessment Type:** Passive & Non-Destructive Security Testing  
**Report Date:** 14 June 2026  
**Researcher Role:** College Security Research / Bug Bounty  

---

## 1. Executive Summary

A security assessment was conducted on CSJMU's public web infrastructure, including the main university website and related subdomains. Testing focused on authentication bypass, information disclosure, misconfiguration, and attack surface mapping.

### Key Results

| Category | Count |
|----------|-------|
| Critical | 5 |
| High | 8 |
| Medium | 7 |
| Low | 4 |
| **Total Findings** | **24** |

### Overall Risk Rating: **CRITICAL**

No **instant login bypass** was achieved during testing (150+ advanced bypass attempts). However, multiple **critical misconfigurations** expose database administration interfaces, source code, and internal network details to the public internet. An attacker with sufficient time could chain these issues into full website compromise.

### Top 5 Critical Issues

1. phpMyAdmin publicly accessible on main and placement servers  
2. Adminer 4.8.1 publicly accessible on files server  
3. MySQL port 3306 exposed on multiple servers  
4. `.git` repository exposed on files.csjmu.ac.in  
5. Zero brute-force protection on database login panels  

---

## 2. Scope

### In-Scope Assets Tested

| Asset | URL / IP | Technology |
|-------|----------|------------|
| Main Website | https://csjmu.ac.in/ (103.224.48.77) | WordPress 6.7.4, PHP 7.4.33, Apache 2.4.53 |
| Placement Portal | https://placement.csjmu.ac.in/ (103.224.48.75) | WordPress 6.8.2, phpMyAdmin 5.2.1 |
| Files Server | https://files.csjmu.ac.in/ (103.224.48.72) | Adminer 4.8.1, exposed `.git` |
| Student Info System | https://sis.csjmu.ac.in/ (103.224.48.79) | Laravel/PHP, GIS API |
| ERP | https://erp.csjmu.ac.in/ | Web application login |
| Admission | https://admission.csjmu.ac.in/ | Payment / admission portal |
| AI Facility API | https://aifacility.tailf3dbcf.ts.net/api/chat | Unauthenticated API |

### Out of Scope / Not Performed

- Actual website defacement or data destruction  
- Large-scale password brute forcing (beyond small verification sets)  
- Exploitation after gaining credentials  
- Social engineering or physical attacks  

---

## 3. Methodology

1. **Reconnaissance** — Subdomain enumeration, technology fingerprinting, sitemap analysis  
2. **Configuration Review** — Exposed admin panels, directory listing, backup/config files  
3. **Authentication Testing** — Login bypass, session manipulation, default credentials (limited set)  
4. **API Testing** — REST/GraphQL endpoints, CORS, parameter fuzzing  
5. **Source Code Exposure** — `.git` repository analysis, error log review  
6. **Advanced Bypass Battery** — Header injection, path normalization, CVE probes, timing analysis  

**Total tests executed:** 200+ individual probes across 3 testing rounds.

---

## 4. Detailed Findings

---

### FINDING-01: phpMyAdmin Publicly Accessible

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL (CVSS ~9.8) |
| **Affected URLs** | https://csjmu.ac.in/phpmyadmin/ |
| | https://placement.csjmu.ac.in/phpmyadmin/ |
| **Status** | Confirmed |

**Description:**  
phpMyAdmin database administration interface is directly reachable from the public internet without IP restriction, VPN, or additional authentication layer.

**Steps to Reproduce:**
1. Open browser (no login required)
2. Navigate to `https://csjmu.ac.in/phpmyadmin/`
3. MySQL login form is displayed immediately

**Evidence:**
- HTTP 200 response with phpMyAdmin login page (~18KB)
- Version: phpMyAdmin 5.2.1 (placement server)
- JavaScript leaks configured username: `user:"root"`, `logged_in:false`

**Impact:**
- Full MySQL database access if password is guessed or leaked
- WordPress `wp_users` table compromise → admin account takeover
- Student/admission data exfiltration
- Website defacement via database content modification

**Remediation:**
1. Remove phpMyAdmin from public internet immediately
2. Restrict access via VPN or IP whitelist (office network only)
3. If remote access is required, use SSH tunnel
4. Never use `root` as the displayed/default MySQL user for phpMyAdmin

---

### FINDING-02: MySQL Port 3306 Publicly Exposed

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL (CVSS ~9.1) |
| **Affected IPs** | 103.224.48.75, 103.224.48.77, 103.224.48.72 |
| **Status** | Confirmed (earlier scans); intermittent timeout observed in later tests |

**Description:**  
MySQL database service accepts connections on TCP port 3306 from external networks, bypassing the web application entirely.

**Impact:**
- Direct offline password cracking against MySQL authentication
- Bypasses all web-layer security controls
- Combined with username leaks (`root`, `Ousr1`), attack surface is severe

**Remediation:**
1. Block port 3306 on firewall for all external traffic
2. Bind MySQL to `127.0.0.1` or internal interface only
3. Use strong, unique passwords and disable remote root login

---

### FINDING-03: Adminer 4.8.1 Publicly Accessible

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL (CVSS ~9.8) |
| **Affected URL** | https://files.csjmu.ac.in/adminer-4.8.1.php |
| **Status** | Confirmed |

**Description:**  
A second database administration tool (Adminer) is publicly accessible. This creates a redundant attack entry point even if phpMyAdmin is secured.

**Steps to Reproduce:**
1. Navigate to `https://files.csjmu.ac.in/adminer-4.8.1.php`
2. Database login form loads (HTTP 200)

**Impact:**
- Same as phpMyAdmin — full database compromise
- Adminer 4.8.1 has known CVEs (e.g., CVE-2021-21311, CVE-2021-43008)
- Attacker can try internal IP `192.168.1.221` as MySQL server

**Remediation:**
1. Delete Adminer from production server
2. Never deploy database tools in web-accessible directories

---

### FINDING-04: Exposed `.git` Repository

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL (CVSS ~8.6) |
| **Affected URL** | https://files.csjmu.ac.in/.git/ |
| **Status** | Confirmed |

**Description:**  
The web server's document root contains a fully exposed Git repository, leaking source code metadata and developer information.

**Exposed Files Verified:**
| File | Status | Content |
|------|--------|---------|
| `.git/HEAD` | 200 OK | `ref: refs/heads/main` |
| `.git/config` | 200 OK | Remote: `github.com:vikas-sonwani/admission2022.git` |
| `.git/logs/HEAD` | 200 OK | Commit history |
| `.git/COMMIT_EDITMSG` | 200 OK | `initial Commit` |
| `.git/refs/heads/main` | 200 OK | Commit hash exposed |

**Developer Information Leaked:**
- Name: `vikas-sonwani`
- Email: `vikassonwanipk@gmail.com`
- Repository: `admission2022` (admission system source code)

**Sensitive Files in Git Index (tracked in repo):**
- `configuration.php`
- `connect.php`
- `application-secret-code.php`
- `AtomAES.php`
- `change-password.php`
- `cb.php`

**Impact:**
- Full source code can be reconstructed via `git dump`
- Hardcoded database credentials, API keys, and encryption logic exposure
- Admission system logic and payment integration details leaked

**Remediation:**
1. Delete `.git` directory from web root: `rm -rf /var/www/html/.git`
2. Rotate ALL credentials that were ever committed to the repository
3. Add `.git` to web server deny rules
4. Audit GitHub repository access permissions

---

### FINDING-05: Zero Brute-Force Protection on phpMyAdmin

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL (CVSS ~8.2) |
| **Affected URLs** | phpMyAdmin on csjmu.ac.in and placement.csjmu.ac.in |
| **Status** | Confirmed |

**Description:**  
No rate limiting, CAPTCHA, account lockout, or IP blocking was observed after 50+ rapid failed login attempts. All requests returned HTTP 200.

**Test Evidence:**
```
10 rapid POST requests → [200, 200, 200, 200, 200, 200, 200, 200, 200, 200]
No HTTP 429 (Too Many Requests)
No HTTP 403 (Forbidden)
No CAPTCHA challenge
```

**Impact:**
- Unlimited password guessing against MySQL `root` account
- Combined with username leak, brute force is practical over time

**Remediation:**
1. Install fail2ban for phpMyAdmin login failures
2. Add Apache `mod_evasive` or `mod_security` rate limiting
3. Implement CAPTCHA after 3 failed attempts
4. Most importantly: remove public access entirely (see FINDING-01)

---

### FINDING-06: MySQL Username Leaked in phpMyAdmin JavaScript

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS ~7.5) |
| **Affected URL** | https://csjmu.ac.in/phpmyadmin/index.php |
| **Status** | Confirmed |

**Description:**  
The phpMyAdmin login page embeds the configured MySQL username in client-side JavaScript.

**Evidence:**
```javascript
CommonParams.setAll({..., user:"root", auth_type:"cookie", logged_in:false})
```

**Impact:**
- Attacker knows exact username for brute force (no enumeration needed)
- Reduces attack complexity significantly

**Remediation:**
1. Do not expose phpMyAdmin publicly
2. Configure phpMyAdmin to not pre-fill or expose usernames in JS

---

### FINDING-07: Database Username Leaked in Error Messages

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS ~7.5) |
| **Affected URL** | https://files.csjmu.ac.in/ (multiple PHP files) |
| **Status** | Confirmed |

**Description:**  
PHP application returns MySQL connection errors revealing internal username and host.

**Evidence:**
```
Connection failed: Access denied for user 'Ousr1'@'192.168.1.221' (using password: YES)
```

**Leaked Information:**
- Database username: `Ousr1`
- Internal MySQL host: `192.168.1.221`
- Confirms password authentication is in use

**Impact:**
- Second database username for targeted attacks
- Internal network topology disclosure

**Remediation:**
1. Disable `display_errors` in production PHP (`display_errors = Off`)
2. Use custom error pages
3. Log errors server-side only

---

### FINDING-08: phpinfo.php Publicly Accessible

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS ~7.5) |
| **Affected URL** | https://sis.csjmu.ac.in/phpinfo.php |
| **Status** | Confirmed |

**Description:**  
PHP configuration disclosure page is publicly accessible, revealing extensive server internals.

**Leaked Information:**
- PHP Version: 7.4.3 (End of Life — no security patches)
- Internal IP: `192.168.1.218`
- Document Root: `/var/www/html/sis.csjmu.ac.in/public`
- Loaded modules, environment variables, server paths

**Impact:**
- Enables targeted CVE exploitation for PHP 7.4.3
- Internal network mapping
- Assists further attacks with full server configuration knowledge

**Remediation:**
1. Delete `phpinfo.php` immediately
2. Block access via `.htaccess` or web server config
3. Upgrade PHP to supported version (8.2+)

---

### FINDING-09: SIS GIS API — No Authentication

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS ~7.5) |
| **Affected URL** | https://sis.csjmu.ac.in/api/getgisdata |
| **Status** | Confirmed |

**Description:**  
Student Information System GIS API returns ~48KB of data without any authentication token, API key, or session validation.

**Steps to Reproduce:**
```bash
curl -X POST https://sis.csjmu.ac.in/api/getgisdata
# Returns HTTP 200, ~48KB JSON data
```

**Additional Testing:**
- Empty JSON body → same 48KB response
- Fake admin tokens/parameters → same response
- No difference in output for any tested payload

**Impact:**
- Unauthorized access to geographic/student distribution data
- Potential PII exposure depending on data contents
- API abuse and scraping without restrictions

**Remediation:**
1. Implement API authentication (JWT/session tokens)
2. Add rate limiting
3. Validate and authorize requests server-side

---

### FINDING-10: CORS Misconfiguration on WordPress REST API

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS ~7.4) |
| **Affected URL** | https://csjmu.ac.in/wp-json/wp/v2/users |
| **Status** | Confirmed |

**Description:**  
The server reflects arbitrary `Origin` headers with credentials allowed.

**Evidence:**
```
Request:  Origin: https://evil.com
Response: Access-Control-Allow-Origin: https://evil.com
          Access-Control-Allow-Credentials: true

Request:  Origin: https://csjmu.ac.in.evil.com
Response: Access-Control-Allow-Origin: https://csjmu.ac.in.evil.com
          Access-Control-Allow-Credentials: true
```

**Impact:**
- If a logged-in admin visits attacker's page, their session data can be exfiltrated via cross-origin requests
- Enables CSRF-style data theft from authenticated users

**Remediation:**
1. Whitelist only legitimate origins (`https://csjmu.ac.in`)
2. Never reflect arbitrary Origin values
3. Set `Access-Control-Allow-Credentials` only for trusted origins

---

### FINDING-11: XML-RPC Enabled with Brute-Force Amplifier

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS ~7.3) |
| **Affected URL** | https://csjmu.ac.in/xmlrpc.php |
| **Status** | Confirmed |

**Description:**  
WordPress XML-RPC is active and supports `system.multicall`, allowing multiple login attempts in a single HTTP request.

**Evidence:**
```bash
# system.listMethods returns 4272 bytes — service is live
curl -X POST https://csjmu.ac.in/xmlrpc.php \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
```

**Impact:**
- WordPress admin password brute force at 100x+ speed via multicall
- DDoS amplification via pingback
- Bypasses per-request rate limiting

**Remediation:**
1. Disable xmlrpc.php: add to `.htaccess`:
   ```apache
   <Files xmlrpc.php>
       Order Deny,Allow
       Deny from all
   </Files>
   ```
2. Or block via WordPress security plugin

---

### FINDING-12: Internal Network Information Disclosure

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS ~6.5) |
| **Affected URL** | https://csjmu.ac.in/ (homepage source) |
| **Status** | Confirmed |

**Description:**  
Internal/private IP addresses and ERP URLs are exposed in public-facing HTML.

**Leaked Internal Assets:**
| Internal URL | Context |
|-------------|---------|
| `192.168.1.242/UniERP.*` | ERP system links on homepage |
| `192.168.1.218` | SIS server (via phpinfo) |
| `192.168.1.221` | MySQL server (via error messages) |

**Impact:**
- Internal network topology mapping for lateral movement
- Assists targeted attacks if attacker gains internal network access

**Remediation:**
1. Remove internal URLs from public HTML
2. Use public-facing proxy URLs for ERP links
3. Segment internal services on separate VLAN

---

### FINDING-13: Directory Listing Enabled

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (CVSS ~5.3) |
| **Affected URLs** | https://csjmu.ac.in/wp-includes/ |
| | https://csjmu.ac.in/wp-content/uploads/2024/ |
| | https://csjmu.ac.in/wp-content/uploads/2025/ |
| **Status** | Confirmed |

**Description:**  
Apache directory listing is enabled, exposing file names and directory structure.

**Impact:**
- Easier discovery of uploaded files, backups, and sensitive documents
- Assists reconnaissance for further attacks

**Remediation:**
```apache
Options -Indexes
```

---

### FINDING-14: WordPress Version & Plugin Disclosure

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (CVSS ~5.3) |
| **Affected URL** | https://csjmu.ac.in/ |
| **Status** | Confirmed |

**Description:**
- WordPress 6.7.4 detected (main), 6.8.2 (placement)
- Plugins identified: Jupiter theme, js_composer (WPBakery), various others
- `readme.html` and `license.txt` accessible (version disclosure)
- `wp-sitemap.xml` exposes 40+ content types and URL structure

**Impact:**
- Targeted exploitation of known plugin/theme CVEs

**Remediation:**
1. Remove `readme.html` and `license.txt` from web root
2. Hide WordPress version in theme
3. Keep all plugins updated; remove unused plugins

---

### FINDING-15: PHP 7.4 End-of-Life on All Servers

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (CVSS ~6.0) |
| **Affected** | All tested CSJMU servers |
| **Status** | Confirmed |

**Description:**  
PHP 7.4 reached End of Life in November 2022. No security patches are released.

| Server | PHP Version |
|--------|-------------|
| csjmu.ac.in | 7.4.33 |
| sis.csjmu.ac.in | 7.4.3 |
| placement.csjmu.ac.in | 7.4.x |

**Impact:**
- Known PHP 7.4 CVEs can be exploited without vendor patches

**Remediation:**
- Upgrade to PHP 8.2 or 8.3 immediately

---

### FINDING-16: Example Passwords in Public phpMyAdmin Documentation

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (CVSS ~4.3) |
| **Affected URL** | https://placement.csjmu.ac.in/phpmyadmin/doc/html/setup.html |
| **Status** | Confirmed |

**Description:**  
phpMyAdmin setup documentation is publicly accessible (142KB) and contains example credentials.

**Example passwords found in docs:**
- `changeme`
- `pmapass`
- `real_password` (placeholder in documentation)

**Impact:**
- Assists attackers in building targeted password dictionaries

**Remediation:**
- Block access to `/phpmyadmin/doc/` directory
- Remove phpMyAdmin from public access

---

### FINDING-17: Error Log Exposed

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (CVSS ~5.0) |
| **Affected URL** | https://files.csjmu.ac.in/error_log |
| **Status** | Confirmed |

**Description:**  
Apache/PHP error log (~21KB) is web-accessible, potentially containing file paths, SQL errors, and stack traces.

**Remediation:**
1. Move error logs outside document root
2. Block `.log` files in web server config

---

### FINDING-18: wp-config-sample.php Causes Server Error

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (CVSS ~4.0) |
| **Affected URL** | https://csjmu.ac.in/wp-config-sample.php |
| **Status** | Confirmed |

**Description:**  
Accessing `wp-config-sample.php` returns HTTP 500 with potential path disclosure in error output.

**Remediation:**
- Delete `wp-config-sample.php` from production

---

### FINDING-19: AI Chat API — No Authentication

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (CVSS ~5.0) |
| **Affected URL** | https://aifacility.tailf3dbcf.ts.net/api/chat |
| **Status** | Confirmed |

**Description:**  
University AI facility chat API accepts requests without authentication.

**Impact:**
- API abuse, resource exhaustion, cost implications
- Potential prompt injection attacks

**Remediation:**
- Add API key or session-based authentication
- Implement rate limiting

---

### FINDING-20: TRACE Method Enabled

| Field | Value |
|-------|-------|
| **Severity** | LOW (CVSS ~3.7) |
| **Affected URL** | https://csjmu.ac.in/wp-json/wp/v2/users |
| **Status** | Confirmed |

**Description:**  
HTTP TRACE method is enabled, which can be used in Cross-Site Tracing (XST) attacks.

**Remediation:**
```apache
TraceEnable off
```

---

### FINDING-21: WordPress Admin Path Returns 404 (Security Through Obscurity)

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Affected URL** | https://csjmu.ac.in/wp-admin/ |
| **Status** | Confirmed |

**Description:**  
`/wp-admin/` redirects to custom 404 page. This is obscurity, not real security — wp-login and REST API remain functional.

---

### FINDING-22: Timing Side-Channel on phpMyAdmin

| Field | Value |
|-------|-------|
| **Severity** | LOW (CVSS ~3.0) |
| **Affected URL** | phpMyAdmin login |
| **Status** | Observed |

**Description:**  
`root` username login attempts average ~0.61s response time vs ~0.42s for nonexistent usernames. Weak signal that `root` is a valid MySQL account.

---

### FINDING-23: Cookie-Based phpMyAdmin Auth Documented

| Field | Value |
|-------|-------|
| **Severity** | LOW (CVSS ~3.5) |
| **Affected URL** | phpMyAdmin setup documentation |
| **Status** | Informational |

**Description:**  
phpMyAdmin `cookie` auth type stores credentials in cookies after login (documented in setup.rst). If combined with XSS, credentials could be stolen.

---

### FINDING-24: wp-cron.php Publicly Triggerable

| Field | Value |
|-------|-------|
| **Severity** | LOW (CVSS ~3.0) |
| **Affected URL** | https://csjmu.ac.in/wp-cron.php |
| **Status** | Confirmed |

**Description:**  
WordPress cron can be triggered by anyone, potentially causing resource abuse.

**Remediation:**
- Disable WP-Cron in `wp-config.php` and use system cron instead

---

## 5. Bypass Testing Summary

### Tests Performed (All Non-Destructive)

| Category | Tests | Result |
|----------|-------|--------|
| Header injection bypass (X-Original-URL, X-Forwarded-For, etc.) | 8 | ❌ Failed (all redirect to 404) |
| phpMyAdmin SQL injection | 10+ | ❌ Failed |
| phpMyAdmin cookie/session fake | 5+ | ❌ Failed |
| phpMyAdmin route direct access (/import, /export, /sql) | 8 | ❌ Failed (login page) |
| Adminer SQLi & LFI | 8 | ❌ Failed |
| WordPress REST API auth bypass | 10+ | ❌ Failed (401) |
| Default credentials (12 pairs) | 12 | ❌ Failed |
| Password brute force (1540 combos) | 1540 | ❌ Failed |
| Unicode/null byte encoding | 5+ | ❌ Failed |
| CSRF token skip | 3 | ❌ Failed |
| Session fixation | 2 | ❌ Failed |
| SIS API parameter fuzz | 6 | ❌ Failed (same data) |
| XML-RPC username enumeration | 8 | ❌ Same error for all users |

### Conclusion on Bypass

> **No instant authentication bypass was achieved.** However, the combination of exposed database panels, leaked usernames, zero rate limiting, and source code exposure creates a viable **time-based attack path**.

---

## 6. Attack Chain (Theoretical)

```
┌─────────────────────────────────────────────────────────────┐
│  STEP 1: RECONNAISSANCE                                     │
│  • Subdomain enumeration → 7+ live services found           │
│  • Username leak: root (phpMyAdmin JS), Ousr1 (errors)      │
│  • Internal IPs: .218, .221, .242                           │
└────────────────────────┬────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 2: CREDENTIAL ACQUISITION (pick one)                  │
│  A) phpMyAdmin brute force (no rate limit)                  │
│  B) MySQL direct brute on port 3306                         │
│  C) git dump → connect.php / configuration.php source       │
│  D) Dictionary with changeme, pmapass from setup docs       │
└────────────────────────┬────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 3: DATABASE ACCESS                                      │
│  • MySQL shell or phpMyAdmin UI                              │
│  • Read/modify wp_users table                                │
│  • Reset admin password hash                                 │
└────────────────────────┬────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 4: WEBSITE COMPROMISE                                   │
│  • Login to wp-admin with modified credentials               │
│  • Upload malicious plugin / modify homepage                   │
│  • Defacement / malware injection / phishing page            │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. Password Leak Locations (Evaluator Reference)

Evaluators asked where passwords are publicly visible. Here are **all identified locations**:

| # | Location | What's Leaked | Actual Password? |
|---|----------|---------------|-----------------|
| 1 | phpMyAdmin HTML source | Field name `pma_password` | ❌ Field name only |
| 2 | phpMyAdmin JavaScript | `user:"root"` | ❌ Username only |
| 3 | PHP error messages | `Ousr1@192.168.1.221 (using password: YES)` | ❌ Username + host only |
| 4 | phpMyAdmin setup.html | `changeme`, `pmapass` | ⚠️ Example passwords in docs |
| 5 | phpMyAdmin setup.rst | Cookie auth mechanism docs | ❌ Mechanism description |
| 6 | `.git` repo files | `connect.php`, `configuration.php` tracked | ⚠️ Source recoverable via git dump |
| 7 | Anywhere else | — | ❌ **No plaintext production password found** |

---

## 8. Remediation Priority Matrix

| Priority | Action | Finding(s) | Effort |
|----------|--------|-----------|--------|
| **P0 — Immediate (24 hours)** | Remove phpMyAdmin from public internet | #01, #05, #06 | Low |
| **P0 — Immediate** | Remove Adminer from public internet | #03 | Low |
| **P0 — Immediate** | Block MySQL port 3306 on firewall | #02 | Low |
| **P0 — Immediate** | Delete `.git` from files.csjmu.ac.in | #04 | Low |
| **P0 — Immediate** | Delete phpinfo.php | #08 | Low |
| **P1 — This Week** | Implement fail2ban / rate limiting | #05 | Medium |
| **P1 — This Week** | Disable xmlrpc.php | #11 | Low |
| **P1 — This Week** | Fix CORS configuration | #10 | Low |
| **P1 — This Week** | Add auth to SIS GIS API | #09 | Medium |
| **P1 — This Week** | Disable PHP error display | #07 | Low |
| **P2 — This Month** | Upgrade PHP 7.4 → 8.2+ | #15 | High |
| **P2 — This Month** | Disable directory listing | #13 | Low |
| **P2 — This Month** | Update WordPress plugins | #14 | Medium |
| **P2 — This Month** | Rotate all database passwords | #04, #06, #07 | Medium |
| **P3 — Ongoing** | Security audit of admission system source | #04 | High |
| **P3 — Ongoing** | Implement WAF (Cloudflare/similar) | All | Medium |

---

## 9. Hacker vs Defender Summary

### Attacker Perspective

> "Login bypass nahi mila, par mujhe teen database ke darwaze mile — phpMyAdmin, Adminer, aur MySQL:3306. Username `root` aur `Ousr1` already pata hai. Rate limit zero hai. Git se poora source code nikal sakta hoon. Bas password chahiye — time lagega par kaam ho jayega."

### Defender Perspective

> "Hamara authentication strong hai — koi direct bypass nahi hua. Par hamari **infrastructure configuration critical level pe vulnerable** hai. Database admin panels internet pe nahi hone chahiye. Agar aaj fix karein to 80% risk turant khatam."

---

## 10. Tools Used

- `curl` — HTTP probing and header testing
- `Python requests` — Automated bypass battery scripting
- Browser DevTools — JavaScript source analysis
- Manual inspection — Git repository, error pages, sitemap

---

## 11. Disclaimer

This assessment was conducted for **educational and authorized security research purposes** as part of a college bug bounty project. All testing was **non-destructive** — no data was modified, deleted, or exfiltrated beyond what was necessary to confirm vulnerability existence. No actual exploitation or website compromise was performed.

---

## 12. Conclusion

CSJMU's web infrastructure has **strong application-layer authentication** (no bypass found in 200+ tests) but **critical infrastructure-layer misconfigurations** that expose database administration tools, source code, and internal network details to the public internet.

The overall risk is **CRITICAL** due to the combination of:
- 3 public database admin interfaces
- Open MySQL port
- Exposed Git repository with admission system source
- Zero brute-force protection
- Leaked database usernames

**Recommended immediate action:** Remove phpMyAdmin, Adminer, and `.git` from public access within 24 hours. This single step eliminates the most critical attack vectors.

---

*Report prepared for CSJMU Security Research / Bug Bounty Project*  
*Assessment Date: June 2026*
