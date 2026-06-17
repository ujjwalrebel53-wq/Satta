# CSJMU — Quick Findings Checklist

Use this for viva / presentation. Full details in `CSJMU_Security_Assessment_Report.md`.

## Critical (5)

- [ ] **C-01** phpMyAdmin public — `csjmu.ac.in/phpmyadmin/` + `placement.csjmu.ac.in/phpmyadmin/`
- [ ] **C-02** MySQL port 3306 open — `103.224.48.75`, `.77`, `.72`
- [ ] **C-03** Adminer public — `files.csjmu.ac.in/adminer-4.8.1.php`
- [ ] **C-04** `.git` exposed — `files.csjmu.ac.in/.git/`
- [ ] **C-05** No brute-force limit on phpMyAdmin (50+ attempts, all 200 OK)

## High (8)

- [ ] **H-01** Username `root` in phpMyAdmin JS (`logged_in:false`)
- [ ] **H-02** Username `Ousr1@192.168.1.221` in PHP errors
- [ ] **H-03** phpinfo.php — `sis.csjmu.ac.in/phpinfo.php`
- [ ] **H-04** SIS API no auth — `sis.csjmu.ac.in/api/getgisdata` (48KB data)
- [ ] **H-05** CORS reflects `evil.com` + credentials allowed
- [ ] **H-06** xmlrpc.php active (multicall brute amplifier)
- [ ] **H-07** Internal IPs on homepage (`192.168.1.242` ERP)
- [ ] **H-08** Git tracks `connect.php`, `configuration.php`, secret files

## Medium (7)

- [ ] **M-01** Directory listing — `wp-includes/`, `uploads/2024/`, `uploads/2025/`
- [ ] **M-02** WP version + plugin disclosure
- [ ] **M-03** PHP 7.4 EOL on all servers
- [ ] **M-04** Example passwords in phpMyAdmin docs (`changeme`, `pmapass`)
- [ ] **M-05** error_log public — `files.csjmu.ac.in/error_log`
- [ ] **M-06** wp-config-sample.php returns 500
- [ ] **M-07** AI API no auth — `aifacility.../api/chat`

## Bypass Testing Result

| Test | Result |
|------|--------|
| Instant login bypass | **NOT FOUND** |
| Header injection (X-Forwarded-For etc.) | Failed |
| SQL injection on login | Failed |
| 1540 password combos | Failed |
| Default creds (12 pairs) | Failed |
| **But:** time-based attack via brute + git dump | **POSSIBLE** |

## One-Line Summary for Evaluators

> "Authentication bypass nahi hua, par database admin panels, git repo, aur MySQL port internet pe khule hain — yeh CRITICAL risk hai."

## Top 5 Fixes (24 hours)

1. phpMyAdmin hatao / IP whitelist
2. Adminer delete karo
3. Port 3306 firewall block
4. `.git` folder delete
5. `phpinfo.php` delete
