#  HTB - LinkVortex  Privilege Escalation  AutoPwn Script

This is an automated privilege escalation script for the Hack The Box machine **LinkVortex**, which exploits an insecure `sudo` configuration and symbolic link processing vulnerability.

---
## 📋 Description

The target machine allows the user `bob` to run a script as root via `sudo`, which processes `.png` files and optionally displays their contents if a specific environment variable is set. By chaining symbolic links, it's possible to read sensitive files such as `/root/.ssh/id_rsa`.

**This script automates the full escalation path:**
- Connects to the machine as `bob` via SSH
- Creates a symlink chain to the root user's private SSH key
- Executes the vulnerable script with the proper environment variable
- Parses and saves the extracted private key
- Connects as `root` using `paramiko`
- Drops an interactive root shell

---
## 🧠 Requirements

- Python 3.x
- paramiko>=2.11.0
- HTB VPN connection active
- Known password for ssh user `bob` 

---
## ⚙️ Usage
```bash
python3 autopwn_root.py --target 10.10.11.47 \
                        --user bob \
                        --password 'fibber-talented-worth' \
```
#### Arguments:
###### 🔹 Required
- `--target`  
    IP address or hostname of the target machine.  
    **Example:** `--target 10.10.11.47`
- `--user`  
    SSH username to connect as.  
    **Example:** `--user bob`
- `--password`  
    Password for the SSH user.  
    **Example:** `--password 'fibber-talented-worth'`
###### 🔸 Optional
- `--script-path`  
    Full path to the vulnerable script on the target system.  
    **Default:** `/opt/ghost/clean_symlink.sh`  
    **Example:** `--script-path /custom/path/to/clean_symlink.sh`
- `--key-out`  
    Output filename for the extracted private key.  
    **Default:** `id_rsa_root`  
    **Example:** `--key-out my_root_key.pem`
---
### 🛠️ Features
✔️ Initial SSH connection as `bob`
✔️ Creation of a double symlink (`id_rsa.txt` ➜ `/root/.ssh/id_rsa` ➜ `id_rsa.png`)
✔️ Execution of the script using `sudo CHECK_CONTENT=true ...`
✔️ Output parsing to extract the private key
✔️ Saving the key as `id_rsa_root`
✔️ New SSH connection as `root`
✔️ Interactive root shell using `paramiko.invoke_shell()`
