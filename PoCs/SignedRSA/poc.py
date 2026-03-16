#!/usr/bin/env python3
# Author: Web3-Serializer
# TryHackMe — Signed Messages (Love At First Breach 2026)
# deps: pip install sympy cryptography requests

import sys
import hashlib
import argparse
import textwrap

import requests
from colorama import init as colorama_init, AnsiToWin32
from sympy import nextprime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers, RSAPublicNumbers,
    rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1,
)
from cryptography.hazmat.backends import default_backend


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
  ██████╗ ███████╗ █████╗     ██╗  ██╗███████╗██╗   ██╗
  ██╔══██╗██╔════╝██╔══██╗    ██║ ██╔╝██╔════╝╚██╗ ██╔╝
  ██████╔╝███████╗███████║    █████╔╝ █████╗   ╚████╔╝
  ██╔══██╗╚════██║██╔══██║    ██╔═██╗ ██╔══╝    ╚██╔╝
  ██║  ██║███████║██║  ██║    ██║  ██╗███████╗   ██║
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚══════╝   ╚═╝
    """ + C.RESET)
    print(f"  {C.BOLD}Signed Messages — Deterministic RSA Key Recovery{C.RESET}")
    print(f"  {C.DIM}Love At First Breach 2026 · Author: Web3-Serializer{C.RESET}\n")


ADMIN_MESSAGE = (
    "Welcome to LoveNote! Send encrypted love messages this Valentine's Day. "
    "Your communications are secured with industry-standard RSA-2048 digital signatures."
)


def derive_seeds(username: str):
    seed_p = f"{username}_lovenote_2026_valentine".encode()
    return seed_p, seed_p + b"pki"


def hash_to_prime(seed: bytes) -> int:
    return int(nextprime(int(hashlib.sha256(seed).hexdigest(), 16)))


def build_private_key(p: int, q: int, e: int = 65537):
    n    = p * q
    d    = pow(e, -1, (p - 1) * (q - 1))
    pub  = RSAPublicNumbers(e, n)
    priv = RSAPrivateNumbers(p, q, d, rsa_crt_dmp1(d, p), rsa_crt_dmq1(d, q), rsa_crt_iqmp(p, q), pub)
    return priv.private_key(default_backend()), n, d


def sign_message(private_key, message: str) -> bytes:
    return private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def local_verify(private_key, message: str, signature: bytes) -> bool:
    try:
        private_key.public_key().verify(
            signature, message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def submit_signature(target: str, username: str, message: str, signature: bytes):
    url = f"http://{target}/verify"
    try:
        resp = requests.post(url, data={
            "username": username, "message": message, "signature": signature.hex()
        }, timeout=10)
        ok(f"HTTP {resp.status_code}")
        if "THM{" in resp.text:
            s = resp.text.index("THM{")
            return resp.text[s:resp.text.index("}", s) + 1]
        warn("No flag in response:")
        print(textwrap.indent(resp.text[:600], "    "))
        return None
    except requests.exceptions.ConnectionError:
        err(f"Cannot connect to {url}")
        return None
    except requests.exceptions.Timeout:
        err("Request timed out")
        return None


def main():
    banner()
    parser = argparse.ArgumentParser(description="Signed Messages CTF PoC")
    parser.add_argument("-t", "--target", metavar="IP:PORT", default=None)
    parser.add_argument("-u", "--username", default="admin")
    parser.add_argument("-m", "--message", default=ADMIN_MESSAGE)
    parser.add_argument("-e", "--export-key", action="store_true")
    parser.add_argument("-s", "--sig-file", metavar="FILE", default=None)
    args = parser.parse_args()

    seed_p, seed_q = derive_seeds(args.username)
    info(f"Seeds derived for: {args.username}")

    p = hash_to_prime(seed_p)
    q = hash_to_prime(seed_q)
    ok(f"p = {str(p)[:18]}… ({p.bit_length()} bits)")
    ok(f"q = {str(q)[:18]}… ({q.bit_length()} bits)")

    private_key, n, d = build_private_key(p, q)
    ok(f"Private key built — n = {str(n)[:18]}… ({n.bit_length()} bits)")

    if args.export_key:
        print(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode())

    signature = sign_message(private_key, args.message)
    ok(f"Signature = {signature.hex()[:40]}… ({len(signature)} bytes)")

    if not local_verify(private_key, args.message, signature):
        err("Local PSS verify FAILED — aborting")
        sys.exit(1)
    ok("Local PSS verify PASSED")

    if args.sig_file:
        with open(args.sig_file, "wb") as fh:
            fh.write(signature)
        ok(f"Saved → {args.sig_file}")

    if not args.target:
        warn("No --target given, offline only")
        info(f"sig hex: {signature.hex()}")
        return

    info(f"Submitting to http://{args.target}/verify ...")
    flag = submit_signature(args.target, args.username, args.message, signature)
    print()
    if flag:
        print(f"  {C.BOLD}{C.GREEN}FLAG → {flag}{C.RESET}\n")
    else:
        err("Flag not captured")
        sys.exit(1)


if __name__ == "__main__":
    main()