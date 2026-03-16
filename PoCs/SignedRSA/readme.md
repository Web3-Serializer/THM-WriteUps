# rsa-key-recovery-poc

When an RSA implementation derives primes from a deterministic seed instead of a CSPRNG, the private key can be reconstructed by anyone who knows the algorithm. This PoC exploits a `/debug` endpoint that leaks the exact seed pattern and prime derivation logic, allowing full admin key recovery and forged RSA-PSS signature submission.

---

## Attack chain

```
/debug leak → seed derivation → nextPrime(SHA-256) → admin privkey → PSS sign → /verify → FLAG
```

1. `/debug` exposes the seed pattern: `{username}_lovenote_2026_valentine`
2. `p = nextprime(SHA256(seed))`, `q = nextprime(SHA256(seed + "pki"))`
3. Build full RSA private key from `p`, `q`
4. Sign the admin welcome message with RSA-PSS / SHA-256 / MAX\_SALT
5. POST to `/verify` and capture the flag

---

## Usage

```bash
pip install sympy cryptography requests colorama
```

```bash
# offline key recovery only
python poc.py

# full chain
python poc.py -t <IP>:5000

# options
  -t  IP:PORT   target host
  -u            target user (default: admin)
  -m            message to sign (default: built-in)
  -e            print reconstructed private key (PEM)
  -s  FILE      save raw signature bytes to file
```

---

## Example output

```
  [*] Seeds derived for: admin
  [+] p = 47916182041887445…  (252 bits)
  [+] q = 17765675040165337…  (254 bits)
  [+] Private key built : n = 85126331932157837… (505 bits)
  [+] Signature = 00cf6794294747188884ad81f9f4fd3f62ffb3f9…  (64 bytes)
  [+] Local PSS verify PASSED
  [*] Submitting to http://10.10.10.42:5000/verify ...
  [+] HTTP 200

  FLAG → [ REDACTED ]
```

---

## Why it works

Standard RSA requires `p` and `q` to be independently and uniformly random. Here, both primes are fully determined by the username, knowing the seed pattern is enough to reconstruct the private key without factoring `n` or any brute force.

The `/debug` endpoint is the root cause: it exposes the key derivation logic in a live production context, reducing the security of "RSA-2048" to the security of a predictable string.

---

## Room

[TryHackMe | Signed Messages](https://tryhackme.com/room/signedmessages) · Love At First Breach 2026

**Author:** Web3-Serializer  
**Category:** Cryptography
