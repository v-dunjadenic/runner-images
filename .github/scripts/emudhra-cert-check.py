#!/usr/bin/env python3
"""Check whether runner tools still trust the compromised eMudhra certificates.

Read-only: no trust store, configuration or credential is changed.

Related issues in actions/runner-images: #15228 (macOS), #15191 (Homebrew bundle),
#15186 (/etc/ssl/cert.pem), #15018 (original report).
Test endpoints and guidance: https://emudhra.we-have-a-problem.com/

Results per target:
  ACCEPTED     the TLS connection succeeded, so the tool still trusts the chain (vulnerable)
  REJECTED     certificate verification failed (protected)
  INCONCLUSIVE another error, such as a network problem; see the detail column
  SKIPPED      the tool or file is not present on this runner
"""

import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time


ENDPOINTS = {
    "G3": "https://dv-g3b-emudhra.we-have-a-problem.com/",
    "AAA": "https://dv-g3b-aaa-emudhra.we-have-a-problem.com/",
}
GIT_CHECK_REPO = "https://git-emudhra.we-have-a-problem.com/check.git"
COMPROMISED_ROOTS = (
    "emSign ECC Root CA - G3",
    "emSign Root TLS CA - G3",
    "AAA Certificate Services",
)
# Categories that the issues report as high severity. "own-store" tools ship their own CA list
# and are reported for information only.
HIGH_SEVERITY = ("system", "homebrew")
SYSTEM = platform.system()
OUTPUT = Path(os.environ.get("RUNNER_TEMP", ".")) / "emudhra-cert-check"
MAX_ATTEMPTS = 3

PYTHON_PROBE = r'''
import ssl, sys, urllib.error, urllib.request
url = sys.argv[1]
cafile = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
context = ssl.create_default_context(cafile=cafile)
# Measure trust only: Python 3.13+ enables strict X.509 checks by default.
strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
if strict:
    context.verify_flags &= ~strict
try:
    urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), context=context, timeout=30)
    print("ACCEPTED")
except urllib.error.HTTPError as error:
    print("ACCEPTED HTTP %s" % error.code)
except Exception as error:
    reason = getattr(error, "reason", error)
    if isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(reason):
        print("REJECTED %s" % reason)
    else:
        print("INCONCLUSIVE %r" % (reason,))
'''

NODE_PROBE = r'''
const https = require("https");
const request = https.request(process.argv[1], { method: "HEAD", timeout: 30000 }, (response) => {
  console.log("ACCEPTED HTTP " + response.statusCode);
  response.resume();
});
request.on("timeout", () => request.destroy(new Error("timeout")));
request.on("error", (error) => console.log((error.code || "") + " " + error.message));
request.end();
'''

CERT_ERROR = re.compile(
    r"ssl certificate problem|certificate verif|unable to get local issuer|self[- ]signed"
    r"|crypt_e_revoked|certificate_verify_failed|cert_untrusted|certificate is not trusted"
    r"|server certificate|schannel.*certificate|unable_to_get_issuer|err_tls_cert",
    re.IGNORECASE,
)
GIT_TLS_OK = re.compile(
    r"not found|returned error: 4\d\d|could not read username|authentication failed"
    r"|not valid: is this a git repository|repository .* not found|http 4\d\d",
    re.IGNORECASE,
)


def run(command, timeout=75, env=None):
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, env=env,
            stdin=subprocess.DEVNULL,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return None, "", "timed out after %ss" % timeout
    except OSError as error:
        return None, "", str(error)


def first_line(text):
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


def classify_curl(code, stdout, stderr):
    if code == 0:
        return "ACCEPTED"
    if code == 60 or CERT_ERROR.search(stderr):
        return "REJECTED"
    return "INCONCLUSIVE"


def classify_git(code, stdout, stderr):
    if code == 0:
        return "ACCEPTED"
    if CERT_ERROR.search(stderr):
        return "REJECTED"
    # The TLS handshake succeeded if the server answered with an HTTP-level error.
    if GIT_TLS_OK.search(stderr):
        return "ACCEPTED"
    return "INCONCLUSIVE"


def classify_printed(code, stdout, stderr):
    line = first_line(stdout)
    if line.startswith("ACCEPTED"):
        return "ACCEPTED"
    if line.startswith("REJECTED") or CERT_ERROR.search(line):
        return "REJECTED"
    return "INCONCLUSIVE"


def probe(command, classify, timeout=75, env=None):
    attempts = []
    for attempt in range(MAX_ATTEMPTS):
        code, stdout, stderr = run(command, timeout=timeout, env=env)
        result = classify(code, stdout, stderr)
        attempts.append({"exit_code": code, "stdout": first_line(stdout), "stderr": first_line(stderr)})
        if result != "INCONCLUSIVE":
            break
        if attempt < MAX_ATTEMPTS - 1:
            time.sleep(3)
    last = attempts[-1]
    return {
        "result": result,
        "exit_code": last["exit_code"],
        "detail": last["stdout"] or last["stderr"],
        "attempts": attempts,
    }


def curl_targets(executable, extra=()):
    command = [executable, "-sS", "-o", os.devnull, "--connect-timeout", "15", "--max-time", "45", *extra]
    return {name: probe([*command, url], classify_curl) for name, url in ENDPOINTS.items()}


def git_targets(executable):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never", GIT_ASKPASS="", SSH_ASKPASS="")
    command = [executable, "-c", "credential.helper=", "-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=30", "ls-remote"]
    targets = {name: probe([*command, url], classify_git, env=env) for name, url in ENDPOINTS.items()}
    targets["git check repo"] = probe([*command, GIT_CHECK_REPO], classify_git, env=env)
    return targets


def python_targets(executable, cafile=""):
    return {
        name: probe([executable, "-c", PYTHON_PROBE, url, cafile], classify_printed)
        for name, url in ENDPOINTS.items()
    }


def node_targets(executable):
    return {name: probe([executable, "-e", NODE_PROBE, url], classify_printed) for name, url in ENDPOINTS.items()}


def roots_in_bundle(path):
    openssl = shutil.which("openssl")
    if not openssl:
        return None
    try:
        pkcs7 = subprocess.run(
            [openssl, "crl2pkcs7", "-nocrl", "-certfile", str(path)], capture_output=True, timeout=30,
        )
        if pkcs7.returncode != 0:
            return None
        subjects = subprocess.run(
            [openssl, "pkcs7", "-print_certs", "-noout"], input=pkcs7.stdout, capture_output=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = subjects.stdout.decode("utf-8", errors="replace")
    return [name for name in COMPROMISED_ROOTS if name in text]


def pip_bundle(python):
    code, stdout, _ = run([python, "-c", "from pip._vendor import certifi; print(certifi.where())"], timeout=30)
    path = first_line(stdout)
    return path if code == 0 and path and Path(path).is_file() else None


def brew_prefix():
    brew = shutil.which("brew")
    if brew:
        code, stdout, _ = run([brew, "--prefix"], timeout=30)
        if code == 0 and first_line(stdout):
            return first_line(stdout)
    for candidate in ("/opt/homebrew", "/usr/local"):
        if Path(candidate, "bin", "brew").exists():
            return candidate
    return None


def tool_version(command):
    code, stdout, stderr = run(command, timeout=30)
    return first_line(stdout or stderr) if code is not None else None


def boot_time_utc():
    if SYSTEM == "Darwin":
        code, stdout, _ = run(["sysctl", "-n", "kern.boottime"], timeout=10)
        match = re.search(r"sec = (\d+)", stdout or "")
        seconds = int(match.group(1)) if match else None
    elif SYSTEM == "Linux":
        seconds = None
        try:
            for line in Path("/proc/stat").read_text().splitlines():
                if line.startswith("btime "):
                    seconds = int(line.split()[1])
        except OSError:
            pass
    else:
        seconds = None
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(seconds)) if seconds else None


def file_info(path):
    path = Path(path)
    if not path.exists():
        return None
    return {
        "path": str(path),
        "resolved": str(path.resolve()),
        "modified_utc": time.strftime("%Y-%m-%d %H:%M", time.gmtime(path.stat().st_mtime)),
    }


TLS_ENV_VARS = (
    "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "CURL_SSL_BACKEND", "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "NODE_EXTRA_CA_CERTS", "PIP_CERT",
)


def diagnostics():
    """Explain results: which trust sources the tools actually use. Read-only."""
    diag = {"tls_env": {name: os.environ[name] for name in TLS_ENV_VARS if name in os.environ}}
    if SYSTEM != "Darwin":
        return diag
    _, _, stderr = run(
        ["/usr/bin/curl", "-v", "-sS", "-o", os.devnull, "--max-time", "30", ENDPOINTS["AAA"]], timeout=45,
    )
    diag["apple_curl_verbose"] = [
        line.strip() for line in stderr.splitlines()
        if re.search(r"CAfile|CApath|SSL connection|verif|issuer:|subject:|Server certificate|SSL certificate", line)
    ][:20]
    _, stdout, stderr = run(
        ["/usr/bin/python3", "-c", "import ssl; print(ssl.OPENSSL_VERSION); print(ssl.get_default_verify_paths())"],
        timeout=30,
    )
    diag["apple_python_ssl"] = (stdout or stderr).strip().splitlines()[:3]
    _, stdout, _ = run(["/usr/bin/git", "config", "--show-origin", "--get-regexp", r"^http\."], timeout=30)
    diag["apple_git_http_config"] = stdout.strip().splitlines()[:10]
    _, stdout, _ = run(["ls", "-la", "/private/etc/ssl"], timeout=10)
    diag["etc_ssl"] = stdout.strip().splitlines()[:15]
    certs_dir = Path("/private/etc/ssl/certs")
    diag["etc_ssl_certs_files"] = len(list(certs_dir.iterdir())) if certs_dir.is_dir() else None
    return diag


def add(checks, seen, check_id, category, kind, executable=None, bundle=None):
    key = (kind, os.path.realpath(executable) if executable else None, os.path.realpath(bundle) if bundle else None)
    if key in seen:
        return
    seen.add(key)
    checks.append({"id": check_id, "category": category, "kind": kind, "executable": executable, "bundle": bundle})


def plan_checks():
    checks, seen = [], set()
    if SYSTEM == "Darwin":
        brew = brew_prefix()
        add(checks, seen, "Apple curl (/usr/bin/curl)", "system", "curl", "/usr/bin/curl")
        add(checks, seen, "Apple git (/usr/bin/git)", "system", "git", "/usr/bin/git")
        add(checks, seen, "Apple python3 (/usr/bin/python3)", "system", "python", "/usr/bin/python3")
        add(checks, seen, "System bundle /etc/ssl/cert.pem", "system", "bundle", bundle="/etc/ssl/cert.pem")
        for name in ("curl", "git"):
            found = shutil.which(name)
            if found:
                category = "homebrew" if brew and os.path.realpath(found).startswith(brew) else "system"
                add(checks, seen, "%s on PATH (%s)" % (name, found), category, name, found)
        if brew:
            for name, path in (
                ("Homebrew curl", "opt/curl/bin/curl"),
                ("Homebrew git", "opt/git/bin/git"),
            ):
                full = os.path.join(brew, path)
                if os.path.exists(full):
                    add(checks, seen, "%s (%s)" % (name, full), "homebrew", name.split()[-1], full)
            for path in (
                "etc/ca-certificates/cert.pem",
                "opt/ca-certificates/share/ca-certificates/cacert.pem",
                "etc/openssl@3/cert.pem",
                "etc/openssl@4/cert.pem",
                "etc/openssl@1.1/cert.pem",
            ):
                full = os.path.join(brew, path)
                if os.path.exists(full):
                    add(checks, seen, "Homebrew bundle %s" % full, "homebrew", "bundle", bundle=full)
        pip = pip_bundle("/usr/bin/python3")
        if pip:
            add(checks, seen, "Apple pip bundle (%s)" % pip, "own-store", "bundle", bundle=pip)
    elif SYSTEM == "Linux":
        for name in ("curl", "git"):
            found = shutil.which(name)
            if found:
                add(checks, seen, "%s (%s)" % (name, found), "system", name, found)
        if os.path.exists("/usr/bin/python3"):
            add(checks, seen, "System python3 (/usr/bin/python3)", "system", "python", "/usr/bin/python3")
        for bundle in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"):
            if os.path.exists(bundle):
                add(checks, seen, "System bundle %s" % bundle, "system", "bundle", bundle=bundle)
        pip = pip_bundle("/usr/bin/python3") if os.path.exists("/usr/bin/python3") else None
        if pip:
            add(checks, seen, "System pip bundle (%s)" % pip, "own-store", "bundle", bundle=pip)
    elif SYSTEM == "Windows":
        found = shutil.which("curl")
        if found:
            add(checks, seen, "curl on PATH (%s)" % found, "system", "curl", found)
        system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "curl.exe")
        if os.path.exists(system32):
            add(checks, seen, "Windows curl (%s)" % system32, "system", "curl", system32)
        found = shutil.which("git")
        if found:
            add(checks, seen, "git on PATH (%s)" % found, "system", "git", found)
        add(checks, seen, "Python on PATH (%s)" % sys.executable, "own-store", "python", sys.executable)
    node = shutil.which("node")
    if node:
        add(checks, seen, "Node.js (%s)" % node, "own-store", "node", node)
    return checks


def execute(check):
    kind, executable = check["kind"], check["executable"]
    if executable and not os.path.exists(executable):
        check["targets"] = {name: {"result": "SKIPPED", "detail": "not installed"} for name in ENDPOINTS}
        return check
    if kind == "curl":
        check["version"] = tool_version([executable, "--version"])
        check["targets"] = curl_targets(executable)
    elif kind == "git":
        check["version"] = tool_version([executable, "--version"])
        check["targets"] = git_targets(executable)
    elif kind == "python":
        check["version"] = tool_version([executable, "--version"])
        check["targets"] = python_targets(executable)
    elif kind == "node":
        check["version"] = tool_version([executable, "--version"])
        check["targets"] = node_targets(executable)
    elif kind == "bundle":
        # Use only this file as the trust store, so the result shows what the file itself trusts.
        check["file"] = file_info(check["bundle"])
        check["targets"] = python_targets(sys.executable, check["bundle"])
        check["roots_present"] = roots_in_bundle(check["bundle"])
    return check


def verdict(checks):
    high = [c for c in checks if c["category"] in HIGH_SEVERITY]
    results = [t["result"] for c in high for t in c["targets"].values()]
    if "ACCEPTED" in results:
        return "VULNERABLE"
    if "INCONCLUSIVE" in results:
        return "INCONCLUSIVE"
    return "PROTECTED"


def accepted(checks, categories):
    return [
        "%s [%s]" % (c["id"], ", ".join(name for name, t in c["targets"].items() if t["result"] == "ACCEPTED"))
        for c in checks
        if c["category"] in categories and any(t["result"] == "ACCEPTED" for t in c["targets"].values())
    ]


def cell(target):
    if not target:
        return "-"
    return target["result"] if target["result"] in ("ACCEPTED", "REJECTED", "SKIPPED") else "INCONCLUSIVE: %s" % target.get("detail", "")[:80]


def detail_rows(result):
    rows = []
    for check in result["checks"]:
        targets = check["targets"]
        roots = check.get("roots_present")
        rows.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            result["label"], result["sample"], check["id"], check["category"],
            cell(targets.get("G3")), cell(targets.get("AAA")), cell(targets.get("git check repo")),
            "-" if roots is None else (", ".join(roots) or "none"),
        ))
    return rows


DETAIL_HEADER = [
    "| Runner | Sample | Check | Category | G3 | AAA | git check repo | Compromised roots in file |",
    "|---|---|---|---|---|---|---|---|",
]


def write_summary(text):
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text)


def do_probe():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    checks = [execute(check) for check in plan_checks()]
    brew = brew_prefix() if SYSTEM == "Darwin" else None
    versions = {}
    if brew and shutil.which("brew"):
        versions["brew"] = tool_version(["brew", "list", "--versions", "curl", "git", "ca-certificates", "openssl@3"])
    os_version = tool_version(["sw_vers", "-productVersion"]) if SYSTEM == "Darwin" else platform.platform()
    result = {
        "label": os.environ.get("RUNNER_LABEL", "local"),
        "sample": os.environ.get("SAMPLE", "1"),
        "image_os": os.environ.get("ImageOS", "-"),
        "image_version": os.environ.get("ImageVersion") or "-",
        "os": SYSTEM,
        "os_version": os_version,
        "arch": platform.machine(),
        "boot_time_utc": boot_time_utc(),
        "cert_pem": file_info("/etc/ssl/cert.pem") if SYSTEM == "Darwin" else None,
        "cert_pem_backup": file_info("/etc/ssl/cert.pem.orig") if SYSTEM == "Darwin" else None,
        "versions": versions,
        "diagnostics": diagnostics(),
        "checks": checks,
    }
    result["verdict"] = verdict(checks)
    result["accepted_high"] = accepted(checks, HIGH_SEVERITY)
    result["accepted_other"] = accepted(checks, ("own-store",))
    text = json.dumps(result, indent=2)
    (OUTPUT / "result.json").write_text(text + "\n", encoding="utf-8")
    print(text)
    write_summary(
        "### %s (sample %s): %s\n\nImage %s, OS %s, booted %s UTC\n\n%s\n\n"
        "<details><summary>Diagnostics</summary>\n\n```json\n%s\n```\n\n</details>\n"
        % (result["label"], result["sample"], result["verdict"], result["image_version"],
           result["os_version"], result["boot_time_utc"] or "-", "\n".join(DETAIL_HEADER + detail_rows(result)),
           json.dumps(result["diagnostics"], indent=2))
    )


def do_report(directory):
    root = Path(directory)
    results = sorted(
        (json.loads(path.read_text(encoding="utf-8")) for path in root.glob("*/result.json")),
        key=lambda item: (item["label"], str(item["sample"])),
    )
    if not results:
        raise SystemExit("No results were downloaded")
    lines = [
        "# eMudhra certificate trust check",
        "",
        "Read-only check of whether runner tools still trust certificates from the compromised eMudhra "
        "intermediates. Issues: actions/runner-images#15228, #15191, #15186, #15018.",
        "",
        "- **ACCEPTED** = TLS connection succeeded, so the tool still trusts the chain (vulnerable). "
        "**REJECTED** = certificate verification failed (protected).",
        "- **VULNERABLE** = at least one `system` or `homebrew` check accepted a chain. `own-store` tools "
        "(pip, Node.js) ship their own CA list and are listed for information only.",
        "- **G3** and **AAA** are the two test chains. **git check repo** is the git test from the "
        "disclosure site. Bundle rows test the file on its own as the only trust store.",
        "- MacCloud's VM-startup fix applies to VMs created after its rollout (Nov 3, about 17:00 UTC). "
        "An ACCEPTED result on a VM booted before that may be an old VM. Boot time is approximate.",
        "",
        "## Verdict per runner",
        "",
        "| Runner | Sample | Image version | OS | Booted (UTC) | Verdict | Accepted (system/homebrew) | Accepted (own-store) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for result in results:
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            result["label"], result["sample"], result["image_version"], result["os_version"],
            result["boot_time_utc"] or "-", result["verdict"],
            "<br>".join(result["accepted_high"]) or "-", "<br>".join(result["accepted_other"]) or "-",
        ))
    lines += ["", "## Details", ""] + DETAIL_HEADER
    for result in results:
        lines += detail_rows(result)
    lines += [
        "", "## Diagnostics", "",
        "Which CA file Apple curl and Python load, TLS environment variables and git http config.", "",
        "| Runner | Sample | TLS env vars | Apple curl CAfile | Apple python default paths |",
        "|---|---|---|---|---|",
    ]
    for result in results:
        diag = result.get("diagnostics") or {}
        cafile = [line for line in diag.get("apple_curl_verbose", []) if "CAfile" in line or "CApath" in line]
        lines.append("| %s | %s | %s | %s | %s |" % (
            result["label"], result["sample"],
            ", ".join("%s=%s" % item for item in diag.get("tls_env", {}).items()) or "-",
            "<br>".join(cafile) or "-",
            "<br>".join(diag.get("apple_python_ssl", [])[1:2]) or "-",
        ))
    text = "\n".join(lines) + "\n"
    (root / "report.md").write_text(text, encoding="utf-8")
    write_summary(text)
    print(text)


if __name__ == "__main__":
    if sys.argv[1:] == ["probe"]:
        do_probe()
    elif len(sys.argv) == 3 and sys.argv[1] == "report":
        do_report(sys.argv[2])
    else:
        raise SystemExit("Usage: emudhra-cert-check.py probe | report RESULTS_DIRECTORY")
