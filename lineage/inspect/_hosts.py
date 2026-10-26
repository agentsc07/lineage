"""Network destinations: which hosts a package talks to, and which of them its own metadata accounts for.

A credential sent to the vendor's own API (an `openai` client sending OPENAI_API_KEY to api.openai.com) is the
product working. The same credential sent to a host that nothing in the package's metadata mentions is
exfiltration. Everything here is deterministic string work; nothing touches the network.
"""
from __future__ import annotations

import ipaddress
import re
import tomllib
from pathlib import Path

URL_HOST = re.compile(r"\b(?:https?|wss?|ftps?|sftp)://(?:[^/\s@'\"<>]*@)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+)", re.I)
BARE_HOST = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$|^\d{1,3}(?:\.\d{1,3}){3}$|^localhost$")
SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov", "edu"}
GENERIC_TOKENS = {"python", "py", "lib", "core", "client", "sdk", "api", "utils", "tools", "http", "async", "aio", "types"}

# Where a project lives or is documented says nothing about where its code may send data.
HOSTING = {"github.com", "gitlab.com", "bitbucket.org", "readthedocs.io", "readthedocs.org", "github.io", "pypi.org", "python.org",
           "pythonhosted.org", "gitlab.io", "sourceforge.net", "twitter.com", "x.com", "discord.gg", "gitter.im", "opencollective.com",
           "sponsors.com", "ko-fi.com", "patreon.com", "mailto", "docs.python.org"}

# Package-name token -> domains the product legitimately talks to with its users' credentials.
VENDOR_DOMAINS: dict[str, tuple[str, ...]] = {
    "boto": ("amazonaws.com", "amazon.com", "169.254.169.254", "169.254.170.2"),
    "aws": ("amazonaws.com", "amazon.com", "169.254.169.254", "169.254.170.2"),
    "s3transfer": ("amazonaws.com",),
    "awscrt": ("amazonaws.com",),
    "google": ("googleapis.com", "google.com", "googleusercontent.com", "metadata.google.internal", "169.254.169.254"),
    "gcsfs": ("googleapis.com", "google.com"),
    "azure": ("windows.net", "microsoft.com", "microsoftonline.com", "azure.com", "azure-api.net", "169.254.169.254"),
    "msal": ("microsoftonline.com", "microsoft.com", "windows.net"),
    "adlfs": ("windows.net", "microsoft.com"),
    "openai": ("openai.com",),
    "anthropic": ("anthropic.com",),
    "huggingface": ("huggingface.co", "hf.co"),
    "github": ("github.com", "githubusercontent.com"),
    "ghapi": ("github.com", "githubusercontent.com"),
    "gitpython": ("github.com",),
    "pip": ("pypi.org", "pythonhosted.org", "python.org"),
    "setuptools": ("pypi.org", "pythonhosted.org", "python.org"),
    "virtualenv": ("pypi.org", "pythonhosted.org", "python.org"),
    "twine": ("pypi.org", "python.org"),
    "uv": ("pypi.org", "pythonhosted.org"),
    "kubernetes": ("kubernetes.io", "kubernetes.default.svc"),
    "docker": ("docker.com", "docker.io"),
    "slack": ("slack.com",),
    "stripe": ("stripe.com",),
    "tensorflow": ("googleapis.com", "tensorflow.org", "google.com"),
    "torch": ("pytorch.org", "download.pytorch.org"),
}


def hosts_in_text(text: str) -> set[str]:
    return {m.group(1).strip("[]").lower() for m in URL_HOST.finditer(text)}


def looks_like_host(s: str) -> bool:
    return bool(BARE_HOST.match(s)) and len(s) <= 253


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def registrable(host: str) -> str:
    """example.co.uk -> example.co.uk, api.example.com -> example.com, 10.0.0.1 -> 10.0.0.1."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.lower().split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def name_tokens(name: str) -> set[str]:
    return {t for t in re.split(r"[-_.\s]+", name.lower()) if len(t) >= 4 and t not in GENERIC_TOKENS} | (
        {re.sub(r"[-_.\s]+", "", name.lower())} if len(name) >= 4 else set())


def declared_hosts(root: Path | None, metadata: dict | None = None) -> set[str]:
    """Hosts the package's own metadata points at: dist-info METADATA, pyproject [project.urls], registry JSON."""
    out: set[str] = set()
    metadata = metadata or {}
    info = metadata.get("info", metadata)
    for v in [*(info.get("project_urls") or {}).values(), info.get("home_page"), info.get("download_url"), info.get("package_url")]:
        if v:
            out |= hosts_in_text(str(v))
    out |= {h for h in metadata.get("declared_hosts", []) if isinstance(h, str)}
    if root is not None and root.is_dir():
        for md in list(root.glob("*.dist-info/METADATA"))[:1] + list(root.glob("*.egg-info/PKG-INFO"))[:1]:
            try:
                for line in md.read_text(errors="replace").splitlines():
                    if line.startswith(("Project-URL:", "Home-page:", "Download-URL:")):
                        out |= hosts_in_text(line)
                    elif not line.strip():
                        break  # headers end at the first blank line
            except OSError:
                pass
        pp = root / "pyproject.toml"
        if pp.is_file():
            try:
                urls = tomllib.loads(pp.read_text()).get("project", {}).get("urls", {})
                for v in urls.values():
                    out |= hosts_in_text(str(v))
            except (tomllib.TOMLDecodeError, OSError, AttributeError):
                pass
    return {h for h in out if registrable(h) not in HOSTING}


def is_declared(host: str, package: str, declared: set[str]) -> bool:
    """Is `host` accounted for by the package's metadata, its name, or its vendor family?"""
    host = host.lower()
    reg = registrable(host)
    if host in declared or reg in {registrable(d) for d in declared}:
        return True
    toks = name_tokens(package)
    label = reg.split(".")[0]
    if any(t in label or (len(label) >= 4 and label in t) for t in toks):
        return True
    for tok, domains in VENDOR_DOMAINS.items():
        if any(tok in t or t == tok for t in toks | {package.lower()}) and any(host == d or host.endswith("." + d) for d in domains):
            return True
    return False
