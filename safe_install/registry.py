"""Accès aux registres npm et PyPI (bibliothèque standard uniquement)."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org/pypi"
USER_AGENT = "safe-install/0.1 (+https://github.com/Jimo0x/safe-install)"
MAX_DOWNLOAD = 60_000_000


class RegistryError(Exception):
    pass


def _get(url: str, limit: int = MAX_DOWNLOAD, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(limit + 1)
    except Exception as exc:  # réseau, 404, TLS...
        raise RegistryError(f"impossible de récupérer {url} : {exc}") from exc
    if len(data) > limit:
        raise RegistryError(f"réponse trop volumineuse : {url}")
    return data


def parse_spec(spec: str, ecosystem: str) -> tuple[str, str | None]:
    """'lodash@4.17.21' -> ('lodash', '4.17.21') ; 'requests==2.32.0' -> ('requests', '2.32.0')."""
    spec = spec.strip()
    if ecosystem == "npm":
        at = spec.rfind("@")
        if at > 0:  # at == 0 : paquet scopé sans version (@scope/nom)
            return spec[:at], spec[at + 1:] or None
        return spec, None
    if "==" in spec:
        name, version = spec.split("==", 1)
        return name.strip(), version.strip() or None
    return spec, None


def npm_metadata(name: str) -> dict:
    quoted = urllib.parse.quote(name, safe="@")
    return json.loads(_get(f"{NPM_REGISTRY}/{quoted.replace('/', '%2F')}"))


def pypi_metadata(name: str, version: str | None = None) -> dict:
    path = f"{urllib.parse.quote(name)}/{urllib.parse.quote(version)}" if version else urllib.parse.quote(name)
    meta = json.loads(_get(f"{PYPI_REGISTRY}/{path}/json"))
    if version:
        # L'endpoint versionné ne liste pas toutes les versions : on complète.
        meta["releases"] = json.loads(_get(f"{PYPI_REGISTRY}/{urllib.parse.quote(name)}/json")).get("releases", {})
    return meta


def resolve_npm_version(meta: dict, version: str | None) -> str:
    if version and version in meta.get("versions", {}):
        return version
    if version:
        tag = meta.get("dist-tags", {}).get(version)
        if tag:
            return tag
        raise RegistryError(f"version introuvable : {version}")
    return meta["dist-tags"]["latest"]


def npm_tarball(meta: dict, version: str) -> tuple[bytes, str]:
    url = meta["versions"][version]["dist"]["tarball"]
    return _get(url), url.rsplit("/", 1)[-1]


def pypi_archive(meta: dict, version: str) -> tuple[bytes, str] | None:
    files = meta.get("releases", {}).get(version) or meta.get("urls") or []
    # On préfère le sdist : c'est lui qui contient setup.py et le code exécuté à l'installation.
    files = sorted(files, key=lambda f: f.get("packagetype") != "sdist")
    if not files:
        return None
    return _get(files[0]["url"]), files[0]["filename"]
