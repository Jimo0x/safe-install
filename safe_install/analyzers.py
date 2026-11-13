"""Analyses statiques : rien n'est jamais exécuté ni extrait sur le disque."""

from __future__ import annotations

import io
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

MAX_FILE_BYTES = 2_000_000      # on ignore les fichiers plus gros (binaires, bundles)
MAX_TOTAL_BYTES = 50_000_000    # protection contre les archives « bombes »
MAX_MEMBERS = 5_000

INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")

# (regex, poids, explication) — appliqués au code source des paquets
CODE_PATTERNS = [
    (r"child_process|require\(['\"]child_process|execSync\(|spawnSync\(", 15, "exécute des commandes système (child_process)"),
    (r"\beval\s*\(\s*(atob|Buffer\.from|base64)", 30, "eval() sur du contenu décodé (obfuscation)"),
    (r"exec\s*\(\s*(base64\.b64decode|compile\(|codecs\.decode)", 30, "exec() sur du contenu décodé (obfuscation)"),
    (r"Buffer\.from\([^)]{40,},\s*['\"]base64['\"]\)|b64decode\(['\"][A-Za-z0-9+/=]{80,}", 15, "gros blob base64 embarqué"),
    (r"\b(curl|wget)\s+[^|;]*\|\s*(sh|bash)", 35, "télécharge et exécute un script (curl | sh)"),
    (r"os\.system\(|subprocess\.(Popen|call|run|check_output)\(", 10, "lance des processus (subprocess/os.system)"),
    (r"discord(app)?\.com/api/webhooks", 35, "envoie des données vers un webhook Discord"),
    (r"api\.telegram\.org/bot", 30, "envoie des données vers un bot Telegram"),
    (r"https?://(\d{1,3}\.){3}\d{1,3}", 20, "contacte une adresse IP en dur"),
    (r"\.ssh/id_|\.aws/credentials|\.npmrc|\.pypirc|Login Data|wallet\.dat", 35, "lit des fichiers de secrets (clés SSH, tokens, portefeuilles)"),
    (r"process\.env\b[^;\n]{0,60}(TOKEN|SECRET|KEY|PASS)|os\.environ[^\n]{0,60}(TOKEN|SECRET|KEY|PASS)", 15, "lit des variables d'environnement sensibles"),
    (r"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){40,}", 15, "chaîne hexadécimale obfusquée"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), w, why) for p, w, why in CODE_PATTERNS]
CODE_EXT = (".js", ".cjs", ".mjs", ".ts", ".py", ".sh", ".json", ".pth", ".cfg", ".toml")


@dataclass
class Finding:
    weight: int
    message: str
    where: str = ""

    def as_dict(self) -> dict:
        return {"weight": self.weight, "message": self.message, "where": self.where}


@dataclass
class Report:
    ecosystem: str
    name: str
    version: str | None = None
    findings: list[Finding] = field(default_factory=list)

    def add(self, weight: int, message: str, where: str = "") -> None:
        self.findings.append(Finding(weight, message, where))

    @property
    def score(self) -> int:
        return min(100, sum(f.weight for f in self.findings))

    @property
    def verdict(self) -> str:
        if self.score >= 50:
            return "BLOCK"
        if self.score >= 20:
            return "WARN"
        return "OK"

    def as_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "package": self.name,
            "version": self.version,
            "score": self.score,
            "verdict": self.verdict,
            "findings": [f.as_dict() for f in sorted(self.findings, key=lambda f: -f.weight)],
        }


# ─────────────────────────── code ───────────────────────────

def scan_source(text: str, where: str, report: Report, seen: set[str]) -> None:
    """Cherche les motifs dangereux. Chaque motif n'est compté qu'une fois par paquet."""
    for rx, weight, why in _COMPILED:
        if why in seen:
            continue
        if rx.search(text):
            seen.add(why)
            report.add(weight, why, where)


def iter_archive(blob: bytes, filename: str):
    """Itère (chemin, texte) sur une archive .tgz/.tar.gz/.zip/.whl, en mémoire."""
    total = 0
    if filename.endswith((".zip", ".whl")):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for i, info in enumerate(zf.infolist()):
                if i >= MAX_MEMBERS:
                    break
                if info.is_dir() or info.file_size > MAX_FILE_BYTES:
                    continue
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    break
                yield info.filename, zf.read(info).decode("utf-8", errors="ignore")
        return
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        for i, member in enumerate(tf):
            if i >= MAX_MEMBERS:
                break
            if not member.isfile() or member.size > MAX_FILE_BYTES:
                continue
            total += member.size
            if total > MAX_TOTAL_BYTES:
                break
            fh = tf.extractfile(member)
            if fh is not None:
                yield member.name, fh.read().decode("utf-8", errors="ignore")


def scan_archive(blob: bytes, filename: str, report: Report) -> None:
    seen: set[str] = set()
    for path, text in iter_archive(blob, filename):
        lower = path.lower()
        if lower.endswith(".pth"):
            # Les .pth sont exécutés au démarrage de Python : très rare et très suspect.
            if "import " in text:
                report.add(40, "fichier .pth qui exécute du code à chaque lancement de Python", path)
        if lower.endswith("/setup.py") or lower == "setup.py":
            if re.search(r"cmdclass\s*=|class\s+\w+\((install|develop|egg_info)\)", text):
                report.add(25, "setup.py remplace la commande d'installation (code exécuté au pip install)", path)
        if lower.endswith(CODE_EXT):
            scan_source(text, path, report, seen)


# ─────────────────────────── npm ───────────────────────────

def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def analyze_npm_metadata(meta: dict, version: str, report: Report, now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    versions = meta.get("versions", {})
    manifest = versions.get(version, {})
    scripts = manifest.get("scripts", {}) or {}

    hooks = {k: v for k, v in scripts.items() if k in INSTALL_HOOKS and k != "prepare"}
    for hook, cmd in hooks.items():
        report.add(25, f"script '{hook}' exécuté automatiquement à l'installation : {cmd[:120]}", "package.json")
        for rx, weight, why in _COMPILED:
            if rx.search(cmd):
                report.add(weight, f"le script '{hook}' {why}", "package.json")

    # Script d'installation qui apparaît dans cette version alors qu'il n'existait pas avant
    times = meta.get("time", {})
    ordered = sorted(
        (v for v in versions if v != version and _parse_time(times.get(v))),
        key=lambda v: _parse_time(times.get(v)),
    )
    current_time = _parse_time(times.get(version))
    previous = [v for v in ordered if current_time and _parse_time(times.get(v)) < current_time]
    if hooks and previous:
        prev_scripts = versions[previous[-1]].get("scripts", {}) or {}
        new_hooks = [h for h in hooks if h not in prev_scripts]
        if new_hooks:
            report.add(30, f"script d'installation ajouté dans cette version (absent de {previous[-1]}) : {', '.join(new_hooks)}")

    created = _parse_time(times.get("created"))
    if created and (now - created).days < 30:
        report.add(15, f"paquet créé il y a {(now - created).days} jour(s)")
    if len(versions) <= 1:
        report.add(5, "une seule version publiée")
    if not (manifest.get("repository") or meta.get("repository")):
        report.add(5, "aucun dépôt de code source déclaré")
    maint = manifest.get("maintainers") or meta.get("maintainers") or []
    if len(maint) == 0:
        report.add(5, "aucun mainteneur déclaré")


# ─────────────────────────── PyPI ───────────────────────────

def analyze_pypi_metadata(meta: dict, version: str, report: Report, now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    info = meta.get("info", {})
    releases = meta.get("releases", {})

    uploads = [
        _parse_time(f.get("upload_time_iso_8601"))
        for files in releases.values() for f in files
    ]
    uploads = [u for u in uploads if u]
    if uploads and (now - min(uploads)).days < 30:
        report.add(15, f"paquet créé il y a {(now - min(uploads)).days} jour(s)")
    if len([v for v, files in releases.items() if files]) <= 1:
        report.add(5, "une seule version publiée")

    urls = info.get("project_urls") or {}
    if not info.get("home_page") and not any("git" in (u or "") for u in urls.values()):
        report.add(5, "aucun dépôt de code source déclaré")

    files = releases.get(version, [])
    if files and all(f.get("packagetype") == "sdist" for f in files):
        report.add(10, "pas de wheel : seul un sdist existe, donc setup.py s'exécutera à l'installation")
    if info.get("yanked"):
        report.add(20, f"version retirée (yanked) : {info.get('yanked_reason') or 'sans raison'}")
