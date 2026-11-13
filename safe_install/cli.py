"""Point d'entrée : safe-install npm express | safe-install pip requests==2.32.0"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys

from . import __version__, registry
from .analyzers import Report, analyze_npm_metadata, analyze_pypi_metadata, scan_archive
from .typosquat import find_lookalikes

COLORS = {"OK": "\033[92m", "WARN": "\033[93m", "BLOCK": "\033[91m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
EXIT_CODES = {"OK": 0, "WARN": 1, "BLOCK": 2}


def analyze(ecosystem: str, spec: str, deep: bool = True) -> Report:
    eco = "pypi" if ecosystem in ("pip", "pypi") else "npm"
    name, version = registry.parse_spec(spec, eco)
    report = Report(eco, name, version)

    lookalikes = find_lookalikes(name, eco)
    if lookalikes:
        report.add(40, f"nom très proche de paquet(s) populaire(s) : {', '.join(lookalikes)} (typosquatting ?)")

    if eco == "npm":
        meta = registry.npm_metadata(name)
        report.version = registry.resolve_npm_version(meta, version)
        analyze_npm_metadata(meta, report.version, report)
        if deep:
            blob, filename = registry.npm_tarball(meta, report.version)
            scan_archive(blob, filename, report)
    else:
        meta = registry.pypi_metadata(name, version)
        report.version = version or meta["info"]["version"]
        analyze_pypi_metadata(meta, report.version, report)
        if deep:
            archive = registry.pypi_archive(meta, report.version)
            if archive:
                scan_archive(archive[0], archive[1], report)
    return report


def render(report: Report, color: bool) -> str:
    c = (lambda code: code) if color else (lambda code: "")
    lines = [
        f"{c(BOLD)}{report.name}@{report.version or '?'}{c(RESET)} ({report.ecosystem})",
        f"  score   : {report.score}/100",
        f"  verdict : {c(COLORS[report.verdict])}{c(BOLD)}{report.verdict}{c(RESET)}",
    ]
    if report.findings:
        lines.append("  raisons :")
        for f in sorted(report.findings, key=lambda f: -f.weight):
            where = f" {c(DIM)}[{f.where}]{c(RESET)}" if f.where else ""
            lines.append(f"    +{f.weight:<3} {f.message}{where}")
    else:
        lines.append("  aucun signal suspect détecté")
    return "\n".join(lines)


def run_install(ecosystem: str, specs: list[str]) -> int:
    if ecosystem == "npm":
        cmd = ["npm", "install", *specs]
    else:
        cmd = [sys.executable, "-m", "pip", "install", *specs]
    if not shutil.which(cmd[0]) and cmd[0] == "npm":
        print("npm introuvable dans le PATH", file=sys.stderr)
        return 127
    return subprocess.call(cmd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="safe-install",
        description="Analyse un paquet npm ou PyPI AVANT de l'installer (typosquatting, scripts d'installation, code suspect).",
    )
    parser.add_argument("ecosystem", choices=["npm", "pip", "pypi"])
    parser.add_argument("packages", nargs="+", help="ex: lodash, express@4.19.2, requests==2.32.0")
    parser.add_argument("--install", action="store_true", help="installe si aucun paquet n'est bloqué")
    parser.add_argument("--force", action="store_true", help="installe même si un paquet est bloqué (déconseillé)")
    parser.add_argument("--fast", action="store_true", help="métadonnées seulement, sans télécharger le code")
    parser.add_argument("--json", action="store_true", help="sortie JSON (pour la CI)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    reports, worst = [], "OK"
    for spec in args.packages:
        try:
            report = analyze(args.ecosystem, spec, deep=not args.fast)
        except registry.RegistryError as exc:
            print(f"[!] {spec} : {exc}", file=sys.stderr)
            report = Report(args.ecosystem, spec)
            report.add(50, f"analyse impossible : {exc}")
        reports.append(report)
        if EXIT_CODES[report.verdict] > EXIT_CODES[worst]:
            worst = report.verdict

    if args.json:
        print(json.dumps([r.as_dict() for r in reports], ensure_ascii=False, indent=2))
    else:
        color = sys.stdout.isatty()
        print("\n\n".join(render(r, color) for r in reports))

    if args.install:
        if worst == "BLOCK" and not args.force:
            print("\nInstallation annulée : au moins un paquet est BLOQUÉ (utilise --force pour passer outre).", file=sys.stderr)
            return EXIT_CODES[worst]
        return run_install("npm" if args.ecosystem == "npm" else "pip", args.packages)
    return EXIT_CODES[worst]


if __name__ == "__main__":
    sys.exit(main())
