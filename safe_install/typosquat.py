"""Détection de noms de paquets qui imitent un paquet populaire."""

from __future__ import annotations

import re

from .popular import POPULAR


def normalize(name: str) -> str:
    """Normalise un nom (PEP 503 pour PyPI, minuscules pour npm)."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def damerau_levenshtein(a: str, b: str) -> int:
    """Distance d'édition avec transpositions (optimal string alignment)."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _strip_scope(name: str) -> str:
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def find_lookalikes(name: str, ecosystem: str, extra: set[str] | None = None) -> list[str]:
    """Retourne les paquets populaires que `name` semble imiter.

    Un paquet qui EST populaire n'imite personne : liste vide.
    """
    reference = {normalize(p) for p in POPULAR.get(ecosystem, set()) | (extra or set())}
    target = normalize(name)
    if target in reference:
        return []

    hits = []
    bare = normalize(_strip_scope(name))
    for popular in sorted(reference):
        pop_bare = normalize(_strip_scope(popular))
        if bare == pop_bare:
            # ex: "@evil/lodash" qui reprend le nom exact d'un paquet connu
            hits.append(popular)
            continue
        # Les noms très courts produisent trop de faux positifs.
        if min(len(bare), len(pop_bare)) < 4:
            continue
        limit = 1 if len(pop_bare) <= 6 else 2
        if damerau_levenshtein(bare, pop_bare) <= limit:
            hits.append(popular)
            continue
        # Suffixes/préfixes trompeurs : "requests-secure", "py-lodash"...
        if re.fullmatch(rf"(py|node|js)?-?{re.escape(pop_bare)}-?(js|py|dev|secure|official|v\d+)?", bare):
            hits.append(popular)
    return hits
