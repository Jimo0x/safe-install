"""Paquets populaires servant de référence pour la détection de typosquatting.

La liste est volontairement courte et embarquée : l'outil doit fonctionner
hors-ligne pour cette vérification. Tu peux l'étendre avec --popular-file.
"""

NPM = {
    "react", "react-dom", "lodash", "express", "axios", "chalk", "commander",
    "debug", "moment", "request", "async", "uuid", "underscore", "vue",
    "webpack", "typescript", "jquery", "dotenv", "yargs", "colors",
    "body-parser", "cors", "next", "eslint", "prettier", "jest", "mocha",
    "babel-core", "@babel/core", "rxjs", "tslib", "classnames", "prop-types",
    "socket.io", "mongoose", "mysql", "pg", "redis", "jsonwebtoken", "bcrypt",
    "nodemon", "glob", "minimist", "semver", "fs-extra", "inquirer", "ws",
    "cross-env", "node-fetch", "electron", "puppeteer", "sharp", "vite",
    "svelte", "angular", "zod", "dayjs", "date-fns", "styled-components",
    "tailwindcss", "postcss", "autoprefixer", "sass", "nanoid", "ethers",
    "web3", "discord.js", "coffee-script", "cross-spawn", "event-stream",
}

PYPI = {
    "requests", "numpy", "pandas", "django", "flask", "urllib3", "setuptools",
    "six", "python-dateutil", "pyyaml", "boto3", "botocore", "certifi",
    "idna", "charset-normalizer", "cryptography", "pillow", "matplotlib",
    "scipy", "scikit-learn", "tensorflow", "torch", "beautifulsoup4", "lxml",
    "selenium", "pytest", "colorama", "click", "jinja2", "sqlalchemy",
    "psycopg2", "pymongo", "redis", "fastapi", "uvicorn", "pydantic",
    "httpx", "aiohttp", "openai", "anthropic", "tqdm", "rich", "paramiko",
    "pycryptodome", "scapy", "pyinstaller", "virtualenv", "pip", "wheel",
    "black", "flake8", "mypy", "tldextract", "python-whois", "discord.py",
    "opencv-python", "keras", "transformers", "jupyter", "streamlit",
}

POPULAR = {"npm": NPM, "pypi": PYPI}
