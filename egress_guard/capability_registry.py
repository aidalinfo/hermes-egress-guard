"""Registre des capacités temporaires émises par un outil de confiance (issue #1).

Un outil déclaré dans `capabilities.<nom>.issued_by` (ex. le `deck_push_begin` du
MCP Studio) rend un ticket d'upload : une URL porteuse d'une signature, valable
quelques minutes. Le garde la classe `secrets` (forme JWT) et refuse donc de la
laisser passer dans une commande.

Le hook `post_tool_call` (post_hook_entry.py) lit le RÉSULTAT de l'outil émetteur
— que le modèle ne peut pas fabriquer — et y enregistre l'empreinte de chaque URL
porteuse de ticket vers un hôte prévu par la politique. Le hook `pre_tool_call`
n'accepte ensuite cette URL que :
  - si son empreinte est au registre, non expirée, de la même session ;
  - vers un hôte de la capacité, dans un outil et une forme de commande prévus ;
  - une seule fois (consommation sous verrou exclusif : deux uploads concurrents
    ne peuvent pas utiliser le même ticket).

Le registre ne contient JAMAIS le ticket : seulement son empreinte SHA-256, le nom
de la capacité, l'expiration et la session.

Limite assumée : le registre est un fichier du même utilisateur que l'agent. Le
garde refuse les appels d'outil qui le citent, mais un script obfusqué pourrait
l'écrire — comme il pourrait déjà exfiltrer sans passer par le garde. Une entrée
forgée ne permet d'envoyer qu'aux hôtes déclarés de la capacité.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

DEFAULT_REGISTRY = Path("/opt/data/egress-guard/capabilities.json")

# URL complète, arrêtée aux guillemets, espaces et barres obliques inverses
# (le résultat d'un outil MCP contient souvent du JSON échappé dans une chaîne).
CAPABILITY_URL = re.compile(r"""https?://[^\s"'<>\\`]+""", re.I)
_HOST = re.compile(r"^https?://([^/:?#]+)", re.I)


def digest(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def url_host(url: str) -> str:
    m = _HOST.match(url)
    return m.group(1).lower() if m else ""


def registry_path(policy: dict) -> Path:
    raw = (policy.get("capability_registry") or {}).get("path")
    return Path(raw) if raw else DEFAULT_REGISTRY


def capability_specs(policy: dict) -> dict:
    caps = policy.get("capabilities") or {}
    return {name: spec for name, spec in caps.items() if isinstance(spec, dict)}


def url_matches_spec(url: str, spec: dict) -> bool:
    """L'URL vise-t-elle un hôte (et un préfixe de chemin) déclaré par la capacité ?"""
    host = url_host(url)
    hosts = [h.lower() for h in spec.get("hosts", [])]
    if not host or host not in hosts:
        return False
    prefix = spec.get("path_prefix")
    if prefix:
        rest = url[url.lower().index(host) + len(host):]
        rest = re.sub(r"^:\d+", "", rest)
        if not rest.startswith(prefix):
            return False
    return True


class Registry:
    """Vue en mémoire du registre. `entries` : {empreinte: {cap, exp, session}}."""

    def __init__(self, entries: Optional[dict] = None, now: Optional[float] = None):
        self.entries: dict = dict(entries or {})
        self.now = time.time() if now is None else now
        self.consumed: set[str] = set()

    def valid(self, url_digest: str, capability: str, session_id: str = "") -> bool:
        e = self.entries.get(url_digest)
        if not e or e.get("cap") != capability:
            return False
        if float(e.get("exp", 0)) <= self.now:
            return False
        bound = e.get("session") or ""
        if bound and session_id and bound != session_id:
            return False
        if bound and not session_id:
            return False
        return True

    def add(self, url_digest: str, capability: str, ttl: float, session_id: str = "") -> None:
        self.entries[url_digest] = {"cap": capability, "exp": self.now + ttl,
                                    "session": session_id or ""}

    def consume(self, digests: list[str]) -> None:
        for d in digests:
            self.entries.pop(d, None)
            self.consumed.add(d)

    def purge(self) -> None:
        self.entries = {d: e for d, e in self.entries.items()
                        if float(e.get("exp", 0)) > self.now}


@contextmanager
def open_locked(path: Path) -> Iterator[Registry]:
    """Ouvre le registre sous verrou EXCLUSIF et le réécrit atomiquement à la sortie.

    Le verrou couvre lecture, décision et écriture : deux hooks concurrents ne
    peuvent pas consommer le même ticket.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            entries = json.loads(path.read_text("utf-8"))
            if not isinstance(entries, dict):
                entries = {}
        except (OSError, ValueError):
            entries = {}
        reg = Registry(entries)
        before = json.dumps(reg.entries, sort_keys=True)
        yield reg
        reg.purge()
        if json.dumps(reg.entries, sort_keys=True) != before or not path.exists():
            tmp = path.with_name(path.name + ".tmp")
            fd_tmp = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd_tmp, "w", encoding="utf-8") as f:
                json.dump(reg.entries, f)
            os.replace(tmp, path)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def register_from_result(tool_name: str, result: object, session_id: str,
                         policy: dict, reg: Registry) -> list[str]:
    """Enregistre les URL porteuses de ticket trouvées dans le résultat d'un émetteur.

    Retourne les noms de capacités enregistrées (jamais les URL).
    """
    text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
    added: list[str] = []
    for name, spec in capability_specs(policy).items():
        if tool_name not in spec.get("issued_by", []):
            continue
        ttl = float(spec.get("ttl_seconds", 900))
        for url in set(CAPABILITY_URL.findall(text or "")):
            if url_matches_spec(url, spec):
                reg.add(digest(url), name, ttl, session_id)
                added.append(name)
    return added
