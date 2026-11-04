"""Egress Guard — cœur d'enforcement déterministe (Couche A du modèle v2).

Évalue une action d'outil AVANT exécution et décide : allow / log / gate / deny.
La décision est DÉTERMINISTE (regex + règles), hors LLM : insensible au prompt
injection et à l'usurpation d'identité, et sans délibération coûteuse.

Modèle (voir guardrails.yaml) :
  décision = risk_matrix[ classe_de_donnée(contenu_sortant) ][ tier(destination) ]
  combinée avec le gating par réversibilité de l'action.

Channel-agnostic : appelé soit par le hook pre_tool_call (egress via outils),
soit par un adaptateur platform (réponse native), avec le même cœur.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:
    yaml = None

try:  # importé comme paquet (tests, CLI) ou à plat depuis le dossier du hook
    from . import capability_registry as _capreg
except ImportError:
    import capability_registry as _capreg

# Chemin par défaut dans un bot Hermes (monté sur /opt/data).
# Surcharger via la variable d'environnement EGRESS_GUARDRAILS (ou PULSE_GUARDRAILS).
DEFAULT_POLICY = Path("/opt/data/guardrails.yaml")

_RANK = {"allow": 0, "log": 1, "gate": 2, "deny": 3}
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_URL = re.compile(r"https?://([^/\s:]+)", re.I)
_SSH_HOST = re.compile(r"(?:ssh|scp|sftp|rsync)\b[^\n]*?\b[\w.-]+@([\w.-]+)", re.I)
_BARE_HOST = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.I)
_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_FILE_LIKE_TLDS = {
    "yaml", "yml", "json", "toml", "ini", "env", "txt", "md", "pdf",
    "csv", "xml", "html", "css", "js", "ts", "py", "sh", "log", "out",
    "run", "mjs", "cjs",
}
_EXFIL_RE = re.compile(r"""(?isx)
    \b(scp|rsync|sftp|nc|ncat|telnet)\b
  | \bcurl\b.*?(\s-d\b|--data|--data-binary|--data-raw|\s-F\b|--form|\s-T\b|--upload-file|-X\s*(POST|PUT|PATCH))
  | \bwget\b.*?(--post-data|--post-file|--method=(POST|PUT))
  | >\s*/dev/tcp/
""")

_PAYLOAD_OPT_RE = re.compile(r"""(?isx)
    (?<![\w-])
    (?: --data(?:-raw|-binary|-urlencode|-ascii)? | --form | --upload-file | -d | -F | -T )
    (?![\w-])
    \s+
    (?: @?"[^"]*" | @?'[^']*' | @?\S+ )
""")


# Enchaînement shell : une commande qui consomme une capacité doit être SEULE.
_SHELL_CHAIN = re.compile(r"[;|&`<>\n]|\$\(")


def _is_exfil_command(text: str) -> bool:
    return bool(_EXFIL_RE.search(text or ""))


def _strip_payloads(text: str) -> str:
    return _PAYLOAD_OPT_RE.sub(" ", text or "")


@dataclass
class Decision:
    action: str                      # allow | log | gate | deny
    reason: str = ""
    sensitivity: str = "public"
    tier: str = "n/a"
    group: str = "none"
    severity: str = "none"
    details: dict = field(default_factory=dict)

    @property
    def blocks(self) -> bool:
        return self.action in ("gate", "deny")


def load_policy(path: Path | str = DEFAULT_POLICY) -> dict:
    raw = Path(path).read_text(encoding="utf-8")
    if yaml is not None:
        return yaml.safe_load(raw)
    return json.loads(raw)


def _gather_text(value: Any) -> str:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.append(_gather_text(v))
    elif isinstance(value, (list, tuple)):
        for v in value:
            out.append(_gather_text(v))
    return "\n".join(out)


def classify_content(text: str, policy: dict) -> tuple[str, str]:
    classes = policy.get("sensitivity_classes", {})
    order = sorted(
        classes.items(),
        key=lambda kv: {"critical": 3, "high": 2, "medium": 1}.get(kv[1].get("severity"), 0),
        reverse=True,
    )
    for name, spec in order:
        for pat in spec.get("patterns", []):
            if re.search(pat, text):
                return name, spec.get("severity", "medium")
    return "public", "none"


def _domain_of(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower()


def _host_in(host: str, entries: list[str]) -> bool:
    host = host.lower().strip(".")
    for e in entries:
        e = e.lower()
        if "/" in e:
            try:
                if _IP.fullmatch(host) and ipaddress.ip_address(host) in ipaddress.ip_network(e, strict=False):
                    return True
            except ValueError:
                pass
        elif e.startswith("*."):
            if host == e[2:] or host.endswith(e[1:]):
                return True
        elif host == e:
            return True
    return False


def _is_internal_host(host: str, policy: dict) -> bool:
    idoms = policy.get("identity", {}).get("internal_domains", [])
    if any(host == d or host.endswith("." + d) for d in idoms):
        return True
    try:
        if _IP.fullmatch(host) and ipaddress.ip_address(host).is_private:
            return True
    except ValueError:
        pass
    return False


def _tier_from_emails(emails: list[str], policy: dict) -> str:
    if not emails:
        return "unknown"
    idoms = set(policy.get("identity", {}).get("internal_domains", []))
    partners = set(policy.get("identity", {}).get("known_partner_domains", []))
    tiers = set()
    for e in emails:
        d = _domain_of(e)
        if d in idoms:
            tiers.add("internal_verified")
        elif d in partners:
            tiers.add("external_known")
        else:
            tiers.add("untrusted")
    for t in ("untrusted", "external_known", "internal_verified"):
        if t in tiers:
            return t
    return "unknown"


def _extract_hosts(text: str) -> list[str]:
    hosts = list(_URL.findall(text)) + list(_SSH_HOST.findall(text))
    hosts += _IP.findall(text)
    for m in _BARE_HOST.findall(text):
        if "." not in m or m in hosts:
            continue
        suffix = m.rsplit(".", 1)[-1].lower()
        if suffix in _FILE_LIKE_TLDS:
            continue
        hosts.append(m)
    return [h.lower() for h in hosts]


def classify_destination(group: str, spec: dict, tool_input: dict,
                         context: dict, policy: dict) -> tuple[str, Optional[Decision]]:
    eg = policy.get("egress", {})

    if group == "email_send":
        emails: list[str] = []
        for key in spec.get("recipients_from", []):
            emails += _EMAIL.findall(_gather_text(tool_input.get(key, "")))
        return _tier_from_emails(emails, policy), None

    if group == "file_upload":
        return spec.get("destination_tier", "internal_verified"), None

    if group == "teams_message":
        tn = (context or {}).get(spec.get("tier_from_context", "channel_tenancy"))
        return (tn or "unknown"), None

    if group == "outbound_net":
        text = " ".join(_gather_text(tool_input.get(k, "")) for k in spec.get("destination_from", []))
        for h in _extract_hosts(text):
            if _host_in(h, eg.get("deny_hosts", [])):
                return "denied", Decision("deny", f"Hôte interdit (SSRF/metadata) : {h}",
                                          group=group, details={"host": h})
        hosts = _extract_hosts(_strip_payloads(text))
        if not hosts:
            return "no_egress", Decision("allow", group=group)
        worst = "internal_verified"
        for h in hosts:
            if _is_internal_host(h, policy):
                t = "internal_verified"
            elif _host_in(h, eg.get("allow_hosts", [])):
                t = "external_known"
            else:
                t = "untrusted"
            if _RANK_TIER(t) > _RANK_TIER(worst):
                worst = t
        return worst, None

    return "unknown", None


def _RANK_TIER(t: str) -> int:
    return {"internal_verified": 0, "external_known": 1, "untrusted": 2, "unknown": 2, "denied": 3}.get(t, 2)


def _iter_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _iter_strings(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _iter_strings(v)]
    return []


def _replace_strings(value: Any, old: str, new: str) -> Any:
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, dict):
        return {k: _replace_strings(v, old, new) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_strings(v, old, new) for v in value]
    if isinstance(value, tuple):
        return tuple(_replace_strings(v, old, new) for v in value)
    return value


def _apply_capabilities(tool: str, tool_input: dict, session_id: str, policy: dict,
                        registry: Any) -> tuple[dict, list[str], str]:
    """Masque UNE URL porteuse d'une capacité enregistrée, si son usage est conforme.

    Retourne (tool_input éventuellement masqué, empreintes consommables, motif de refus).
    Sans capacité valide et conforme, tool_input est rendu intact : le ticket reste
    classé `secrets` et le refus habituel s'applique.
    """
    if registry is None:
        return tool_input, [], ""
    specs = [(n, s) for n, s in _capreg.capability_specs(policy).items()
             if tool in s.get("consumed_by", [])]
    if not specs:
        return tool_input, [], ""
    strings = _iter_strings(tool_input)
    urls = [u for s in strings for u in _capreg.CAPABILITY_URL.findall(s)]
    note = ""
    for name, spec in specs:
        hits = [u for u in urls if _capreg.url_matches_spec(u, spec)
                and registry.valid(_capreg.digest(u), name, session_id)]
        if not hits:
            continue
        if len(hits) != 1:
            note = f"ticket '{name}' cité plusieurs fois"
            continue
        url = hits[0]
        carrier = next(s for s in strings if url in s)
        if _SHELL_CHAIN.search(carrier):
            note = f"ticket '{name}' dans une commande enchaînée (une seule commande attendue)"
            continue
        pattern = spec.get("command_pattern")
        if pattern and not re.search(pattern, carrier):
            note = f"ticket '{name}' hors de la commande prévue"
            continue
        masked = _replace_strings(tool_input, url, f"https://{_capreg.url_host(url)}/")
        allowed = {h.lower() for h in spec.get("hosts", [])}
        others = [h for h in _extract_hosts(_gather_text(masked)) if h not in allowed]
        if others:
            note = f"ticket '{name}' accompagné d'une autre destination"
            continue
        return masked, [_capreg.digest(url)], ""
    return tool_input, [], note


def _touches_registry(tool_input: dict, policy: dict) -> bool:
    if not _capreg.capability_specs(policy):
        return False
    path = _capreg.registry_path(policy)
    text = _gather_text(tool_input)
    return str(path.parent) in text or path.name in text


def _find_group(tool_name: str, policy: dict) -> tuple[Optional[str], dict]:
    for group, spec in policy.get("egress_tools", {}).items():
        if tool_name in spec.get("tools", []):
            return group, spec
    return None, {}


def _action_class_decision(tool_name: str, policy: dict) -> Optional[Decision]:
    for cls, spec in policy.get("action_classes", {}).items():
        if tool_name in spec.get("tools", []):
            dec = spec.get("decision", "allow")
            return Decision(dec, f"Action '{tool_name}' classée '{cls}' -> {dec}", group=cls)
    return None


def evaluate(payload: dict, policy: dict, registry: Any = None) -> Decision:
    """payload : {tool_name, tool_input, session_id, extra/context}. Retourne une Decision.

    `registry` : capacités temporaires enregistrées (capability_registry.Registry),
    ou None pour n'en accepter aucune. Une capacité acceptée figure dans
    `details["capabilities"]` (empreintes) : l'appelant la consomme si l'action passe.
    """
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    context = payload.get("extra", {}) or payload.get("context", {}) or {}
    session_id = payload.get("session_id") or ""

    if _touches_registry(tool_input, policy):
        return Decision("deny", f"{tool}: accès au registre des capacités interdit",
                        group="capability_registry", details={"tool": tool})

    tool_input, used_caps, cap_note = _apply_capabilities(tool, tool_input, session_id,
                                                          policy, registry)

    candidates: list[Decision] = []

    ac = _action_class_decision(tool, policy)
    if ac:
        candidates.append(ac)

    group, spec = _find_group(tool, policy)
    if group:
        tier, override = classify_destination(group, spec, tool_input, context, policy)
        if override is not None:
            candidates.append(override)
        else:
            text = _gather_text(tool_input)
            sens, sev = classify_content(text, policy)
            read_tools = spec.get("read_tools", [])
            is_read = (tool in read_tools) or (
                group == "outbound_net" and not _is_exfil_command(text))
            if is_read:
                action = "deny" if sens != "public" else "allow"
                reason = (f"{tool}: donnée sensible '{sens}' emportée vers l'extérieur -> deny"
                          if action == "deny" else "")
            else:
                action = policy.get("risk_matrix", {}).get(sens, {}).get(tier, "gate")
                reason = (f"egress {group}: donnée='{sens}'({sev}) vers tier='{tier}' -> {action}"
                          if action != "allow" else "")
            candidates.append(Decision(action, reason, sensitivity=sens, tier=tier,
                                       group=group, severity=sev,
                                       details={"tool": tool}))

    if not candidates:
        decision = Decision("allow", group="none")
    else:
        decision = max(candidates, key=lambda d: _RANK[d.action])
    if used_caps:
        decision.details = {**decision.details, "capabilities": used_caps}
    if cap_note and decision.blocks:
        decision.reason = f"{decision.reason} ({cap_note})"
    return decision
