"""CLI d'installation : egress-guard install / check"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

_PKG = Path(__file__).resolve().parent

DEFAULT_MATCHER = (
    "send_email|reply_email|reply_all_email|forward_email|send_draft_email|"
    "upload_drive_file|upload_group_file|"
    "terminal|web_fetch|fetch|http_request|"
    "send_chat_message|send_channel_message|send_chat_file_message|"
    "delete_email|delete_ticket|close_ticket|update_contract|create_contract|"
    "coolify_deploy|coolify_restart|kubectl_apply|kubectl_delete|"
    # outils de fichiers et de code : le guard leur refuse l'accès au registre des capacités
    "read_file|write_file|patch|search_files|execute_code"
)

HOOK_FILES = ("egress_guard.py", "capability_registry.py", "hook_entry.py", "post_hook_entry.py")


def _ok(m):   print(f"  ✅  {m}")
def _warn(m): print(f"  ⚠️   {m}")
def _info(m): print(f"  ℹ️   {m}")
def _err(m):  print(f"  ❌  {m}", file=sys.stderr)


# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------
def cmd_install(args) -> int:
    tools_dir   = Path(args.tools_dir)
    guardrails  = Path(args.guardrails)
    config_path = Path(args.config)
    python_bin  = args.python

    print("\n🛡️  Egress Guard — installation\n")

    # 1. Copier les fichiers Python
    tools_dir.mkdir(parents=True, exist_ok=True)
    for fname in HOOK_FILES:
        shutil.copy2(_PKG / fname, tools_dir / fname)
        _ok(f"Copié : {tools_dir / fname}")

    # 2. Policy : copier le template si absente
    if not guardrails.exists():
        template = _PKG / "guardrails.template.yaml"
        shutil.copy2(template, guardrails)
        _warn(f"Policy copiée (template) → {guardrails}")
        _warn("  Personnaliser : internal_domains, authorized_senders, allow_hosts")
    else:
        _ok(f"Policy existante conservée : {guardrails}")

    # 3. Patcher config.yaml
    if not config_path.exists():
        _warn(f"config.yaml introuvable : {config_path}")
        _info("Ajouter manuellement :")
        _print_snippet(python_bin, tools_dir, _issuers(guardrails))
        return 0

    _patch_config(config_path, python_bin, tools_dir, _issuers(guardrails))
    print("\n✅  Installation terminée — relancer le bot pour activer le hook.\n")
    return 0


def _build_hook(python_bin: str, tools_dir: Path) -> dict:
    return {
        "matcher": DEFAULT_MATCHER,
        "command": f"{python_bin} {tools_dir}/hook_entry.py",
        "timeout": 5,
    }


def _issuers(guardrails: Path) -> list[str]:
    """Noms exacts des outils émetteurs de capacités déclarés dans la politique."""
    if yaml is None or not guardrails.exists():
        return []
    try:
        policy = yaml.safe_load(guardrails.read_text("utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    names: list[str] = []
    for spec in (policy.get("capabilities") or {}).values():
        for t in (spec or {}).get("issued_by", []) or []:
            if t not in names:
                names.append(t)
    return names


def _build_post_hook(python_bin: str, tools_dir: Path, issuers: list[str]) -> dict:
    # Matcher STRICT : nom exact, ancré (un autre serveur MCP ne doit pas alimenter le registre).
    return {
        "matcher": "^(" + "|".join(re.escape(t) for t in issuers) + ")$",
        "command": f"{python_bin} {tools_dir}/post_hook_entry.py",
        "timeout": 5,
    }


def _hook_present(hooks_list: list, marker: str = "egress-guard") -> bool:
    return any(
        isinstance(h, dict) and marker in h.get("command", "")
        for h in hooks_list
    )


def _post_hook_present(hooks_list: list) -> bool:
    return _hook_present(hooks_list, "post_hook_entry.py")


def _patch_config(config_path: Path, python_bin: str, tools_dir: Path,
                  issuers: list[str] | None = None):
    issuers = issuers or []
    if yaml is None:
        _warn("pyyaml absent — snippet à copier :")
        _print_snippet(python_bin, tools_dir, issuers)
        return

    backup = config_path.with_suffix(".yaml.bak-pre-egress-guard")
    shutil.copy2(config_path, backup)
    _info(f"Backup : {backup}")

    cfg = yaml.safe_load(config_path.read_text("utf-8")) or {}
    hooks = cfg.setdefault("hooks", {})
    pre = hooks.setdefault("pre_tool_call", [])
    changed = False

    if _hook_present(pre):
        _ok("Hook pre_tool_call déjà câblé")
        for h in pre:
            if isinstance(h, dict) and "egress-guard" in h.get("command", ""):
                missing = [t for t in DEFAULT_MATCHER.split("|")
                           if t not in (h.get("matcher") or "").split("|")]
                if missing:
                    _warn("matcher pre_tool_call existant incomplet, outils absents : "
                          + ", ".join(missing))
    else:
        pre.append(_build_hook(python_bin, tools_dir))
        changed = True
        _ok("Hook pre_tool_call ajouté")

    if issuers:
        post = hooks.setdefault("post_tool_call", [])
        if _post_hook_present(post):
            _ok("Hook post_tool_call (capacités) déjà câblé")
        else:
            post.append(_build_post_hook(python_bin, tools_dir, issuers))
            changed = True
            _ok("Hook post_tool_call ajouté pour : " + ", ".join(issuers))

    if not changed:
        _ok("config.yaml déjà à jour — rien à faire")
        backup.unlink()
        return

    cfg["hooks_auto_accept"] = True

    config_path.write_text(
        yaml.dump(cfg, allow_unicode=True, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    _ok("config.yaml patché")


def _print_snippet(python_bin: str, tools_dir: Path, issuers: list[str] | None = None):
    h = _build_hook(python_bin, tools_dir)
    post = ""
    if issuers:
        ph = _build_post_hook(python_bin, tools_dir, issuers)
        post = f"""    post_tool_call:
      - matcher: "{ph['matcher']}"
        command: "{ph['command']}"
        timeout: {ph['timeout']}
"""
    print(f"""
  hooks:
    pre_tool_call:
      - matcher: "{h['matcher']}"
        command: "{h['command']}"
        timeout: {h['timeout']}
{post}  hooks_auto_accept: true
""")


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------
def cmd_check(args) -> int:
    tools_dir   = Path(args.tools_dir)
    guardrails  = Path(args.guardrails)
    config_path = Path(args.config)

    print("\n🔍  Egress Guard — vérification\n")
    issues = 0

    for fname in HOOK_FILES:
        f = tools_dir / fname
        if f.exists():
            _ok(str(f))
        else:
            _err(f"Manquant : {f}")
            issues += 1

    if guardrails.exists():
        _ok(f"Policy : {guardrails}")
    else:
        _err(f"Policy absente : {guardrails}")
        issues += 1

    if config_path.exists() and yaml is not None:
        cfg = yaml.safe_load(config_path.read_text("utf-8")) or {}
        hooks = cfg.get("hooks", {}) or {}
        if _hook_present(hooks.get("pre_tool_call", []) or []):
            _ok("Hook pre_tool_call câblé dans config.yaml")
        else:
            _err("Hook ABSENT de config.yaml — lancer : egress-guard install")
            issues += 1
        if _issuers(guardrails):
            if _post_hook_present(hooks.get("post_tool_call", []) or []):
                _ok("Hook post_tool_call (capacités) câblé")
            else:
                _err("Capacités déclarées mais hook post_tool_call ABSENT — lancer : egress-guard install")
                issues += 1
    else:
        _warn(f"config.yaml non vérifiable : {config_path}")

    print()
    return issues


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------
def _common_args(p: argparse.ArgumentParser):
    p.add_argument("--config",     default="/opt/data/config.yaml")
    p.add_argument("--guardrails", default="/opt/data/guardrails.yaml")
    p.add_argument("--tools-dir",  default="/opt/data/workspace/tools/egress-guard")
    p.add_argument("--python",     default="/opt/hermes/.venv/bin/python")


def main():
    parser = argparse.ArgumentParser(
        prog="egress-guard",
        description="Installe et configure l'egress guard sur un bot Hermes",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_install = sub.add_parser("install", help="Installe les fichiers et câble le hook")
    _common_args(p_install)

    p_check = sub.add_parser("check", help="Vérifie que l'installation est complète")
    _common_args(p_check)

    args = parser.parse_args()
    sys.exit({"install": cmd_install, "check": cmd_check}[args.cmd](args))


if __name__ == "__main__":
    main()
