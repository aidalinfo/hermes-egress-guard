"""CLI d'installation : egress-guard install / check"""
from __future__ import annotations

import argparse
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
    "coolify_deploy|coolify_restart|kubectl_apply|kubectl_delete"
)


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
    for fname in ("egress_guard.py", "hook_entry.py"):
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
        _print_snippet(python_bin, tools_dir)
        return 0

    _patch_config(config_path, python_bin, tools_dir)
    print("\n✅  Installation terminée — relancer le bot pour activer le hook.\n")
    return 0


def _build_hook(python_bin: str, tools_dir: Path) -> dict:
    return {
        "matcher": DEFAULT_MATCHER,
        "command": f"{python_bin} {tools_dir}/hook_entry.py",
        "timeout": 5,
    }


def _hook_present(hooks_list: list, marker: str = "egress-guard") -> bool:
    return any(
        isinstance(h, dict) and marker in h.get("command", "")
        for h in hooks_list
    )


def _patch_config(config_path: Path, python_bin: str, tools_dir: Path):
    if yaml is None:
        _warn("pyyaml absent — snippet à copier :")
        _print_snippet(python_bin, tools_dir)
        return

    backup = config_path.with_suffix(".yaml.bak-pre-egress-guard")
    shutil.copy2(config_path, backup)
    _info(f"Backup : {backup}")

    cfg = yaml.safe_load(config_path.read_text("utf-8")) or {}
    pre = cfg.setdefault("hooks", {}).setdefault("pre_tool_call", [])

    if _hook_present(pre):
        _ok("Hook déjà câblé dans config.yaml — rien à faire")
        backup.unlink()
        return

    pre.append(_build_hook(python_bin, tools_dir))
    cfg["hooks_auto_accept"] = True

    config_path.write_text(
        yaml.dump(cfg, allow_unicode=True, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    _ok("config.yaml patché : hook ajouté")


def _print_snippet(python_bin: str, tools_dir: Path):
    h = _build_hook(python_bin, tools_dir)
    print(f"""
  hooks:
    pre_tool_call:
      - matcher: "{h['matcher']}"
        command: "{h['command']}"
        timeout: {h['timeout']}
  hooks_auto_accept: true
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

    for fname in ("egress_guard.py", "hook_entry.py"):
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
        pre = cfg.get("hooks", {}).get("pre_tool_call", [])
        if _hook_present(pre):
            _ok("Hook câblé dans config.yaml")
        else:
            _err("Hook ABSENT de config.yaml — lancer : egress-guard install")
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
