#!/usr/bin/env python3
"""Adaptateur hook post_tool_call -> registre des capacités (issue #1).

Contrat Hermes (agent/shell_hooks.py, model_tools.py) :
  - stdin  : JSON {hook_event_name, tool_name, tool_input, session_id, extra}
             extra.result = résultat de l'outil (chaîne JSON), extra.status = ok|error|blocked
  - hook OBSERVATEUR : la sortie est ignorée ; exit 0 dans tous les cas
  - appelé de façon synchrone, avant que le résultat ne parvienne au modèle

Seuls les outils listés dans `capabilities.<nom>.issued_by` enregistrent quelque
chose. Le résultat contient le ticket en clair : ce script n'en écrit que
l'empreinte SHA-256, ne journalise rien et n'imprime rien.

Câblage dans config.yaml du bot (matcher STRICT, nom exact de l'outil émetteur) :

  hooks:
    post_tool_call:
      - matcher: "^mcp__motion_studio__deck_push_begin$"
        command: "/opt/hermes/.venv/bin/python /opt/data/workspace/tools/egress-guard/post_hook_entry.py"
        timeout: 5
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from egress_guard import DEFAULT_POLICY, load_policy  # noqa: E402
import capability_registry as capreg  # noqa: E402


def handle(payload: dict, policy: dict) -> list[str]:
    """Enregistre les capacités émises par l'appel décrit dans `payload`."""
    tool = payload.get("tool_name") or ""
    extra = payload.get("extra") or {}
    if (extra.get("status") or "ok") != "ok":
        return []
    if not any(tool in s.get("issued_by", []) for s in capreg.capability_specs(policy).values()):
        return []
    result = extra.get("result")
    if result is None:
        return []
    with capreg.open_locked(capreg.registry_path(policy)) as reg:
        return capreg.register_from_result(tool, result, payload.get("session_id") or "",
                                           policy, reg)


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        policy_path = (os.environ.get("PULSE_GUARDRAILS")
                       or os.environ.get("EGRESS_GUARDRAILS") or DEFAULT_POLICY)
        handle(payload, load_policy(policy_path))
    except Exception:  # noqa: BLE001 — observateur : ne jamais gêner l'agent
        pass  # rien d'enregistré -> le ticket reste refusé comme secret
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
