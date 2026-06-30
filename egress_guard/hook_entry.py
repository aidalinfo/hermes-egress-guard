#!/usr/bin/env python3
"""Adaptateur hook pre_tool_call -> Egress Guard.

Contrat Hermes (agent/shell_hooks.py) :
  - stdin  : JSON {hook_event_name, tool_name, tool_input, extra}
  - stdout : pour BLOQUER -> {"decision":"block","reason":"..."}
             pour LAISSER PASSER -> rien (toute autre sortie est ignorée)
  - exit 0 dans tous les cas (la décision passe par stdout)

Câblage dans config.yaml du bot :

  hooks:
    pre_tool_call:
      - matcher: "send_email|reply_email|reply_all_email|forward_email|send_draft_email|\
upload_drive_file|upload_group_file|terminal|web_fetch|fetch|http_request|\
send_chat_message|send_channel_message|send_chat_file_message|\
delete_email|delete_ticket|close_ticket|update_contract|create_contract|\
coolify_deploy|coolify_restart|kubectl_apply|kubectl_delete"
        command: "/opt/hermes/.venv/bin/python /opt/data/workspace/tools/egress-guard/hook_entry.py"
        timeout: 5
  hooks_auto_accept: true

Variables d'environnement :
  EGRESS_GUARDRAILS   chemin absolu vers guardrails.yaml (défaut : /opt/data/guardrails.yaml)
  PULSE_GUARDRAILS    alias rétro-compatible (priorité si présent)
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from egress_guard import DEFAULT_POLICY, Decision, evaluate, load_policy  # noqa: E402


def _approvers_hint(policy: dict) -> str:
    """Construit un message lisible avec les personnes à contacter pour un gate."""
    senders = policy.get("identity", {}).get("authorized_senders", [])
    names = [s.get("user_name", s.get("email", "")) for s in senders if s.get("user_name") or s.get("email")]
    if not names:
        return "un responsable autorisé"
    if len(names) == 1:
        return names[0]
    return " ou ".join([", ".join(names[:-1]), names[-1]])


def _audit(decision: Decision, payload: dict, policy: dict) -> None:
    cfg = policy.get("audit", {})
    if decision.action not in cfg.get("log_decisions", ["log", "gate", "deny"]):
        return
    line = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": decision.action,
        "tool": payload.get("tool_name"),
        "sensitivity": decision.sensitivity,
        "tier": decision.tier,
        "reason": decision.reason,
        "input": str(payload.get("tool_input", ""))[:200],
    }
    try:
        p = Path(cfg.get("log_path", "/opt/data/logs/egress-guard.log"))
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
    except OSError:
        pass  # l'audit ne doit jamais faire échouer la décision


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return 0  # payload illisible -> fail-open léger

    # Priorité : PULSE_GUARDRAILS (rétro-compat) > EGRESS_GUARDRAILS > DEFAULT_POLICY
    policy_path = (
        os.environ.get("PULSE_GUARDRAILS")
        or os.environ.get("EGRESS_GUARDRAILS")
        or DEFAULT_POLICY
    )

    try:
        policy = load_policy(policy_path)
    except (OSError, ValueError) as exc:
        print(json.dumps({"decision": "approve",
                          "reason": f"egress-guard: politique illisible ({exc})"}))
        return 0

    decision = evaluate(payload, policy)
    _audit(decision, payload, policy)

    if decision.action == "deny":
        print(json.dumps({"decision": "block",
                          "reason": f"⛔ BLOQUÉ (egress-guard) — {decision.reason}"}))
    elif decision.action == "gate":
        approvers = _approvers_hint(policy)
        print(json.dumps({"decision": "block",
                          "reason": (
                              f"⏸️ VALIDATION HUMAINE REQUISE (egress-guard) — {decision.reason}. "
                              f"Demande une confirmation explicite à {approvers} avant de réexécuter."
                          )}))
    # allow / log -> rien (laisser passer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
