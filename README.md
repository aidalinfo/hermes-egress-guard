# hermes-egress-guard

Garde-fou d'egress déterministe pour bots [Hermes](https://github.com/NousResearch/hermes) (Nous Research).

Intercepte les outils "sortants" **avant** exécution via un hook `pre_tool_call`, prend une décision en code pur (hors LLM), et bloque ou laisse passer. Insensible au prompt-injection.

```
tool call → hook pre_tool_call → hook_entry.py → egress_guard.py → allow / log / gate / deny
                                                        ↑
                                               guardrails.yaml (config du bot)
```

## Philosophie

Basé sur le modèle **egress-first** v2 :

- Contrôle sur la **patte de sortie** (la plus fiable, hors délibération LLM)
- Décision **déterministe** : `risk_matrix[classe_de_donnée][tier_destination]`
- Résistant au prompt-injection (pas de jugement modèle dans la décision)
- **Fail-open léger** sur politique illisible (ne bloque pas tout le runtime)

Réf. : Willison "lethal trifecta" · DeepMind CaMeL (arXiv 2503.18813) · OWASP Agentic Top 10

## Installation

### 1. Copier les fichiers sur le bot

```bash
# Dans /opt/data/workspace/tools/egress-guard/ du conteneur
mkdir -p /opt/data/workspace/tools/egress-guard
cp egress_guard/egress_guard.py /opt/data/workspace/tools/egress-guard/
cp egress_guard/hook_entry.py   /opt/data/workspace/tools/egress-guard/
```

### 2. Créer la politique du bot

```bash
cp config/guardrails.template.yaml /opt/data/guardrails.yaml
# Éditer les sections marquées "← À PERSONNALISER"
```

Les champs à adapter par bot :

| Champ | Description |
|-------|-------------|
| `identity.internal_domains` | Domaines de l'organisation |
| `identity.authorized_senders` | Responsables qui reçoivent les demandes de gate |
| `identity.self_identity` | Email du bot |
| `egress.allow_hosts` | Hôtes réseau légitimes |
| `egress_tools.*.tools` | Outils MCP installés sur ce bot |

### 3. Câbler le hook dans `config.yaml` du bot

```yaml
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
```

**Adapter le `matcher`** aux outils réellement installés sur le bot (inutile de lister des outils absents).

### 4. Variables d'environnement (optionnel)

```bash
# Chemin de la politique (défaut : /opt/data/guardrails.yaml)
EGRESS_GUARDRAILS=/opt/data/guardrails.yaml

# Alias rétro-compatible avec l'installation d'origine
PULSE_GUARDRAILS=/opt/data/pulse-mcp-guardrails.yaml
```

## Logique de décision

### Tiers de destination

| Tier | Signification |
|------|--------------|
| `internal_verified` | Domaine de l'organisation (internal_domains) |
| `external_known` | Partenaire listé dans known_partner_domains |
| `untrusted` | Hors tenant, guest Teams |
| `unknown` | Tenancy indéterminée (envoi proactif/cron) |

### Classes de données

| Classe | Sévérité | Exemples |
|--------|----------|---------|
| `secrets` | critical | API keys, tokens, clés SSH, JWT |
| `infra_inventory` | high | IPs privées, namespaces k8s, apps Coolify |
| `commercial_sensitive` | medium | Marges, SIREN en lot, remises |
| `public` | none | Contenu non sensible |

### Table de risque par défaut

|                     | internal_verified | external_known | untrusted | unknown |
|---------------------|:-----------------:|:--------------:|:---------:|:-------:|
| **secrets**         | deny              | deny           | deny      | deny    |
| **infra_inventory** | allow             | gate           | deny      | deny    |
| **commercial**      | allow             | gate           | gate      | gate    |
| **public**          | allow             | log            | gate      | log     |

### Gating par réversibilité

Indépendamment du contenu, certaines actions (suppression, fermeture, déploiement infra) nécessitent une validation humaine synchrone avant exécution.

## Audit

Les décisions `log`, `gate`, `deny` sont journalisées dans `/opt/data/logs/egress-guard.log` (JSON, une ligne par événement). Les `allow` ne sont pas loggués (volume).

## Tests

```bash
# Standalone
python3 tests/test_egress_guard.py

# Avec pytest
pip install pytest pyyaml
pytest tests/ -v

# Avec une politique de bot réelle
EGRESS_GUARDRAILS=/opt/data/guardrails.yaml pytest tests/ -v
```

## Limites assumées

Ce garde-fou est de l'**egress applicatif**, pas du netfilter :

- Protège uniquement les outils listés dans le `matcher` du hook
- Un `terminal` exécutant un process arbitraire hors hook a un egress OS ouvert
- Complémentaire (et non substituable) à des règles réseau (iptables, WireGuard, etc.)

## Structure

```
hermes-egress-guard/
├── egress_guard/
│   ├── __init__.py
│   ├── egress_guard.py      # Cœur déterministe (classify + evaluate)
│   └── hook_entry.py        # Adaptateur hook Hermes pre_tool_call
├── config/
│   └── guardrails.template.yaml  # Template à personnaliser par bot
├── tests/
│   └── test_egress_guard.py
└── .github/workflows/ci.yml
```
