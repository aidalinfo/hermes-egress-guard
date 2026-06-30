# hermes-egress-guard

Garde-fou d'egress déterministe pour bots [Hermes](https://github.com/NousResearch/hermes) (Nous Research).

Intercepte les outils "sortants" **avant** exécution via un hook `pre_tool_call`, prend une décision en code pur (hors LLM), et bloque ou laisse passer. Insensible au prompt-injection.

```
tool call → hook pre_tool_call → hook_entry.py → egress_guard.py → allow / log / gate / deny
                                                        ↑
                                               guardrails.yaml (config par bot)
```

## Installation rapide

```bash
# Installer et câbler le hook en une commande (nécessite uv)
uvx --from git+https://github.com/aidalinfo/hermes-egress-guard egress-guard install
```

Ça fait tout automatiquement :
1. Copie `egress_guard.py` + `hook_entry.py` dans `/opt/data/workspace/tools/egress-guard/`
2. Crée `/opt/data/guardrails.yaml` depuis le template si absente
3. Patche `/opt/data/config.yaml` pour ajouter le hook (backup automatique)

Puis relancer le bot pour activer le hook.

### Options

```bash
egress-guard install \
  --config     /opt/data/config.yaml \
  --guardrails /opt/data/guardrails.yaml \
  --tools-dir  /opt/data/workspace/tools/egress-guard \
  --python     /opt/hermes/.venv/bin/python
```

### Vérifier l'installation

```bash
uvx --from git+https://github.com/aidalinfo/hermes-egress-guard egress-guard check
```

### Alternative sans uv (pipx)

```bash
pipx run --spec git+https://github.com/aidalinfo/hermes-egress-guard egress-guard install
```

## Personnaliser la politique

Après installation, éditer `/opt/data/guardrails.yaml` et renseigner les champs marqués `← À PERSONNALISER` :

| Champ | Ce qu'il contrôle |
|-------|------------------|
| `identity.internal_domains` | Domaines de l'organisation (tier `internal_verified`) |
| `identity.authorized_senders` | Responsables qui reçoivent les demandes de gate |
| `identity.self_identity` | Email du bot (exclus des approuveurs) |
| `egress.allow_hosts` | Hôtes réseau atteignables |
| `egress_tools.*.tools` | Outils MCP à surveiller (adapter au bot) |

## Philosophie

Basé sur le modèle **egress-first** v2 :

- Contrôle sur la **patte de sortie** (la plus fiable, hors délibération LLM)
- Décision **déterministe** : `risk_matrix[classe_de_donnée][tier_destination]`
- Résistant au prompt-injection — aucun jugement modèle dans la décision
- **Fail-open léger** sur politique illisible (ne bloque pas tout le runtime)

Réf. : Willison "lethal trifecta" · DeepMind CaMeL (arXiv 2503.18813) · OWASP Agentic Top 10

## Logique de décision

### Tiers de destination

| Tier | Signification |
|------|--------------|
| `internal_verified` | Domaine de l'organisation (`internal_domains`) |
| `external_known` | Partenaire listé dans `known_partner_domains` |
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

`gate` = validation humaine synchrone requise (nommée depuis `authorized_senders`).

### Gating par réversibilité

Indépendamment du contenu, certaines actions (delete, close, deploy infra) déclenchent un gate systématique.

## Audit

Décisions `log`, `gate`, `deny` journalisées dans `/opt/data/logs/egress-guard.log` (JSON, une ligne par événement). Les `allow` ne sont pas loggués.

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

C'est de l'**egress applicatif**, pas du netfilter :

- Protège uniquement les outils listés dans le `matcher` du hook
- Un process shell exécuté hors hook a un egress OS ouvert
- Complémentaire (et non substituable) à des règles réseau (iptables, WireGuard…)

## Structure

```
hermes-egress-guard/
├── egress_guard/
│   ├── __init__.py
│   ├── egress_guard.py           # Cœur déterministe (classify + evaluate)
│   ├── hook_entry.py             # Adaptateur hook Hermes pre_tool_call
│   ├── cli.py                    # CLI : egress-guard install / check
│   └── guardrails.template.yaml  # Template embarqué (copié par install)
├── config/
│   └── guardrails.template.yaml  # Même template, lisible sur GitHub
├── tests/
│   └── test_egress_guard.py
├── pyproject.toml
└── .github/workflows/ci.yml
```
