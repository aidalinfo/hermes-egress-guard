# hermes-egress-guard

Garde-fou d'egress déterministe pour bots [Hermes](https://github.com/NousResearch/hermes) (Nous Research).

Intercepte les outils "sortants" **avant** exécution via un hook `pre_tool_call`, prend une décision en code pur (hors LLM), et bloque ou laisse passer. Insensible au prompt-injection.

```
tool call → hook pre_tool_call → hook_entry.py → egress_guard.py → allow / log / gate / deny
                                                        ↑
                                               guardrails.yaml (config par bot)
```

## Installation rapide

> **Prérequis :** [`uv`](https://docs.astral.sh/uv/getting-started/installation/) installé sur la machine ou dans le conteneur.
> ```bash
> curl -LsSf https://astral.sh/uv/install.sh | sh
> ```

```bash
# 1. Installer et câbler le hook
uvx --from git+https://github.com/aidalinfo/hermes-egress-guard egress-guard install

# 2. Personnaliser la politique (voir section ci-dessous)
nano /opt/data/guardrails.yaml

# 3. Vérifier
uvx --from git+https://github.com/aidalinfo/hermes-egress-guard egress-guard check

# 4. Relancer le bot
```

`install` fait automatiquement :
1. Copie `egress_guard.py` + `hook_entry.py` → `/opt/data/workspace/tools/egress-guard/`
2. Crée `/opt/data/guardrails.yaml` depuis le template (si absente)
3. Patche `/opt/data/config.yaml` pour ajouter le hook + `hooks_auto_accept: true` (backup automatique)

La commande est **idempotente** : relancée sur un bot déjà équipé, elle ne duplique pas le hook.

### Chemins non standard

```bash
uvx --from git+https://github.com/aidalinfo/hermes-egress-guard egress-guard install \
  --config     /opt/data/config.yaml \
  --guardrails /opt/data/guardrails.yaml \
  --tools-dir  /opt/data/workspace/tools/egress-guard \
  --python     /opt/hermes/.venv/bin/python
```

### Alternative (pipx)

```bash
pipx run --spec git+https://github.com/aidalinfo/hermes-egress-guard egress-guard install
```

### Via Docker (depuis l'hôte)

```bash
docker exec <container> sh -c "
  curl -LsSf https://astral.sh/uv/install.sh | sh &&
  uvx --from git+https://github.com/aidalinfo/hermes-egress-guard egress-guard install
"
```

## Personnaliser la politique

Éditer `/opt/data/guardrails.yaml` et renseigner les champs marqués `← À PERSONNALISER` :

| Champ | Ce qu'il contrôle |
|-------|------------------|
| `identity.internal_domains` | Domaines de l'organisation → tier `internal_verified` |
| `identity.authorized_senders` | Personnes contactées pour valider un `gate` |
| `identity.self_identity` | Email du bot (exclu des approuveurs) |
| `egress.allow_hosts` | Hôtes réseau atteignables (défaut-deny sur le reste) |
| `egress_tools.*.tools` | Outils MCP à surveiller (adapter à ceux installés sur le bot) |

Le template est consultable ici : [`config/guardrails.template.yaml`](config/guardrails.template.yaml).

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

`gate` = validation humaine synchrone requise, message adressé aux `authorized_senders`.

### Gating par réversibilité

Indépendamment du contenu, certaines actions (suppression, fermeture, déploiement infra) déclenchent un `gate` systématique, configuré dans `action_classes`.

## Audit

Décisions `log`, `gate`, `deny` journalisées dans `/opt/data/logs/egress-guard.log` (JSON, une ligne par événement). Les `allow` ne sont pas loggués (volume).

## Tests

```bash
# Depuis ce repo, standalone
python3 tests/test_egress_guard.py

# Avec pytest
pip install pytest pyyaml
pytest tests/ -v

# Avec la politique réelle d'un bot
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
│   └── guardrails.template.yaml  # Template embarqué dans le package pip/uvx
├── config/
│   └── guardrails.template.yaml  # Même template, lisible sur GitHub
├── tests/
│   └── test_egress_guard.py
├── pyproject.toml
└── .github/workflows/ci.yml
```
