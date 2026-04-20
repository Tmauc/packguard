# PackGuard — Contexte & Plan

> Document de référence du projet. À lire en premier pour comprendre les décisions prises, ce qui est dans le scope, et ce qui a été reporté.
> Créé le 2026-04-20.

---

## 1. Vision

PackGuard est un outil **standalone, 100 % local, multi-repo, multi-écosystème** pour gouverner les versions de packages avec :

- Un **policy engine d'offset** (ex. `latest - 1`) pour rester volontairement en retrait de `latest` et se protéger des régressions et attaques supply-chain récentes.
- Un **dashboard interactif** pour visualiser les versions, leurs timelines, leurs changelogs, leurs relations et leur compatibilité.
- Une **intelligence supply-chain** agrégée (CVE, malwares, typosquats, dependency confusion) avec support de fonctionnement hors-ligne.
- Une portabilité totale : même binaire qui tourne sur PC dev, en CI dans un repo, ou sur un serveur client.

**Différenciateurs** face à Dependabot / Renovate / Snyk / Socket :
- Policy offset native.
- Timeline visuelle des versions et des releases.
- Graphe interactif + chaînes contaminées surlignées.
- 100 % local, zéro dépendance cloud, mode air-gap possible.

---

## 2. Forme de l'app — décision finale

**1 binaire Rust statique, 3 modes, dashboard web embarqué.**

```
packguard scan       → mode headless (CI, hook git, cron)
packguard sync       → refresh des caches (vulns, metadata)
packguard ui         → lance le dashboard sur localhost
  (packguard serve   → v2 : team mode, Docker)
```

Déployable sur :
| Cible | Mode |
|---|---|
| PC dev | `ui` |
| CI / dans le repo | `scan` (SARIF, exit-code policy) |
| Serveur client (v2) | `serve` via image Docker |

**Non-choix explicites :** pas de SaaS cloud, pas de desktop natif (Tauri/Electron), pas d'extension IDE en v1.

---

## 3. Stack technique

### Core (Rust)
- `clap` — CLI args
- `tokio` — async runtime
- `reqwest` — HTTP registres
- `rusqlite` ou `sqlx` — SQLite (WAL mode)
- `serde` + `serde_json` / `toml` / `serde_yaml`
- `semver`, `node-semver-rs`, `pep440_rs` — dialectes semver
- `axum` — serveur HTTP pour le mode `ui`
- `rust-embed` — assets Vite bundlés dans le binaire
- `git2` — clone GitHub Advisory DB
- `tracing` — logs structurés

### Dashboard
- Vite + React + TypeScript
- Tailwind + shadcn/ui
- TanStack Query
- Cytoscape.js (graphe — Phase 5)
- visx ou recharts (timeline — Phase 4)

### Dev tooling
- `cargo-nextest`, `cargo-insta`
- `just` ou `cargo-make`

---

## 4. Écosystèmes — scope

### ✅ Tier 1 — MVP (Phase 1)
| Écosystème | Package managers | Fichiers |
|---|---|---|
| npm | npm, pnpm, yarn (classic + berry) | `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` |
| PyPI | pip, poetry, uv, pdm | `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock` |

### 🟢 Tier 2 — post-MVP
- crates.io (Rust) — `Cargo.toml`, `Cargo.lock`
- Go modules — `go.mod`, `go.sum`

### 🟡 Tier 3 — v2
- Maven / Gradle (Java, Kotlin, Scala)
- Packagist (PHP) — `composer.json`, `composer.lock`
- RubyGems — `Gemfile`, `Gemfile.lock`
- NuGet (.NET) — `*.csproj`, `packages.lock.json`

### 🔵 Tier 4 — opportuniste
Hex (Elixir), Pub (Dart/Flutter), Swift PM, CocoaPods, CPAN, CRAN, Conan/vcpkg, Mix, Hackage, OPAM.

### ❌ Hors scope définitif
| Catégorie | Raison |
|---|---|
| Package managers OS (apt, brew, yum, pacman, choco, scoop, winget) | Dépendances système, pas applicatives |
| Images Docker / Helm charts | Artefacts de déploiement ; outillage saturé (Trivy, Grype) |
| Nix / Guix | Modèle fonctionnel atypique, niche |
| Homebrew Taps, AUR | Distribution, pas deps projet |
| Git submodules | Pas de notion de version semver |
| Vendored / copié-collé | Pas traçable |
| Binaires téléchargés hors registry | Pas de manifest |
| CDN imports directs (`<script src=...>`) | Parsing HTML trop bruité |
| LaTeX/CTAN et autres sans registre stable | Pas de source de vérité |

### Zones grises (best-effort)
- Git dependencies → ref affiché, pas de "latest"
- Registres privés → supportés si credentials dans env/config standard
- Pre-releases → inclus/exclus selon `policy.stability`
- Deprecated mais pas yanked → badge, non bloquant par défaut
- Forks/renames → détection via metadata, pas d'auto-migration

---

## 5. Architecture d'extensibilité

Un trait `Ecosystem` en Rust ; chaque écosystème = un module qui l'implémente. Le core ne sait rien de spécifique à npm ou pip.

```rust
trait Ecosystem: Send + Sync {
    fn id(&self) -> &'static str;                         // "npm", "pypi"…
    fn detect(&self, root: &Path) -> Vec<Project>;        // trouve manifests
    fn parse(&self, project: &Project) -> Result<DepSet>; // → schéma commun
    fn registry(&self) -> &dyn Registry;                  // client HTTP
    fn semver(&self) -> &dyn SemverDialect;               // règles de compare
    fn changelog(&self, pkg: &Pkg) -> Vec<ReleaseNote>;
}
```

Ajouter un écosystème = ~400 lignes, zéro modif du core / dashboard / policy.

**Couches communes mutualisées :**
- Normalisation semver → `enum { Patch, Minor, Major, Pre, Incompatible }`
- Client HTTP + cache ETag partagé
- OSV.dev nomme nativement tous les écosystèmes → un seul chemin vuln-intel
- Schéma SQLite identique (colonne `ecosystem`)

---

## 6. Policy engine — format cible

Fichier `.packguard.yml` à la racine du repo :

```yaml
defaults:
  offset: -1                # latest major-1
  allow_patch: true
  allow_security_patch: true
  stability: stable         # exclut prereleases
  min_age_days: 7           # ignore releases < 7j (anti supply-chain)
  block:
    cve_severity: [high, critical]
    malware: true
    deprecated: true
    yanked: true
overrides:
  - match: "react"
    offset: 0
  - match: "lodash"
    pin: "4.17.21"
  - match: "@babel/*"
    offset: -2
groups:
  - name: security-critical
    match: ["jsonwebtoken", "bcrypt*", "@auth/*"]
    offset: 0
    min_age_days: 0
```

Pour chaque dep, le moteur calcule la **version recommandée** =
`max(versions publiées) filtrée par policy`.

---

## 7. Stratégie offline

Trois niveaux ; v1 gère 1 & 2, niveau 3 reporté.

### Niveau 1 — Online (défaut)
`scan` fetch à la volée + cache SQLite.

### Niveau 2 — Snapshot
```
packguard sync              # seul moment réseau
packguard scan --offline    # lit cache, erreur si donnée absente
```
`sync` télécharge :
- **Vulns** : dumps OSV.dev par écosystème (`osv-vulnerabilities/<eco>/all.zip`), repo git GitHub Advisory, repo git PyPI Advisory.
- **Metadata packages** : versions + dates pour chaque package déjà vu, indexé par `(ecosystem, name, etag)`.
- **Changelogs** : lazy, GitHub API au besoin.

### Niveau 3 — Air-gapped (reporté v2)
Bundles signés `packguard bundle export` / `import` via USB/partage.

---

## 8. Modèle de données (SQLite)

```
repos(id, path, ecosystem, fingerprint, last_scan_at)
workspaces(id, repo_id, name, manifest_path)
packages(id, ecosystem, name, latest, latest_fetched_at)
package_versions(pkg_id, version, published_at, deprecated, yanked, metadata_json)
dependencies(workspace_id, pkg_id, declared_range, installed, kind, source_lockfile)
vulnerabilities(id, source, pkg_id, affected_range, severity, cve_id, published_at, url)
malware_reports(id, pkg_id, version, source, reported_at, evidence)
compatibility(pkg_id, version, peer_deps_json, engines_json)
policies(scope, pattern, rule_json)
scan_history(id, repo_id, ts, diff_json)
alerts(id, repo_id, type, payload_json, seen_at)
```

---

## 9. Sources de données supply-chain

- **OSV.dev** — agrégateur Google, gratuit, universel, dumps publics — base principale
- **GitHub Advisory Database** — repo git public `github/advisory-database`
- **PyPI Advisory DB** — repo git public
- **Socket.dev** — API, malware & typosquat (freemium)
- **deps.dev** — Google, graphe dépendances + scorecard
- **OpenSSF Scorecard** — score de santé des projets
- **CVE NVD** — fallback CVE ID
- Scraping opportuniste (BleepingComputer, Socket blog, Phylum, GitHub Security Lab) → "compromise events" normalisés ; toujours préférer les API aux scrapes.

Chaque version porte des badges : `cve` / `malware` / `typosquat` / `yanked` / `deprecated`.

---

## 10. Dashboard — vues prévues

1. **Overview** — health score, risques, stats (outdated, vulns, pinned)
2. **Packages table** — filtres (ecosystem, status, compliance policy), badges colorés
3. **Package detail** — timeline versions, changelog parsé, matrice compat, historique local
4. **Dependency graph** (Cytoscape) — chaînes vers vulns surlignées
5. **Policies editor** — UI + preview des effets
6. **Alerts feed** — nouvelles CVE/malware sur tes packages
7. **Compare** — snapshot N vs N+1, breaking changes détectés

**Codes visuels :**
- 🔴 Critical / malware
- 🟠 Major behind or High CVE
- 🟡 Minor/patch behind
- 🟢 Compliant
- 🏴‍☠️ Compromis connu
- ⏳ Trop récent (min_age)

---

## 11. Commandes CLI prévues

```
packguard init                       # crée .packguard.yml
packguard scan [path]                # scan + write SQLite
packguard sync                       # refresh vulns + metadata
packguard report                     # rapport CLI coloré
packguard recommend                  # liste des bumps conformes policy
packguard apply --dry-run            # diff manifests
packguard ui                         # dashboard localhost
packguard watch                      # re-scan on file change
packguard audit                      # scan vulns + malware uniquement
packguard export --format json|sarif|md
```

Intégration CI : `packguard scan --fail-on-violation --format sarif`.

---

## 12. Roadmap

| Phase | Contenu | État |
|---|---|---|
| **0 — Spike** | POC Rust qui scan un projet npm + query registry npm + classif semver + sortie table | ✅ done (2026-04-20, 3 commits, 12 tests) |
| **1 — MVP CLI** | npm/pnpm/yarn + pip/poetry/uv, policy offset, SQLite, report CLI | ✅ done (2026-04-20, 9 commits, 71 tests, 4 crates) |
| **1.5 — Historique versions** | Persister `package_versions` complet + resolver policy précis (offset exact, `min_age_days`, `stability`) | ✅ done (2026-04-20, 3 commits, 87 tests) |
| **2 — Vuln intel online** | OSV + GH Advisory, cache, badges | ✅ done (2026-04-20, 6 commits, 126 tests, 5 crates, 8 CVE détectées sur Nalo) |
| **2.5 — Malware & typosquat** | MAL entries OSV/GHSA + typosquat heuristique + Socket.dev opt-in + `block.malware` | 🎯 en cours |
| **3 — Sync offline (niveau 2)** | `sync` + `--offline`, dumps | |
| **4 — Dashboard v1** | `ui` → localhost, Vite+React, table + détail + timeline | |
| **5 — Graph + compat** | Cytoscape, peer deps, chaînes contaminées | |
| **6 — Supply-chain+** | Socket/Phylum/Scorecard, typosquat, min_age | |
| **7 — Apply & CI** | `apply --dry-run`, SARIF export | |

### Reporté v2+
- Mode `serve` équipe + image Docker
- Air-gapped (niveau 3 offline, bundles signés)
- Postgres backend (via trait `Store`)
- Extension IDE (VSCode/JetBrains)
- Auth SSO/OIDC
- Desktop natif (Tauri) — à réévaluer seulement sur demande
- Écosystèmes Tier 2 : Cargo, Go
- Écosystèmes Tier 3 : Maven/Gradle, Composer, RubyGems, NuGet
- Auth classique (login/password) du mode `serve` — à implémenter le jour du `serve`

---

## 13. Phase 0 — Spike ✅ done (2026-04-20)

**Livré :** workspace `crates/packguard-core` + `crates/packguard-cli`, 3 commits, 12 tests verts, validé en live contre `registry.npmjs.org`.

- `470c136` — scaffold workspace + parsing npm manifest/lockfile
- `f82184c` — client registre async
- `dc548ff` — commande `scan` + table colorée + smoke test offline

**Validé :**
- Détection manifest/lockfile (package.json + lockfile v2/v3, scoped packages, skip nested)
- Parsing JSON robuste (4 catégories de deps, rejet lockfile v1)
- Registry client async, concurrence bornée (16 par défaut), timeout 10s, rustls-only
- Classif semver (Current / Patch / Minor / Major / Unknown) via crate `semver`
- CLI (clap : `--offline`, `--concurrency`, table colorée)

**Démo réelle :**
```
react        18.2.0  → 19.2.5   major
@babel/core  7.24.0  → 7.29.0   minor
typescript   5.4.5   → 6.0.3    major
```

**Volontairement laissé hors du spike (→ Phase 1) :** SQLite, policy engine, Python, peer deps, dashboard.

---

## 14. Phase 1 — MVP CLI ✅ done (2026-04-20)

**Livré :** 9 commits, 71 tests verts, clippy clean, fmt OK. Validé live sur `../monorepo` (front/vesta pnpm + services/incentive Poetry).

**Architecture livrée :**
```
crates/
├── packguard-core     # Ecosystem trait, npm (package-lock + pnpm-lock), pypi
├── packguard-policy   # YAML parser, resolver dialect-aware, evaluate_dependency
├── packguard-store    # rusqlite + refinery 0.9, schéma §8 complet
└── packguard-cli      # scan / init / report
```

**Commits clés :**
- `5a78154` refactor(core): extract `Ecosystem` trait
- `3788822` feat(core): pypi ecosystem (pip/poetry/uv)
- `87d1684` feat(store): rusqlite + refinery persistence
- `f8e573c` feat(policy): YAML rules + recommendation engine
- `cf9fe19` feat(cli): `packguard init`
- `7f55330` feat(cli): `packguard report` (compliance + sarif/json/table)
- `2f922ce` fix(core): pnpm-lock.yaml + tolerate non-string npm time entries

**Critères de sortie — tous verts :**
- ✅ `packguard init` détecte auto les écosystèmes
- ✅ `scan` lit npm + pypi, écrit SQLite, skip sur fingerprint inchangé
- ✅ `report` : tableau groupé + compliance + résumé + sarif/json/table
- ✅ `--fail-on-violation` → exit 1
- ✅ `scan --offline` échoue proprement si cache vide
- ✅ README racine : usage, limitation pip, format policy
- ✅ 71 tests verts (> 40 visés), clippy & fmt OK

**Spec Phase 1 (pour historique) — détail du découpage 1.1 → 1.5 archivé ci-dessous :**

<details>
<summary>Scope originel</summary>

Découpage en 5 sous-lots :
- **1.1** multi-écosystème via trait `Ecosystem` (npm refacto + PyPI pip/poetry/uv, PEP 440)
- **1.2** SQLite store (`rusqlite` + `refinery`, schéma §8, WAL)
- **1.3** policy engine (`.packguard.yml` : defaults + overrides + groups, glob, `compute_recommended_version`)
- **1.4** `packguard init` (détection auto + YAML conservateur + `--force`)
- **1.5** rapport CLI enrichi (`report` distinct de `scan`, groupé, compliance, `--format`, `--fail-on-violation`)

Décisions verrouillées Phase 1 :
- PyPI : pip + poetry + uv ensemble, pip en declared-only mode
- Store : `rusqlite` + `refinery`
- Pas de `.packguard.yml` dans `../monorepo` ; usage uniquement en lecture comme cible de test

</details>

---

## 14.5. Phase 1.5 — Historique versions ✅ done (2026-04-20)

**Livré :** 3 commits, 87 tests verts (+16), clippy & fmt clean. Dette #1 soldée.

**Commits :**
- `be9bf9b` feat(core,store): fetch + persist full version history
- `e359112` feat(policy,cli): strict offset resolver + `InsufficientCandidates` status
- `68da896` test(policy): resolver snapshot tests + `block.deprecated`/`yanked` bonus

**Validation live — `report` sur Nalo/services/incentive, avant vs après :**

```
Avant (Phase 1, fallback major-distance) :
  { compliant: 5, warnings: 20, violations: 2 }

Après (Phase 1.5, resolver strict) :
  { compliant: 3, warnings: 21, violations: 2, insufficient: 3 }
```

Shifts de statut confirment le gain de précision :
- `fastapi` : compliant → warning (`0.120.4` → `0.136.0` dans la fenêtre offset-1, raté par le fallback)
- `rich` : compliant → warning (`14.1.0` → `14.2.0`)
- `psycopg`, `sepaxml` : warning → insufficient (saut de major, pas de release dans latest-1)
- `types-requests` : déplacement similaire

**Volumétrie store :** historique complet persisté — 358 versions `faker`, 329 `sentry-sdk`, 322 `sqlalchemy`, 290 `fastapi`. Flags `yanked`/`deprecated` détectés (ex : `pydantic 1.10.3`, `pytest 8.1.0`, `requests 2.32.0`).

**Bonus livré (sous-lot 1.5.3) :** `block.deprecated` et `block.yanked` câblés. Si la version installée match une release flaggée, le resolver retourne `Violation` avec message explicite. Couvert par snapshots sur fixture `node-ipc` (versions `10.1.1`/`10.1.2` yanked+deprecated).

### Notes saillantes — à connaître pour Phase 2

1. **Sémantique `offset` durcie :** recommandation = max version ≤ `latest_major - N`. Si la major cible n'existe pas (ex: package ayant sauté 2.x → 3.x sans 2 stable récent), retour `InsufficientCandidates` plutôt qu'approximation. Le fallback major-distance de Phase 1 est volontairement supprimé.

2. **`min_age_days` sans date** : si un registre ne retourne pas de `published_at` pour une release, elle est **gardée** (principe du bénéfice du doute). PyPI expose systématiquement la date ; npm dans ~99 % des cas. Pas d'impact observé.

3. **`InsufficientCandidates` ≠ violation** : `--fail-on-violation` ne se déclenche pas sur `insufficient`. Design volontaire : c'est un signal neutre ("la policy ne peut pas se prononcer"), affiché en **magenta** dans la table et comme `"status": "insufficient"` en JSON. Sinon, les users seraient forcés de changer leur policy à chaque saut de major — antipattern.

4. **`block.cve_severity` et `block.malware`** : toujours parsés/stockés mais non évalués → Phase 2 quand OSV entrera. Aucun changement par rapport au brief.

5. **Fixtures réutilisables Phase 2 :** 4 fixtures JSON réelles ajoutées — `react` (12 versions), `django` (10), `@babel/core` (8), `node-ipc` (yanked/deprecated) — dans `crates/packguard-policy/tests/fixtures/registries/`. Réutilisables pour tests intégration OSV (affected_ranges vs historique).

<details>
<summary>Spec Phase 1.5 (pour historique)</summary>

Découpage en 3 sous-lots :
- **1.5.1** alimenter `package_versions` depuis scanners (npm `time.<ver>`, PyPI `releases.<ver>`), insertion bulk idempotente
- **1.5.2** resolver policy consomme l'historique : offset strict + `min_age_days` + `stability`, nouveau variant `PolicyInsufficientCandidates`
- **1.5.3** fixtures JSON riches + snapshot tests (5+), démo avant/après sur Nalo

Bonus autorisé : `block.deprecated`/`block.yanked` (trivial avec les colonnes en place).

</details>

---

## 14.6. Phase 2 — Vuln intel online ✅ done (2026-04-20)

**Livré :** 6 commits, 126 tests verts (+39, incluant 2 gated live), clippy & fmt clean, nouveau crate `packguard-intel`. **8 vraies CVE détectées** sur Nalo/monorepo (5 en PyPI, 3 en npm).

**Commits :**
- `48cf293` feat(core,store): schema V2 + vulnerability types + store APIs
- `aec3010` feat(intel,cli): crate `packguard-intel` + `sync` fetches OSV + GHSA
- `178bf21` feat(intel): dialect-aware vulnerability matching engine
- `42f11a2` feat(policy,cli): `VulnerabilityViolation` + `block.cve_severity` + remediation
- `c540fc0` feat(cli): `audit` command + CVE column + vuln footer in report
- `477200d` feat(intel,cli): OSV `/v1/query` fallback + gated live tests

**Architecture finale (5 crates) :**
```
crates/
├── packguard-core     # Ecosystem trait + Severity + AffectedSpec + Vulnerability types
├── packguard-policy   # YAML + dialect-aware resolver + VulnerabilityViolation + remediation
├── packguard-store    # rusqlite + refinery V2 + vuln upsert + sync_log
├── packguard-intel    # ← NOUVEAU : OSV dumps + GHSA git + API fallback + dialect matcher + alias dedup
└── packguard-cli      # scan / init / sync / report / audit
```

**Démo Nalo/monorepo — vraies CVE détectées :**

*services/incentive (Poetry, 27 deps) — 5 CVE :*
```
pillow     12.0.0   CVE-2026-25990   high    fix: 12.1.1
pillow     12.0.0   CVE-2026-28171   high    fix: 12.2.0
pyjwt      2.10.1   CVE-2026-32597   high    fix: 2.12.0
pytest     8.4.2    CVE-2026-8877    medium  fix: 9.0.3
requests   2.32.5   CVE-2026-25645   medium  fix: 2.33.0
```

*front/vesta (pnpm, 91 deps) — 3 CVE :*
```
eslint    9.25.0    CVE-2026-12345   medium  fix: 9.26.0
lodash    4.17.23   CVE-2026-4800    high    fix: 4.18.0
lodash    4.17.23   CVE-2026-4802    medium  fix: 4.18.0
```

**Impact `report` (avec `block.cve_severity: [high, critical]` par défaut) :**
- Avant Phase 2 : `3 compliant · 17 warnings · 0 violations · 4 insufficient`
- Après Phase 2 : `3 compliant · 16 warnings · 4 violations · 4 insufficient` + 🟠 3 high · 🟡 2 medium en pied
- `pyjwt`, `pillow`, `lodash` passent en `VulnerabilityViolation` → `--fail-on-violation` = exit 1

**Volumétrie `sync` :**
```
osv-npm  — scanned 21770, persisted 94 (watched)
osv-pypi — scanned 19085, persisted 168 (watched)
Store holds 262 advisories.
```
10 s bout-en-bout (download + parse + filter + persist). Deuxième run → `304 Not Modified` sur les dumps, `git pull --ff-only` sur GHSA, rien persisté.

### Notes saillantes — à connaître pour Phase 2.5 et au-delà

1. **Dépendance `policy → intel` :** `packguard-policy` a gagné une dépendance sur `packguard-intel` pour accéder à `MatchedVuln`. Pas de cycle (intel ne dépend que de core). Alternative envisagée (pousser `MatchedVuln` dans core) rejetée pour garder les types près de leur logique de production.

2. **GHSA sans `libgit2`/`gix` :** shell-out à `git` (présent en dev/CI), pas de dépendance native, build plus rapide. Si `git` absent du PATH → erreur claire. Trade-off conscient vs complexité `git2`.

3. **Dedup OSV × GHSA au match-time** (union-find sur aliases), pas à l'insertion. Raison : PK `(source, advisory_id, pkg_id)` reste simple, pas de merge complexe au write, et le matcher voit de toute façon les doublons. Les deux URLs sources sont préservées (exposées via `source` dans l'audit JSON).

4. **Filtrage "watched-only"** : `sync` ne persiste que les vulns affectant des packages déjà dans `packages`. Sans ça la DB explose (~262 entries utiles vs 200K+). Le fallback API OSV couvre les nouveaux packages (cas CI-warmup ou `scan` avant `sync`).

5. **`VulnerabilityViolation` bloquante** (comme spec). `--fail-on-violation` se déclenche sur CVE, pas seulement sur pins/majors-behind. Label SARIF distingue `cve-violation` des autres policy violations pour UI/alerting.

6. **Remediation ne traverse pas les majors.** Si la reco du resolver est vulnérable, itération descendante sur les candidates **dans la fenêtre offset autorisée**. Si tout est vulnérable dans la fenêtre → `InsufficientCandidates`. Respect strict de la sémantique offset.

7. **TTL fallback API 24h** tracé via `sync_log` avec clés dynamiques `osv-api:{eco}:{name}`. Premier `audit` sur un nouveau package → appel live ; dans l'heure → cache. Après 24h → requery.

8. **Bug trouvé & corrigé dans 2.4** : le matcher n'indexait que les versions présentes dans `package_versions`. Si la version installée n'y était pas (vieux stores peuplés avant 1.5), le check CVE ne se déclenchait pas. Surface par les tests d'intégration, fix dans le même commit.

9. **Tech-debts non touchées comme demandé :**
   - #2 (lockfiles pnpm nested / yarn.lock) → reporté à la demande
   - #3 (`block.cve_severity` ✅ fait ; `block.malware` → Phase 2.5)
   - #5 (note `refinery 0.9`) → informatif
   - #4 (live tests gated) **✅ résolue** via `PACKGUARD_LIVE_TESTS=1`

<details>
<summary>Spec Phase 2 (pour historique)</summary>

5 sous-lots : 2.1 fetch & store OSV+GHSA (dedup aliases), 2.2 matching dialect-aware (`semver` / `pep440_rs`), 2.3 policy integration (`VulnerabilityViolation` + remediation itérative), 2.4 CLI (`audit` + colonne CVE + footer), 2.5 fallback API OSV TTL 24h.

Décisions : dumps OSV prioritaires, API fallback opt-in (`--no-live-fallback`), GHSA via git clone + filtre `github-reviewed/`.

</details>

---

## 14.7. Phase 2.5 — Malware & typosquat 🎯 en cours

**Objectif :** compléter l'intelligence supply-chain de PackGuard avec la **détection de packages malveillants et typosquats**, en réutilisant au maximum l'infrastructure `packguard-intel` déjà en place. Évaluer `block.malware` dans le resolver. Exposer les résultats dans `audit` et `report` avec une distinction visuelle claire vis-à-vis des CVE.

### Sources Phase 2.5

**Tier 1 (gratuit, sans auth, directement exploitable) :**
- **OSV.dev entrées `MAL-*`** — déjà dans les dumps téléchargés Phase 2 ! Filtrer les entries avec ID préfixé `MAL-` ou `database_specific.severity = "malicious"`
- **GHSA entries type `malware`** — également déjà dans les dumps Phase 2, filtrer par `database_specific.github_reviewed_at` + type

**Tier 2 (opt-in, auth requise) :**
- **Socket.dev API** — `https://api.socket.dev/v0/npm/{name}/{version}` (npm surtout, PyPI partiel). Score + issues (malware, obfuscation, install scripts, typosquat, …). Free tier suffisant. Token via env `PACKGUARD_SOCKET_TOKEN`

**Tier 3 (heuristique locale, pas d'API externe) :**
- **Typosquat via Levenshtein** sur listes top-N des écosystèmes :
  - npm top 5000 : récupéré depuis `https://raw.githubusercontent.com/npm/registry/main/popular-packages.json` (ou equivalent communautaire) une fois lors du `sync`
  - PyPI top 15000 : `https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json`
  - Cachées dans `~/.packguard/cache/reference/{eco}-top-packages.json`
- Distance d'édition ≤ 2 + check de swaps de caractères + prefix/suffix additions

**Tier 4 (bonus si ça ne déborde pas) :**
- **Phylum** — pattern identique à Socket (API + token). Second opinion / redondance. Skip silencieux si non configuré

### Sous-lots

#### 2.5.1 — Harvest MAL entries déjà présentes
- `packguard-intel` gagne un module `malware::harvest_existing` qui parcourt les entries OSV + GHSA déjà en cache
- Filtrage : OSV ID commençant par `MAL-`, ou `database_specific.type == "malicious-package"`, ou GHSA `database_specific.severity == "malware"`
- Schéma : réutiliser la table `malware_reports(id, pkg_id, version, source, reported_at, evidence)` du §8
- Dedup par `(source, id, pkg_id, version)`, `evidence` = JSON brut de l'entry

#### 2.5.2 — Typosquat heuristique local
- Télécharger les listes top-N lors du `sync` (une fois par semaine, TTL 7j configurable)
- Algorithme de scoring typosquat :
  1. Pour un package `X` **pas** dans le top-N : trouver tout `Y` dans top-N tel que `levenshtein(X, Y) ≤ 2` (ignorer `X == Y`)
  2. Si match → calculer confiance : `1.0` pour swap 1 caractère, `0.7` pour insertion/délétion, `0.5` pour préfixes (`node-` / `py-` / `lib-`) ou suffixes (`-js` / `-py`)
  3. Filtres anti-faux-positifs : exclure scoped (`@org/pkg` pas typosquat de `pkg`) ; exclure si `X` est dans une liste blanche maintenue par la communauté (ex : packages officiels avec noms similaires) ; exclure les noms < 4 caractères
- Résultat stocké en `malware_reports` avec `source = "typosquat-heuristic"` + `evidence.{score, resembles, distance}`

#### 2.5.3 — Socket.dev opt-in
- Si `PACKGUARD_SOCKET_TOKEN` présent dans l'env OU `.packguard.yml` contient `intel.socket.enabled: true` → activation
- Fetch pour chaque package watched : score package + issues
- Rate limit + backoff, concurrence bornée (même pattern que OSV API fallback)
- Résultats stockés dans `malware_reports` avec `source = "socket.dev"` + `evidence = response JSON`
- Sans token → skip silencieux, pas d'erreur
- Documenté dans README : comment obtenir un token free tier

#### 2.5.4 — Policy integration + nouveau variant
- Le YAML policy accepte désormais `block.malware: true|false` (déjà parsé, à évaluer) et **nouveau** `block.typosquat: strict|warn|off` (par défaut `warn` — non-bloquant, juste signal)
- Nouveau variant `Compliance::MalwareViolation(Vec<MalwareHit>)` — bloquante (comptée dans violations, déclenche `--fail-on-violation`)
- `Compliance::TyposquatWarning(Vec<TyposquatHit>)` — **non** bloquante, affichée comme warning avec couleur distincte
- Pour `block.typosquat: strict` → `TyposquatHit` remonte en `MalwareViolation` bloquante
- Ordre d'évaluation : `block.deprecated`/`yanked` (Phase 1.5) → `block.cve_severity` (Phase 2) → `block.malware` (Phase 2.5) → `block.typosquat` (Phase 2.5)
- Le resolver/remediation iterates de la même façon pour skipper les versions malware (identique au skip CVE Phase 2)

#### 2.5.5 — CLI enrichment
- **`packguard audit`** gagne des sections :
  - Actuelle : `CVE/GHSA` (Phase 2)
  - Nouvelle : `Malware` avec colonnes `package`, `installed`, `source` (OSV-MAL / GHSA / Socket), `evidence summary`
  - Nouvelle : `Typosquat suspects` avec colonnes `package`, `resembles`, `score`
  - Nouveau flag `--focus cve|malware|typosquat|all` (défaut `all`)
  - Nouveau flag `--fail-on-malware` → exit 1 si ≥ 1 malware détecté
- **`packguard report`** : la colonne `CVE` devient `Risk` (plus générale) :
  - Format : `2🔴 · 1🟠 · 1🏴‍☠️` (CVE critical + CVE high + malware)
  - Pied résumé gagne `malware: { confirmed: N, suspected_typosquat: M }`
  - Icône 🏴‍☠️ = malware confirmé, ⚠️ = typosquat suspect

#### 2.5.6 — Bonus : Phylum (si bandwidth)
- Pattern identique à Socket : `PACKGUARD_PHYLUM_TOKEN`, `intel.phylum.enabled: true`
- Source `phylum.io` dans `malware_reports`
- Si les deux Socket et Phylum sont actifs → dedup au match-time (même union-find pattern que OSV×GHSA en Phase 2)
- Autorisé seulement si Phases 2.5.1 → 2.5.5 sont livrées ET tests à jour

### Critères de sortie

- [ ] `packguard sync` récupère : MAL entries OSV/GHSA (harvest) + top-N lists (npm + pypi) + Socket scores (si token)
- [ ] Table `malware_reports` peuplée avec `source` distinguant origine (`osv-mal`, `ghsa-malware`, `typosquat-heuristic`, `socket.dev`)
- [ ] Typosquat heuristique testé : 10+ cas positifs connus (`colors` → `collors`, `lodash` → `lodahs`, `requests` → `request`, `discord.js` → `discord-js`, …) et 10+ cas négatifs (packages légitimes avec noms similaires)
- [ ] `block.malware` évalué → `MalwareViolation` bloquante
- [ ] `block.typosquat` évalué → `TyposquatWarning` par défaut, `MalwareViolation` si `strict`
- [ ] Remediation : resolver saute les versions malware comme pour CVE
- [ ] `audit --focus malware` / `--focus typosquat` / `--fail-on-malware`
- [ ] `report` colonne unifiée `Risk` (CVE + malware + typosquat), résumé enrichi
- [ ] Socket opt-in : token via env ou config, skip silencieux sans, README documente setup
- [ ] Démo Nalo/monorepo : chiffres avant/après pour malware + typosquat (attendu : 0 malware confirmé, N suspects typosquat à valider manuellement)
- [ ] 25+ nouveaux tests, clippy `-D warnings` clean, fmt OK
- [ ] `PACKGUARD_LIVE_TESTS=1` : ajout tests live Socket.dev si token configuré

### Hors scope Phase 2.5
- **Scraping blogs** (BleepingComputer, Socket blog, Phylum research) → jamais en tant que source primaire. Si besoin de signal ad-hoc → alertes Phase 6+
- **Auto-remediation** qui change le pin vers une version safe → Phase 7 (`apply --dry-run`)
- **Dashboard visuel** des malwares → Phase 4
- **Chaînes contaminées transitives** via malware → Phase 5 (graphe)
- **OpenSSF Scorecard** intégration → Phase 6 (signal complémentaire, pas malware per se)
- **Phylum obligatoire** — reste bonus opt-in identique à Socket

### Nouvelles dépendances prévisibles
- `strsim` (crate Rust, petit, pure Rust) pour Levenshtein + swaps
- Pas de nouvelle crate HTTP ni de libgit2

---

## 15. Tech debt & follow-ups (remontés Phase 1)

À traiter en Phase 1.5 ou intégré à une phase ultérieure. Ordre par priorité :

1. ~~**Store : enrichir l'historique des versions**~~ **✅ résolu Phase 1.5** (commits `be9bf9b` + `e359112`). Historique complet persisté pour npm + PyPI ; resolver strict ; `InsufficientCandidates` remonté proprement. Cf. §14.5.

2. **Parsers lockfiles manquants** *(limitation usage réel)*
   - pnpm-lock.yaml : **supporté racine uniquement**. Workspaces pnpm imbriqués reportés.
   - yarn.lock (classic + berry) : **non parsé** — seul `package.json` est utilisé en fallback.
   - À traiter quand un repo cible les exigera (Nalo front est pnpm root, ça passe).

3. **Évaluation `block.*`** — partiellement résolu :
   - ✅ `block.deprecated` / `block.yanked` câblés Phase 1.5
   - ✅ `block.cve_severity` câblé Phase 2 (commit `42f11a2`, `VulnerabilityViolation`)
   - ⏳ `block.malware` → Phase 2.5 (Socket.dev / Phylum / heuristiques typosquat)

4. ~~**Tests live gated**~~ **✅ résolu Phase 2** (commit `477200d`). `PACKGUARD_LIVE_TESTS=1` opt-in pour 2 tests live contre l'API OSV.

5. **Choix dépendance noté** *(informatif)*
   - `refinery 0.9` retenu (et non 0.8) car 0.8 pinne `rusqlite ≤ 0.26`, incompatible avec la version courante. Aucun impact fonctionnel.

---

## 16. Décisions verrouillées ✅

**Objectif :** passer du spike fonctionnel à un MVP CLI utilisable — multi-écosystèmes, persistance, policy, rapport structuré.

### Découpage en 5 sous-lots (ordre imposé)

#### 1.1 — Multi-écosystème via trait `Ecosystem`
- Refactor le code npm existant derrière le trait `Ecosystem` (cf. §5)
- Ajouter l'écosystème PyPI : **pip + poetry + uv ensemble**
- Parsers : `requirements*.txt`, `pyproject.toml` (sections `[project]` et `[tool.poetry]`), `poetry.lock`, `uv.lock`
- Client registre : `https://pypi.org/pypi/{name}/json`
- Dialecte semver : **PEP 440** via crate `pep440_rs`
- **Pip en "declared-only mode"** : pas de lockfile natif → classif sur latest publiée, limitation documentée dans le README
- Détection monorepo Python (pyproject workspaces) — best-effort

#### 1.2 — SQLite store
- `rusqlite` + `refinery` pour migrations
- Schéma conforme à §8
- WAL mode, fichier `~/.packguard/store.db` (override via `--store`)
- Nouveau crate `packguard-store`
- Refactor `scan` pour persister : repos, packages, versions, dependencies, scan_history

#### 1.3 — Policy engine
- Parser `.packguard.yml` conforme à §6 (defaults + overrides + groups)
- Support : `offset`, `pin`, `allow_patch`, `allow_security_patch`, `stability`, `min_age_days`, `block.{cve_severity, malware, deprecated, yanked}`
- Glob matching sur noms de packages (`@babel/*`, `bcrypt*`)
- `compute_recommended_version(package, all_versions, policy) -> Version`
- Tests unitaires riches (overrides qui se chevauchent, groups vs overrides, prereleases)

#### 1.4 — `packguard init`
- Auto-détection des écosystèmes présents
- Génère un `.packguard.yml` sensé avec defaults conservateurs : `offset: -1`, `allow_patch: true`, `stability: stable`, `min_age_days: 7`, bloque critical/high CVE et malware
- Refuse d'écraser un fichier existant sauf `--force`
- En-tête pointant vers la doc

#### 1.5 — Rapport CLI enrichi
- `packguard report` distinct de `scan` : lit SQLite, zéro réseau
- Grouping : écosystème → workspace → package
- Colonne "Policy" avec compliance (✅ compliant / ⚠️ warning / ❌ violation)
- Summary : # compliant / warnings / violations bloquantes
- `--fail-on-violation` → exit `1` si ≥ 1 violation bloquante
- `--format table|json|sarif` (sarif minimal, seulement violations bloquantes)

### Décisions verrouillées Phase 1
1. PyPI : pip + poetry + uv dans 1.1 (pas de séparation), pip en declared-only
2. Store : `rusqlite` + `refinery`
3. Pas de `.packguard.yml` dans `../monorepo`. PackGuard reste isolé. `../monorepo` utilisable uniquement en lecture comme cible de test manuel.

### Contraintes techniques
- Étendre le workspace existant, pas de refonte
- Nouveaux crates bienvenus si ça clarifie (`packguard-store`, `packguard-policy`, `packguard-ecosystem-pypi`…)
- Tous les parsers → snapshot tests (`cargo-insta`) sur fixtures
- Tests d'intégration live contre vrai registre gated par `PACKGUARD_LIVE_TESTS=1`
- Concurrence bornée + timeout sur HTTP, rustls-only
- Pas de `unwrap()`/`expect()` hors tests ; erreurs via `thiserror` + `anyhow`
- 40+ tests verts, `cargo clippy -- -D warnings` clean, `cargo fmt` OK

### Critères de sortie
- [ ] `packguard init` dans un repo Nalo (front/vesta + services/incentive) produit un `.packguard.yml` sensé
- [ ] `packguard scan` lit npm ET pypi, écrit SQLite, skip si fingerprint inchangé
- [ ] `packguard report` : tableau groupé + compliance + résumé
- [ ] `--fail-on-violation` → exit `1` sur violation bloquante
- [ ] `packguard scan --offline` échoue proprement si cache vide (message explicite)
- [ ] README racine : usage, limitation pip, format policy
- [ ] 40+ tests verts, clippy clean, fmt OK

### Hors scope Phase 1 (à NE PAS faire)
- Vulns / CVE / OSV → Phase 2
- `sync` offline niveau 2 → Phase 3
- Dashboard web → Phase 4
- Graphe / peer deps / compat matrix → Phase 5
- Malware / typosquat / Socket.dev → Phase 6
- `apply` / modification de manifests → Phase 7
- Mode `serve` / Docker / auth → v2
- Cargo, Go, Maven, autres → Tier 2/3

### Attentes de delivery
- Commits atomiques par sous-lot, messages conventionnels (`feat(core)`, `feat(cli)`, `feat(store)`, `test`, `refactor`)
- Chaque sous-lot laisse le workspace compilable + testé
- Hésitation sur un design → documenter alternatives dans le commit ou `DESIGN_NOTES.md`, ne pas demander 10 questions
- À remonter : blocage architectural imprévu, edge case qui change le scope, critère de sortie inatteignable
- Rapport final attendu : format identique à Phase 0 (commits + tests + démo + notes)

---

## 15. Décisions verrouillées ✅

| Dimension | Choix |
|---|---|
| Nom | **PackGuard** |
| Forme | 1 binaire, 3 modes (`scan` / `sync` / `ui`) |
| Core | Rust |
| Dashboard | Vite + React + shadcn/ui + Tailwind |
| Store | SQLite (WAL) via `rusqlite` + `refinery` |
| Offline | Niveaux 1 (online) + 2 (snapshot) en v1 |
| Écosystèmes MVP | npm/pnpm/yarn + pip/poetry/uv |
| Auth `serve` | Reportée v2 (basic login/pw à l'époque) |
| Cloud | Explicitement hors scope |

---

## 16. Questions en suspens

- Aucune bloquante.
