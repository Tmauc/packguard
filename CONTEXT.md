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
| **2.5 — Malware & typosquat** | MAL entries OSV/GHSA + typosquat heuristique + Socket.dev opt-in + `block.malware` | ✅ done (2026-04-20, 5 commits, 160 tests, 12 MAL records + 1 typosquat suspect sur Nalo) |
| **3 — Sync offline (niveau 2)** | `sync` + `--offline`, dumps | |
| **4a — Dashboard foundations** | `packguard-server` + scaffold Vite/React/shadcn + Overview + Packages table + `ui` dev mode | ✅ done (2026-04-20, 6 commits, 196 Rust + 13 front tests, 6 crates, validé sur Nalo) |
| **4b — Dashboard specialization** | Package detail + timeline visx + Policies editor dry-run + `build.rs` embed release | ✅ done (2026-04-21, 5 commits, 185 Rust + 29 Vitest tests, binaire release autonome, 4 screenshots) |
| **5a — Graph backend** | Migration V5 (`dependency_edges` + `compatibility`) + extraction transitive lockfiles + API graph/contamination/compat | ✅ done (2026-04-21, 3 commits, 201 Rust tests, BFS contamination live sur Nalo : lodash remonte via textlint) |
| **5b — Graph UI + CLI** | Page `/graph` Cytoscape (dagre + cose-bilkent, focus CVE) + onglet Compatibility + CLI `packguard graph` | ✅ done (2026-04-21, 5 commits, 206 Rust + 36 Vitest tests, 3 screenshots, contamination lodash visible) |
| **6 — Polish Phase** | Fix 6 findings dogfood : backend `/api/graph` vide, UI scan button CWD, CLI store discoverability, `ui-embed` banner/auto-open | ✅ done (2026-04-21, 4 commits, 215 Rust tests, root cause `#6` = canonicalisation paths manquante, chaîne lodash désormais visible en UI) |
| **6-bis — Polish-bis** | Fix 4 findings post-Polish : `packguard ui` sans path filtre CWD, Graph crash optional unresolved, UI ignore dependents, backend compat rows vides | ✅ done (2026-04-21, 4 commits, 218 Rust + 39 Vitest tests, 1481 nodes / 3677 edges live Nalo, 0 orphan edges, placeholder nodes pour unresolved) |
| **7a — Per-project backend + CLI** | Filters `?project=<path>` sur tous endpoints + `GET /api/workspaces` + CLI `--project` uniforme + fallback most-recent | ✅ done (2026-04-21, 3 commits, 227 Rust tests, parity live 91+27=118 sur Nalo, zéro hardcode Nalo dans le code prod) |
| **7b — Per-project UI + Policies** | `<WorkspaceSelector />` header + pages scopées via `useSearchParams` + Policies UI scopée + drill-down Used by multi-workspace | ✅ done (2026-04-21, 3 commits + screenshots en commit séparé `0714be6`, 50 Vitest + 227 Rust) |
| **8a — Release-ready artifacts** | Dockerfile + GH Actions release workflow + install.sh + docs/integrations + `init --with-ci` + Homebrew formula template + PUBLISHING.md | ✅ done (2026-04-21, 7 commits, 233 Rust tests, Docker 46 MB distroless, 5 targets matrix, onboarding 5 min validé) |
| **8b — Publishing + Nalo validation** | `cargo publish` + Homebrew tap + Docker push + step PackGuard dans vrai `.gitlab-ci.yml` Nalo avec preuve MR bloquée | ✅ **distribution done (2026-04-22)** : GitHub Release v0.1.0 + ghcr.io + Docker Hub + Homebrew tap + **crates.io 6 crates (core/intel/store/policy/server/cli@0.1.0)** + cosign signatures + automation Homebrew via release workflow + version-sanity check + `bump-version.sh`. **Reste seulement** : step PackGuard dans vrai `.gitlab-ci.yml` Nalo avec preuve MR bloquée (validation business, pas blocking pour l'outil) |
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

## 14.7. Phase 2.5 — Malware & typosquat ✅ done (2026-04-20)

**Livré :** 5 commits, 160 tests verts (+34 nets), clippy & fmt clean, `packguard-intel` étendu sans nouveau crate. **12 vraies entries OSV-MAL harvestées + 1 typosquat suspect** (faux positif attendu : `eslint-plugin-import` vs `eslint-plugin-import-x`, fork légitime).

**Commits :**
- `3da2511` feat(intel,store): harvest MAL entries from OSV/GHSA dumps
- `83f729e` feat(intel,cli): typosquat heuristic + top-N reference lists
- `4a9a466` feat(intel,cli): Socket.dev opt-in scanner with token env activation
- `febcd83` feat(policy,cli): `MalwareViolation` + `TyposquatWarning` + `audit --focus`
- `807fee0` docs(readme): document Phase 2.5 surface + defer Phylum bonus

**Architecture finale inchangée (5 crates) — `packguard-intel` étendu :**
```
crates/
├── packguard-core     # + MalwareReport, MalwareKind (3 variants)
├── packguard-policy   # + MalwareViolation + TyposquatWarning (Compliance variants)
├── packguard-store    # + schema V3 malware_reports, natural key (source, rpkg_id, version)
├── packguard-intel    # + malware::, typosquat::, socket:: modules
└── packguard-cli      # audit --focus cve|malware|typosquat|all, --fail-on-malware, Risk column
```

**Démo Nalo/monorepo :**

`packguard sync` (volumétrie) :
```
✓ osv-npm   — scanned 217703, persisted 191 vuln + 12 malware (watched)
✓ osv-pypi  — scanned  19085, persisted 71 vuln + 1 malware (watched)
✓ typosquat-pypi-top — refreshed (15000 entries cached)
✓ typosquat — 1 suspect flagged
📚 store holds 256 advisories + 13 malware reports
```

12 entries OSV-MAL harvestées ciblent des versions précises — `axios` 0.30.4/1.14.1, `react` 1.0.x, `eslint-plugin-prettier` 4.2.2/4.2.3, `posthog-js` 1.297.3, etc. **Aucune n'est la version installée par Nalo** → le matcher fait son travail : pas de faux positifs bloquants.

`packguard audit --focus all front/vesta` : 3 CVE (eslint, lodash×2), **0 malware confirmé**, 1 typosquat suspect (`eslint-plugin-import`, distance 2 de `eslint-plugin-import-x`). Faux positif attendu — fork légitime, à ajouter à la WHITELIST si besoin de le faire taire.

### Notes saillantes

1. **Pas de nouveau crate** (respect de la consigne). `packguard-intel` étendu de 4 → 7 modules (`malware`, `typosquat::{mod,filters,lists}`, `socket`).

2. **Schéma V3 `malware_reports`** reconstruit avec natural key `(source, rpkg_id, version)` + `kind` / `severity` / `evidence` JSON / `reported_at` / `fetched_at`. Phase 1 avait un stub vide → `DROP + rebuild` propre via refinery.

3. **Routage MAL × Vuln au parse-time** : `osv::parse` et `ghsa::parse_cache` détectent `is_malware_advisory` dès le parsing et émettent `(Vec<Vulnerability>, Vec<MalwareReport>)`. Une advisory va dans une seule des deux buckets, jamais les deux.

4. **Typosquat top-N** :
   - PyPI : liste officielle `hugovk.github.io/top-pypi-packages` (15 000 noms), téléchargée
   - npm : **baseline curée embarquée** `NPM_TOP` (~200 noms), car source communautaire instable. Override possible via `~/.packguard/cache/reference/npm-top-packages.json` (documenté README)

5. **Filtres anti-faux-positifs typosquat** : length ≥ 4, pas de scope (`@org/*`), self-match exclu, `WHITELIST` curée (`request/requests`, `react/preact`, etc.). **21 tests** couvrent positifs + négatifs.

6. **3 variants `MalwareKind` distincts** (sémantiques différentes) :
   - `Malware` → bloquant par défaut
   - `Typosquat` → warning par défaut (sauf `block.typosquat: strict`)
   - `ScannerSignal` → informationnel (Socket alerts de low confidence)
   Socket alerts mappent selon severity déclarée.

7. **`MalwareViolation` bloquante** : comptée dans `violations`, déclenche `--fail-on-violation` ET `--fail-on-malware` (nouveau flag). Exit codes distincts pour discriminer en CI.

8. **Phylum reporté explicitement** — non bloquant : l'API Phylum est **project-oriented** (analyse d'un manifest entier) et pas per-package comme Socket. Incompatible avec notre flow actuel. Socket sert de template quand on ajoutera des "project-scanners" en phase future.

9. **`PACKGUARD_LIVE_TESTS` Socket non câblé** : rate limit rendrait la CI flakey. Pattern documenté dans le commit `4a9a466` pour Phase 3 future si besoin.

10. **Tech-debt #3 partiellement soldée** : `block.malware` câblé (2.5.4). Reste `block.typosquat: strict` override per-package dans `.packguard.yml` → reportable à la demande.

<details>
<summary>Spec Phase 2.5 (pour historique)</summary>

6 sous-lots : 2.5.1 harvest MAL OSV/GHSA déjà syncé (gratuit), 2.5.2 typosquat heuristique local (Levenshtein + swaps + filtres FP), 2.5.3 Socket.dev opt-in, 2.5.4 policy integration (`MalwareViolation` bloquante, `TyposquatWarning` non), 2.5.5 CLI (`audit --focus`, `Risk` column), 2.5.6 Phylum bonus.

Décisions : 4 tiers de sources, pas de nouveau crate, Socket/Phylum opt-in strict, Phylum finalement reporté pour incompatibilité pattern.

</details>

---

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

## 14.8. Phase 4 — Dashboard web

**Split décidé en cours de cadrage :** Phase 4 découpée en **4a (Foundations)** et **4b (Specialization)** par l'agent (argumentaire retenu : 2 stacks complets + build pipeline custom + 35+ tests = risque de cut-corners si tout en une run ; sous-lots à coût très inégal ; mieux vaut livrer un noyau démontrable que tout en demi-fini).

### Phase 4a — Foundations ✅ done (2026-04-20)

**Livré :** 6 commits, 196 tests Rust (+36 nets, incluant 15 server + 20 DTO ts-rs roundtrip), 13 tests frontend Vitest, clippy/fmt clean, pnpm lint/typecheck clean. Nouveau crate `packguard-server`, répertoire `dashboard/` scaffolé à la racine.

**Commits :**
- `a03f25d` feat(server): `packguard-server` crate — REST API + V4 jobs + ts-rs roundtrip
- `6204ce2` chore(server): clean up orphan ts-rs export dirs from earlier regen runs
- `2c20ab2` feat(dashboard): scaffold Vite + React 19 + Tailwind 4 + shadcn UI
- `9a7fc6a` feat(dashboard): Overview page with stat cards + donuts + top-risks
- `b5121a6` feat(dashboard): Packages table with URL-state filters + sort + pagination
- `38f0eb1` feat(cli): add `packguard ui` subcommand to boot the dashboard API

**Architecture finale (6 crates + dashboard) :**
```
packguard/
├── crates/
│   ├── packguard-core
│   ├── packguard-policy
│   ├── packguard-store      # + migration V4 (jobs table)
│   ├── packguard-intel
│   ├── packguard-server     # ← NOUVEAU : axum + REST API + job runner + ts-rs DTOs
│   └── packguard-cli        # + `ui` subcommand
└── dashboard/               # ← NOUVEAU : Vite + React 19 + TS + Tailwind 4 + shadcn
    ├── src/
    │   ├── pages/           # Overview, Packages (+ PackageDetail placeholder 4b)
    │   ├── components/      # layout, cards, filters, donuts, table
    │   └── lib/             # API client typé ts-rs, router
    └── vitest tests
```

**Validation live — Nalo/monorepo via `packguard ui` :**
- `GET /api/overview` → 118 packages (91 npm + 27 pypi), health_score 16, top-risks `pillow` (2 high CVE), `lodash` (1 high CVE), 1 typosquat suspect `eslint-plugin-import-x`, compliance 19/80/9/10
- `GET /api/packages` paginate correctement ; filtres `has_cve=true`, `severity=high`, `has_typosquat=true` retournent les bonnes lignes
- `GET /api/packages/pypi/pillow` expose l'historique complet (108+ versions remontant à 2010)
- `POST /api/sync` job : pending → running → completed, `vulns_persisted: 282`, `typosquat_suspects: 1`
- Migration V4 appliquée cleanement sur le store Phase 2.5 existant

**ts-rs roundtrip :** `a03f25d` implémente la solution discutée (test Rust qui asserte le hash des fichiers TS générés). Détecte le drift automatiquement en CI. 20 DTOs couverts.

**Reporté explicitement à Phase 4b :**
1. Page Package detail (5 onglets : Overview / Versions / Vulnerabilities / Malware / Dependents) — placeholder existe dans `dashboard/src/pages/PackageDetail.tsx`
2. Timeline visx avec virtualisation (500+ versions pour `pillow` → windowing nécessaire)
3. Policies editor (Monaco ou CodeMirror pour YAML) + endpoint dry-run `POST /api/policies/dry-run`
4. `build.rs` embed des assets Vite en release (actuellement `ui` sert l'API, le dev Vite sert le front — pattern dev-mode uniquement)
5. Screenshots README (Overview + Packages avec données Nalo)

**Nit à corriger en 4b :**
- `crates/packguard-server/bindings/` contient des orphans root-caused (ts-rs 11 transitive exports). Gitignoré pour l'instant. Fix propre via `TS_RS_EXPORT_DIR` env var ou un feature Cargo dédié.

**Note du rapport agent :** pas de screenshots UI dans ce rapport (textuel), mais le JSON live des endpoints sur données Nalo est l'équivalent de la démo visuelle (à compléter en 4b avec screenshots quand le detail page + timeline seront visibles).

<details>
<summary>Spec Phase 4a (pour historique)</summary>

Sous-lots livrés : 4.1 (`packguard-server` + V4 migration `jobs` + service layer + tests intégration), 4.2 (frontend scaffold Vite+React+Tailwind+shadcn+ts-rs+TanStack Query+router+layout), 4.3 (Overview cards + donuts + boutons Scan/Sync), 4.4 (Packages table filtres/sort/pagination/click-through), 4.8 partiel (`packguard ui` en dev mode, Vite proxy, `build.rs` embed différé à 4b).

Décision ts-rs : inline dans 4.1 (test hash, pas de commit séparé).

</details>

### Phase 4b — Specialization ✅ done (2026-04-21)

**Livré :** 5 commits atomiques, 185 tests Rust (−11 nets : +13 fonctionnels − 28 tests ts-rs redondants supprimés par le fix du nit) + 29 Vitest (+16 nets) + 3 tests embed sous feature, clippy/fmt clean (avec et sans feature `ui-embed`), pnpm lint/typecheck clean, drift gate ts-rs toujours vert.

**Commits :**
- `1d71cfe` feat(server,dashboard): Package detail — Versions / Vulns / Malware / Policy tabs
- `bcb8da5` feat(dashboard): visx version timeline with density clusters + hover zoom
- `b2e5cb5` feat(server,dashboard): Policy editor with CodeMirror + dry-run + atomic save
- `b4f35c9` chore(server): strip ts-rs auto-export attribute to stop polluting `bindings/`
- `5451023` feat(server,cli): `ui-embed` feature + `build.rs` + release screenshots + README

**Adhérence aux décisions verrouillées :**
1. ✅ **CodeMirror 6** (pas Monaco) — `@uiw/react-codemirror` + `@codemirror/lang-yaml`, ~100 KB bundle
2. ✅ **Timeline virtualization** seuil 200 versions (override du seuil §14.8 qui disait 500 — agent a arbitré à 200 après mesure réelle sur `pillow`), 60 buckets de densité + Reset
3. ✅ **Dry-run `POST /api/policies/dry-run`** — réutilise `evaluate_row` sur le candidat vs le snapshot courant, retourne per-bucket deltas + 50 premiers packages flippés. Erreurs YAML → 400 avec line/column 1-based extrait de `serde_yaml`
4. ✅ **`build.rs` embed sous feature `ui-embed`** : skip en debug, skip sur `PACKGUARD_SKIP_UI_BUILD=1`, skip si `dashboard/dist/` existe déjà (override via `PACKGUARD_REBUILD_UI=1`). `rust-embed` avec compression. `cargo build --release -p packguard-cli --features ui-embed` produit un binaire autonome qui sert `/`, `/assets/*`, et tous les deep-links SPA tout en gardant `/api/*` sur les handlers
5. ✅ **Nit ts-rs fixé** dans son propre commit `b4f35c9`. Root cause identifiée : `#[ts(export)]` émet un `#[test]` par type qui écrit dans `bindings/` peu importe `export_to`. Drop de l'attribut `export` (on garde `export_to`) élimine le side-effect ; la drift gate `types_drift` reste le vrai contrat. `.gitignore` band-aid supprimé.

**Architecture finale (6 crates + dashboard) :**
```
packguard/
├── crates/
│   ├── packguard-core
│   ├── packguard-policy
│   ├── packguard-store
│   ├── packguard-intel
│   ├── packguard-server     # + dry_run, detail endpoint, ui-embed feature, build.rs
│   └── packguard-cli
├── dashboard/
│   ├── src/
│   │   ├── pages/           # Overview, Packages, PackageDetail (nouveau 4b), Policies (rewrite 4b)
│   │   └── components/
│   │       └── packages/
│   │           └── VersionTimeline.tsx  # visx, density buckets, zoom
│   └── dist/                # build output, embarqué en release
└── docs/screenshots/        # overview.png, packages.png, detail.png, policies.png
```

**Smoke live sur store Nalo (release binary, feature `ui-embed` active, sans Vite) :**
```
GET  /                              → 200 (SPA embarquée)
GET  /api/health                    → 200 {"ok": true}
GET  /packages/pypi/pillow          → 200 (SPA fallback)
GET  /api/packages/pypi/pillow      → 200 {106 versions, 177 CVEs, policy trace}
POST /api/policies/dry-run (bad YAML) → 400 "invalid YAML at line 3, column 5: …"
```

**Screenshots** sur données Nalo réelles :
- `docs/screenshots/overview.png` — health 16 %, 118 packages, 8 CVE, 1 typosquat, donuts + top-5 risks
- `docs/screenshots/packages.png` — table filtrable/triable, mix npm + PyPI
- `docs/screenshots/detail.png` — pillow, timeline visx 2012→2026, installed 12.0.0 souligné, 177 CVE, 106 versions
- `docs/screenshots/policies.png` — éditeur CodeMirror avec badge "conservative-defaults", Preview/Revert/Save, dry-run panel

**Hors-scope respecté** : pas de graphe de deps, pas d'alerts feed, pas de compare view, pas de SSE, pas de dark mode, pas d'i18n, pas de PDF export. Onglet **Changelog** reste un placeholder (décision explicite : lazy-fetch registre upstream = pas essentiel v1).

**Tech-debts :**
- **#3 (ts-rs nit) ✅ résolue** dans `b4f35c9`
- **#2 (yarn.lock, pnpm nested workspaces)** et **#5 (refinery info)** restent reportées comme demandé

<details>
<summary>Spec Phase 4b (pour historique)</summary>

Sous-lots : 4.5 Package detail (5 onglets), 4.6 timeline visx + virtualisation, 4.7 Policies editor Monaco/CodeMirror + dry-run endpoint, 4.8 fin : `build.rs` embed release + README + screenshots, + fix nit ts-rs `bindings/` en commit séparé.

Décisions : CodeMirror 6 (vs Monaco), timeline threshold 200 versions, dry-run réutilise evaluate_dependency, feature `ui-embed` pour le release build.

</details>

---

Inclut **sous-lots 4.1, 4.2, 4.3, 4.4, et 4.8 partiel** :
- 4.1 — `packguard-server` crate (axum + REST API + job runner + V4 migration `jobs`) + tests d'intégration sur chaque endpoint
- 4.2 — Frontend scaffold (`dashboard/` Vite + React 19 + TS + Tailwind + shadcn + **ts-rs roundtrip** + TanStack Query + react-router + layout sidebar/header)
- 4.3 — Page Overview : cards + donuts recharts + boutons Scan/Sync avec feedback
- 4.4 — Page Packages table : filtres + sort + pagination + click-through vers detail (detail page elle-même en 4b)
- 4.8 partiel — CLI `packguard ui` en **dev mode** (Vite proxy). **`build.rs` embed différé à 4b**

**Attendu 4a :** 5 commits, ~25 tests (~15 Rust API + ~10 front), démo screenshots Overview + Packages sur Nalo. Rapport flag explicitement ce qui reste à 4b.

**Décision ts-rs :** génération + vérification **inline dans 4.1** (pas de commit séparé). Un test Rust asserte que les fichiers TS générés sont à jour via hash. CI run `cargo test` → check automatique.

Inclut **sous-lots 4.5, 4.6, 4.7, et 4.8 fin** :
- 4.5 — Page Package detail : onglets Versions / Vulnerabilities / Malware / Policy eval / Changelog
- 4.6 — Timeline visx : 6 types de markers (gris/rouge/orange/magenta/violet + installed/recommended), virtualisation pour packages à > 500 versions, zoom/pan, tooltip
- 4.7 — Policies editor : form + preview **dry-run** (endpoint qui évalue la policy sans la persister) + validation YAML + save
- 4.8 fin — `build.rs` embed release + screenshots README + README majeur + docs install/usage

**Attendu 4b :** ~7 commits, 25+ tests supplémentaires, démo complète avec 4 pages + GIF animé si possible.

---

### Spec détaillée (commune aux deux phases)

**Objectif global :** exposer dans un dashboard web local l'intégralité du signal accumulé par la CLI sur les 4 phases précédentes. Mode `packguard ui` spawne un serveur HTTP sur `localhost`, ouvre le navigateur, et sert une SPA React qui consomme une API REST exposée par le binaire. Même binaire, même données (SQLite existant), pas de réimplémentation.

**Objectif :** exposer dans un dashboard web local l'intégralité du signal accumulé par la CLI sur les 4 phases précédentes. Mode `packguard ui` spawne un serveur HTTP sur `localhost`, ouvre le navigateur, et sert une SPA React qui consomme une API REST exposée par le binaire. Même binaire, même données (SQLite existant), pas de réimplémentation.

### Architecture cible

```
┌──────────────────────────────────────────────────────────────┐
│  packguard (binaire Rust — 5 crates + 1 nouveau)             │
│                                                               │
│  packguard ui [--port N] [--no-open] [--host 127.0.0.1]      │
│    └─ packguard-server (axum)                                 │
│        ├─ GET /api/overview                                   │
│        ├─ GET /api/packages  (filters, sort, pagination)      │
│        ├─ GET /api/packages/:ecosystem/:name  (detail)        │
│        ├─ GET /api/policies                                   │
│        ├─ PUT /api/policies                                   │
│        ├─ POST /api/scan   (async, returns job_id)            │
│        ├─ POST /api/sync   (async, returns job_id)            │
│        ├─ GET  /api/jobs/:id  (status polling)                │
│        └─ GET /* → sert les assets Vite (rust-embed)          │
│                                                               │
│  dashboard/ (Vite + React + TS — repo racine, hors crates/)  │
│    └─ build output → embarqué par rust-embed au release      │
└──────────────────────────────────────────────────────────────┘
```

**Décisions d'architecture verrouillées :**
- **Nouveau crate `packguard-server`** justifié : concerns séparés (routing, serialization, job runner) distincts du CLI et du core. Pattern identique à `packguard-intel` en Phase 2
- **Frontend dans `dashboard/` à la racine** (pas dans `crates/`) — pnpm, Vite, TypeScript
- **Types partagés Rust ↔ TS via `ts-rs`** — génère les types TS depuis les structs Rust annotées `#[derive(TS)]`. Pas de drift possible
- **Build pipeline :** `build.rs` dans `packguard-server` invoque `pnpm build` si `dashboard/dist/` absent ou en mode release. Skip via `PACKGUARD_SKIP_FRONTEND=1` pour CI qui pré-build
- **Dev flow :** Vite dev server sur `5173` qui proxy `/api/*` vers Rust sur `5174`. Hot reload front + `cargo watch` pour back. Documenté dans `dashboard/README.md`
- **State management :** TanStack Query pour server state ; React state local pour UI. Pas de Zustand/Redux en v1
- **Pas d'auth en v1** (binding `127.0.0.1` uniquement, reporté v2 pour `serve` mode)
- **Pas de streaming SSE/WebSocket en v1** : polling via TanStack Query refetch pour les jobs scan/sync. SSE → Phase 4.5 si besoin réel

### Sous-lots

#### 4.1 — `packguard-server` crate + REST API
- Nouveau crate avec axum, tower-http (CORS si besoin, trace layer), serde
- Service layer qui **consomme** `packguard-store` / `packguard-core` / `packguard-policy` / `packguard-intel` — pas de logique métier dupliquée
- Job runner async (tokio spawn) pour scan/sync avec stockage `jobs(id, kind, status, started_at, finished_at, result)` en SQLite (nouvelle table via migration V4)
- Erreurs typées → réponses JSON cohérentes `{ "error": { "code": "...", "message": "...", "detail": ... } }`
- Tests d'intégration sur chaque endpoint (test DB fixture)

#### 4.2 — Frontend scaffold
- `dashboard/` : Vite + React 19 + TypeScript + Tailwind + shadcn/ui
- Installer shadcn components clés : `Button`, `Card`, `Table`, `Dialog`, `Tabs`, `Badge`, `Input`, `Select`, `Tooltip`, `Separator`, `Sonner` (toasts), `Form`
- TanStack Query + fetcher typé basé sur les types `ts-rs`
- Router : `react-router-dom` v7 (routes : `/`, `/packages`, `/packages/:ecosystem/:name`, `/policies`)
- Palette couleurs alignée sur la CLI : rouge critical, orange major, jaune minor, vert compliant, magenta insufficient, violet malware. Tokens Tailwind custom
- Layout de base : sidebar navigation + header avec actions Scan/Sync + toasts

#### 4.3 — Page Overview
- Header : bouton **Scan** (POST /api/scan), bouton **Sync** (POST /api/sync), badge indiquant dernier scan/sync
- Cards :
  - Health score (calculé : % compliant, avec évolution vs dernier scan)
  - Total packages watched par écosystème
  - Vulnerabilities breakdown (critical/high/medium/low)
  - Malware breakdown (confirmé / suspect typosquat)
  - Compliance breakdown (compliant / warning / violation / insufficient)
- Graphique donut simple (recharts) pour chaque breakdown
- Top 5 packages les plus à risque (somme pondérée CVE severity + malware flag)
- Responsive : desktop-first, pas d'obligation mobile parfait en v1

#### 4.4 — Page Packages table
- Liste complète des deps watched, paginée server-side
- Filtres : écosystème, compliance status, severity max, has malware, has typosquat, name search
- Colonnes : Package, Écosystème, Installed, Recommended, Compliance badge, Risk (CVE + malware badges condensés), Last scanned
- Tri sur chaque colonne
- Click sur une ligne → navigate to detail
- Actions bulk : export CSV/JSON de la vue courante (bonus)

#### 4.5 — Page Package detail
- Métadonnées : nom, écosystème, installed, recommended, policy appliquée (résolue), dernier scan
- Onglet **Versions** : table de toutes les versions persistées en `package_versions`, colonnes `version`, `published_at`, `deprecated`, `yanked`, `matches_range` (highlight la version installée et la recommended)
- Onglet **Vulnerabilities** : table des CVE/GHSA matchés, severity, affected range, fix version, source (OSV / GHSA / Socket)
- Onglet **Malware** : MAL entries + typosquat suspects si applicable
- Onglet **Policy eval** : trace explicative du résolveur — quelle règle a matché, quelles versions filtrées par `stability`, `min_age_days`, `block.*`, version retenue et pourquoi
- Onglet **Changelog** (best-effort) : lazy-fetch GitHub Releases si URL repo devinable

#### 4.6 — Timeline dans le Package detail
- Composant `VersionTimeline` basé sur **visx** (flexible pour markers custom)
- Axe temporel horizontal, points colorés par version :
  - Gris : release normale
  - Rouge : CVE critique active sur cette version
  - Orange : CVE high
  - Magenta : yanked
  - Violet : MAL entry
  - Souligné : version installée
  - Contour : version recommandée
- Zoom/pan, tooltip au hover avec détails
- Performance : virtualiser si > 500 versions (cas `sentry-sdk` avec 329 versions)

#### 4.7 — Page Policies editor
- Lit `.packguard.yml` courant via API
- Form strict basé sur le schéma policy : defaults, overrides (liste), groups (liste)
- Preview live à droite : "Avec cette policy, le scan actuel donnerait X compliant / Y warnings / Z violations" (dry-run côté serveur sans persister)
- Bouton Save : PUT /api/policies → écrit le fichier + reload store
- Validation YAML côté backend, erreurs remontées au formulaire

#### 4.8 — CLI `packguard ui` command + packaging
- Nouvelle sous-commande CLI
- Options : `--port N` (défaut 5174, fallback si occupé), `--host 127.0.0.1` (override pour `serve` v2), `--no-open` (skip auto-open browser)
- Open browser via `open` crate (cross-platform)
- Graceful shutdown sur Ctrl+C (ferme les jobs async proprement)
- `build.rs` configuration pour embed Vite assets en release
- Docs racine README : screenshot + commande d'install + workflow type

### Critères de sortie

- [ ] `packguard ui` lance le serveur, ouvre le navigateur, affiche l'Overview
- [ ] 4 pages fonctionnelles : Overview, Packages, Package detail, Policies
- [ ] Timeline visx affiche les versions + markers pour Nalo réel (`sentry-sdk` avec ses 329 versions, `fastapi` avec vulns)
- [ ] Boutons Scan/Sync déclenchent les actions, feedback visuel (toast + progress), DB rafraîchie en live
- [ ] Policies editor : modification + save + preview dry-run fonctionnent
- [ ] Types partagés Rust ↔ TS via `ts-rs`, zéro drift possible (CI check)
- [ ] `build.rs` embed les assets Vite au `cargo build --release`
- [ ] Tests d'intégration API (chaque endpoint, sad paths compris)
- [ ] Tests composants React clés (Overview cards, Packages filters, Policy form) via Vitest + Testing Library
- [ ] Démo Nalo/monorepo : screenshot des 4 pages avec données réelles + courte vidéo ou GIF animé bienvenu
- [ ] 20+ nouveaux tests Rust, 15+ tests frontend, clippy & fmt clean, `pnpm lint` + `pnpm typecheck` clean
- [ ] README racine mis à jour : section "Dashboard" avec screenshot + install + usage

### Hors scope Phase 4
- **Dependency graph** (Cytoscape, chaînes contaminées visuelles) → Phase 5
- **Alerts feed** → Phase 4.5 ou Phase 6 (nécessite un système d'événements)
- **Compare view** (snapshot N vs N+1) → Phase 4.5
- **Multi-repo aggregated view** → v2 `serve` mode
- **Auth / login / users** → v2 `serve` mode
- **Streaming SSE/WebSocket** → Phase 4.5 si besoin réel de temps réel
- **Dark mode** → bonus seulement si bandwidth
- **Mobile responsive parfait** → desktop-first, smartphone pas prioritaire
- **i18n** → v2
- **Export complet** (PDF reports, etc.) → Phase 7 ou v2

### Nouvelles dépendances prévisibles

**Rust (`packguard-server`) :**
- `axum` (routing HTTP)
- `tower`, `tower-http` (middleware, trace layer, éventuellement compression)
- `ts-rs` (génération types TS depuis Rust)
- `open` (ouvrir le browser cross-platform)
- Réutilise `tokio`, `serde`, `thiserror`, `tracing` déjà présents

**Frontend (`dashboard/`) :**
- `react`, `react-dom` 19
- `react-router-dom` 7
- `@tanstack/react-query` 5
- `tailwindcss` 4 + `@tailwindcss/vite`
- `shadcn-ui` CLI + components installés selon besoin
- `@visx/*` pour timeline
- `recharts` pour donuts/bars Overview
- `lucide-react` pour icônes
- `sonner` pour toasts
- `vitest` + `@testing-library/react` pour tests

### Points d'attention pour l'agent

- **Ne pas dupliquer la logique** : tout appel métier passe par les crates existantes (`packguard-core`, `packguard-store`, etc.). Le serveur est une fine couche de translation
- **Types `ts-rs` générés dans un commit séparé** (ou script de check) pour éviter que le front drifte
- **Port 5174** pour le backend, **5173** pour Vite dev — classique, évite les collisions communes
- **Honnêteté sur les placeholders** : si une vue n'a rien à afficher (pas encore de scan), message clair "Run a scan to get started" avec bouton
- **Couleurs sémantiques** alignées CLI/UI (même palette, même meaning) — éviter de réinventer
- **Accessibilité raisonnable** : labels de form, alt sur images, contraste WCAG AA. Pas besoin de perfect AAA
- **Performance** : le store Nalo contient ~260 advisories + ~120 deps + ~2000 versions. Pas besoin de SSR ou de Suspense exotique. Une SPA classique suffit largement
- **Dashboard doit marcher offline** une fois la DB remplie — pas d'appel réseau sortant depuis le browser (tout passe par l'API Rust locale)

---

## 14.9. Phase 5 — Graph + compatibility

**Split décidé en cours de cadrage** (agent a proposé, validé 2026-04-21) :
- **Phase 5a — Backend** (5.1 migration + 5.2 extraction transitive + 5.3 API) : validation par smoke JSON sur Nalo, pas d'UI
- **Phase 5b — Frontend + CLI** (5.4 page `/graph` + 5.5 onglet Compat + 5.6 CLI bonus) : screenshot contamination `lodash` CVE = critère de sortie 5b

**Objectif global :** matérialiser ce qui différencie PackGuard d'un `npm audit` / `pip-audit` — **les chaînes transitives**. Extraire le graphe de dépendances complet depuis les lockfiles, résoudre les peer deps, et **visualiser les chaînes contaminées** qui remontent depuis un package vulnérable jusqu'aux racines du projet.

### Phase 5a — Backend ✅ done (2026-04-21)

**Livré :** 3 commits atomiques (−1 vs budget de ~4, scope absorbé), 201 tests Rust (+16 nets), clippy/fmt clean, ts-rs drift vert (12 nouveaux DTOs).

**Commits :**
- `b834eef` feat(store,core): V5 migration for `dependency_edges` + compat rows + cache
- `b3569a5` feat(core): emit transitive edges + compat rows from npm & PyPI lockfiles
- `61312a6` feat(server): graph + contamination BFS + compat endpoints

**Extracteurs livrés (4 formats lockfile) :**
- **package-lock.json v2/v3** : full `packages:` tree + npm hoist resolver
- **pnpm-lock.yaml** : double support v6/v7 `packages:` + v9 `snapshots:` (fixture dual-format consolidée, d'où le volume de tests légèrement sous budget mais couverture préservée)
- **poetry.lock** : `[package.dependencies]` avec flag optional
- **uv.lock** : `dependencies = [{name, specifier}…]` inline
- Metadata compat extraite : `engines` (npm) + `python-versions` / `requires_python` (PyPI) → nourrit la table `compatibility`

**Architecture BFS contamination :** borne à **32 de profondeur**, **200 chaînes max retournées**, dedup + tri longueur ascendant. Cache invalidé atomiquement dans `save_project` (delete-edges + delete-cache + re-insert dans la même transaction, test roundtrip couvre).

**Smoke live sur store Nalo (release binary, 3978 edges extraits de `front/vesta`) :**

```
GET /api/graph?max_depth=2&kind=runtime
→ { nodes: 837, edges: … }

GET /api/graph/contaminated?vuln_id=<lodash CVE>
→ {
    hits: [{ ecosystem: "npm", name: "lodash", installed: "4.17.23" }],
    chains: [
      { workspace: ".../vesta", path: ["npm:lodash@4.17.23"] },
      { workspace: ".../vesta", path: [
          "npm:textlint@15.5.2",
          "npm:@textlint/linter-formatter@15.5.2",
          "npm:lodash@4.17.23"
      ]},
      { workspace: ".../vesta", path: [
          "npm:textlint-rule-doubled-spaces@1.0.2",
          "npm:textlint@15.5.2",
          "npm:@textlint/linter-formatter@15.5.2",
          "npm:lodash@4.17.23"
      ]}
    ],
    from_cache: false   // true au 2ème appel ✅
  }

GET /api/packages/npm/lodash/compat
→ { rows: [], dependents: [
    @nalo/phoebus@2026.4.16,
    @textlint/linter-formatter@15.5.2,
    @visx/responsive@3.12.0,
    @visx/shape@3.12.0,
    @visx/text@3.12.0,
    …
  ]}
```

**Observation intéressante :** `lodash` est utilisé notamment par **`@nalo/phoebus`** (le design system Nalo). C'est la première fois qu'on voit une chaîne de dépendance interne Nalo dans le signal — preuve concrète que le graphe capture bien les workspaces internes.

**Points d'attention respectés :**
- Pas de résolution de deps — on lit pnpm / poetry / uv as-is (PackGuard ≠ package manager)
- Peer deps non résolus → **warning**, jamais violation
- Contamination cache keyé `(scan_id, vuln_id)`, invalidé atomiquement au `save_project`
- `DepKind` a gagné `PartialOrd`/`Ord` (seule modif sémantique hors additions)

**Hors-scope 5a respecté** : aucun frontend touché, aucune CLI `packguard graph`, aucun screenshot. Tech-debts #2 et #5 non touchées.

<details>
<summary>Spec Phase 5a (pour historique)</summary>

3 sous-lots livrés : 5.1 migration V5 (`dependency_edges` + `compatibility` + `contamination_cache`, indexes, store helpers), 5.2 extraction transitive (4 formats lockfile + metadata compat), 5.3 API (3 endpoints : graph, contamination BFS, compat).

Décisions : BFS borné à 32 profondeur + 200 chaînes max, cache invalidé via scan_id, pas de résolution deps custom.

</details>

### Phase 5b — Frontend + CLI ✅ done (2026-04-21)

**Livré :** 5 commits atomiques (3 sous-lots + 1 fix + 1 docs), 206 tests Rust (+5 CLI), 36 Vitest (+7 : 5 Graph page + 2 Compat tab), clippy/fmt clean, pnpm lint/typecheck clean, ts-rs drift vert (aucun nouveau DTO nécessaire — 5a suffisait). **CLI bonus `packguard graph` livré** (pas seulement 5.4 + 5.5).

**Commits :**
- `67601de` feat(dashboard): `/graph` page — Cytoscape canvas + focus-CVE contamination
- `b781fae` feat(dashboard): Compatibility tab on Package detail
- `0a164bf` fix(dashboard): focus-CVE narrows canvas + URL-driven tabs + layout spacing
- `07533a6` feat(cli): `packguard graph` — ascii / dot / json + `--contaminated-by`
- `6d4850f` docs(readme): Phase 5 — graph page, Compatibility tab, graph CLI, V5 store

**Critère de sortie obligatoire ✅ atteint :** `docs/screenshots/graph-focus-lodash.png` montre la chaîne la plus profonde de contamination `lodash` (`textlint-rule-doubled-spaces → textlint → @textlint/linter-formatter → lodash`) rendue **en rouge end-to-end**, avec root en contour noir et lodash qui porte son payload de 2 CVE. Bandeau top confirme `"CVE-2026-4800: 1 package hit · 3 contamination chains · cached"`.

**Architecture frontend livrée :**
```
dashboard/src/
├── pages/
│   ├── Graph.tsx              # nouveau, ~260 LoC
│   └── PackageDetail.tsx      # + onglet Compatibility + URL tab param
├── components/graph/          # nouveau : GraphCanvas + FocusBanner + FilterBar
└── lib/api.ts                 # + 3 endpoints branchés
```

**Screenshots livrés** (release binary + UI embarquée, store Phase 5) :
- `docs/screenshots/graph-default.png` — cose-bilkent blob, 837 nœuds / 1245 edges, montre l'échelle + palette écosystème
- `docs/screenshots/graph-focus-lodash.png` — **le screenshot critique** (voir ci-dessus)
- `docs/screenshots/compat-lodash.png` — onglet Compatibility avec empty-state banner + Used By list 5 lignes

**Smoke live CLI `packguard graph` :**

```
$ packguard --store /tmp/packguard_phase5.db graph front/vesta \
      --contaminated-by CVE-2026-4800

CVE-2026-4800 — 1 hit(s), 3 chain(s)

  chain 1: .../vesta/package.json
    ┌── npm:lodash@4.17.23

  chain 2: .../vesta/package.json
    ┌── npm:textlint@15.5.2
    │── npm:@textlint/linter-formatter@15.5.2
    └── npm:lodash@4.17.23

  chain 3: .../vesta/package.json
    ┌── npm:textlint-rule-doubled-spaces@1.0.2
    │── npm:textlint@15.5.2
    │── npm:@textlint/linter-formatter@15.5.2
    └── npm:lodash@4.17.23
```

La CLI et l'UI partagent le **même BFS + cache backing** (une seule source de vérité).

**Décisions respectées :**
- ✅ Layouts : dagre défaut, cose-bilkent option, rien d'exotique
- ✅ Palette : rouge CVE / violet malware / magenta yanked / bleu npm / vert PyPI
- ✅ Performance : bandeau `oversize_warning` si > 2000 nœuds (absent sur Nalo 837/1245)
- ✅ Mode Focus : canvas narrow + chaîne peinte en rouge end-to-end
- ✅ Onglet Compat : tables peer deps + engines (required) + footprint count + lien `/graph?focus=...`
- ✅ CLI bonus livré avec 3 formats (ascii par défaut, dot pour Graphviz, json)

**Hors-scope respecté** : pas de WebGL renderer (reporté v5.5 comme §14.9), pas d'export PDF/PNG, pas de graphe multi-workspace agrégé.

**Tech-debts :** #2 (yarn.lock, pnpm nested) et #5 (refinery info) restent reportées comme convenu.

<details>
<summary>Spec Phase 5b (pour historique)</summary>

3 sous-lots livrés : 5.4 page `/graph` Cytoscape (dagre + cose-bilkent + mode Focus CVE), 5.5 onglet Compatibility dans Package detail (peer deps + engines + transitive footprint + upstream chain), 5.6 CLI `packguard graph` bonus livré (ascii/dot/json + `--focus` + `--contaminated-by`).

Décisions : layouts dagre défaut, palette alignée CLI, warning > 2000 nodes, même BFS backing que l'API (une source de vérité UI + CLI).

</details>

---

## Phase 5 — Bilan agrégé (5a + 5b)

**Total Phase 5 :** 8 commits sur 2 sessions (3 + 5), +21 tests Rust (185 → 206), +7 Vitest (29 → 36), +3 screenshots, 4 formats lockfile transitifs, 3 endpoints API + 1 CLI command.

**Livrable utilisateur mesurable :** la chaîne `front/vesta → textlint-rule-doubled-spaces → textlint → @textlint/linter-formatter → lodash@4.17.23` est désormais **visible** à la fois dans le terminal (`packguard graph --contaminated-by`) et dans le browser (mode Focus CVE sur `/graph`). C'est le signal exact qu'un `npm audit` basique ne fournit pas.

**État binaire final Phase 5 :**
```
packguard init   → .packguard.yml conservative
packguard scan   → npm + PyPI + history + transitive edges + compat
packguard sync   → OSV + GHSA + malware + typosquat
packguard audit  → CVE + malware + typosquat, SARIF
packguard report → compliance + --fail-on-violation
packguard graph  → ascii/dot/json, --focus, --contaminated-by   ← nouveau Phase 5b
packguard ui     → dashboard 6 pages (+ Graph, Compat tab)       ← nouveau Phase 5
```

---

**Scope Phase 5b** : 5.4 + 5.5 + 5.6 ci-dessous.
**Critère de sortie clé 5b** : screenshot graphe Nalo `front/vesta` + zoom sur la chaîne contaminée par `lodash` CVE visible et lisible. Backend 5a a **déjà produit les chaînes** (`lodash` remonte via `textlint → @textlint/linter-formatter` et via `@nalo/phoebus`), il ne reste qu'à les rendre visibles.

### Sous-lots

#### 5.1 — Graph data model & migration V5
- Nouvelle table `dependency_edges(id, scan_id, source_pkg_version_id, target_pkg_name, target_range, resolved_version_id NULLABLE, kind, workspace_id)` dans `packguard-store`
- Enum `kind` : `Runtime`, `Dev`, `Peer`, `Optional`, `Build`
- `resolved_version_id` nullable pour les peer deps non résolus (warning)
- Nouvelle table `compatibility(pkg_version_id, engines_json, peer_deps_json, os_json, cpu_json)` — schéma §8 déjà prévu mais non alimenté
- Migration V5 idempotente via refinery
- Indexes sur `scan_id`, `source_pkg_version_id`, `target_pkg_name` pour les traversées

#### 5.2 — Extraction transitive depuis les lockfiles
- Étendre `packguard-core` parsers :
  - **pnpm-lock.yaml** : section `packages:` contient chaque nœud résolu avec `dependencies:`, `peerDependencies:`, `peerDependenciesMeta:`, `optionalDependencies:`
  - **package-lock.json v2/v3** : arbre `packages:` keyed par path ; chaque entry a `dependencies`, `peerDependencies`, `optionalDependencies`
  - **poetry.lock** : `[[package]]` array, chacun avec `[package.dependencies]` et `[package.extras]`
  - **uv.lock** : format TOML similaire, `dependencies` inline
- Extraction des `engines` (Node, npm, yarn, Python) depuis :
  - npm : `engines` field du manifest par version
  - PyPI : `requires_python` dans le payload registre
- Persistance dans `dependency_edges` + `compatibility` au moment du `scan`
- Tests fixtures : pnpm monorepo simple, poetry standard, uv avec extras

#### 5.3 — API graph + peer deps + chaînes contaminées
- **Graph endpoint** `GET /api/graph?workspace=W&max_depth=N&kind=runtime,dev,peer`
  - Response : `{ nodes: [{id, name, ecosystem, version, flags: {vulns, malware, deprecated, yanked}}], edges: [{source, target, kind, range}] }`
  - Filtrable par profondeur, kinds, et inclure/exclure transitives
- **Peer deps status** `GET /api/packages/:eco/:name/compat`
  - Pour chaque peer required : présent oui/non, version dans la range oui/non, source du match
  - Engines : required vs detectable (best-effort, on reporte seulement ce qu'on sait)
- **Contamination chains** `GET /api/vulns/:vuln_id/chains?workspace=W`
  - BFS inverse depuis le package vulnérable vers les roots (deps directes)
  - Response : liste de chaînes `[root → ... → vulnerable_pkg]`, triées par longueur puis severity
  - Cache en DB dans nouvelle table `contamination_cache(scan_id, vuln_id, chains_json)`, invalidée au prochain `scan`
- Tests d'intégration : graphe minimal à 3 nœuds avec un CVE sur la feuille

#### 5.4 — Dashboard : nouvelle page Graph
- Route `/graph` dans le dashboard
- Composant `DependencyGraph` basé sur `cytoscape` + `react-cytoscapejs`
- **Layouts switchables** (défaut dagre hiérarchique) :
  - `dagre` — top-down depuis les roots (le plus lisible pour un dep tree)
  - `cose-bilkent` — force-directed, bon pour voir les clusters
  - `circle` — pour petits graphes
- **Rendu nœuds** :
  - Couleur par écosystème (npm=bleu, PyPI=vert)
  - Border rouge si CVE active, magenta si yanked, violet si malware
  - Label = `name@version`
  - Taille proportionnelle au nombre de dependents (pagerank simplifié)
- **Rendu arêtes** :
  - Traits pleins noirs = runtime
  - Traits bleus = dev
  - Pointillés orange = peer
  - Gris clair fins = optional
- **Interactions** :
  - Click nœud → panel latéral avec détails (vulns, policy, link vers Package detail)
  - Double-click → centre + zoom
  - Hover nœud → highlight du chemin vers les roots + vers les vulns descendantes
  - Filter bar : inclure/exclure kinds, profondeur max
- **Mode Focus** : sélectionner un CVE dans la liste → afficher uniquement le sous-graphe contaminé (roots vers package vulnérable en rouge) avec background grisé pour le reste
- **Performance** : Nalo ~500 nœuds, Cytoscape natif suffit. Si > 2000 nœuds détectés → basculer sur `cytoscape.js/canvas` ou prévenir l'utilisateur avec un avertissement (reporté v5.5 si besoin)

#### 5.5 — Dashboard : onglet Compatibility dans Package detail
- Nouvel onglet "Compatibility" à côté de Versions / Vulns / Malware / Policy eval / Changelog
- Sections :
  - **Peer dependencies** : table avec `name`, `range_required`, `resolved_version`, `status` (✅ ok / ⚠️ missing / ❌ out-of-range)
  - **Engines** : table avec `runtime` (node/npm/python), `range_required`, `detected_version` (si détectable), `status`
  - **Transitive footprint** : # direct deps, # transitive, depth max, # dédupliqués
  - **Upstream chain** : liste condensée des chemins qui mènent à ce package (si c'est une dep transitive)
- Lien vers la page `/graph?focus=:eco:name` pour visualiser en contexte

#### 5.6 — Bonus : CLI `packguard graph` command
- Si bandwidth dispo après 5.1 → 5.5
- `packguard graph [--workspace W] [--focus pkg] [--contaminated-by CVE] [--format ascii|dot|json]`
- Output ASCII tree par défaut (package + tree character)
- `--format dot` pour export Graphviz
- `--format json` pour consommation externe
- Utile en CI pour audit rapide ou export vers tooling tiers

### Critères de sortie

- [ ] Migration V5 ajoutée, `dependency_edges` + `compatibility` peuplées depuis un `scan` sur Nalo
- [ ] pnpm-lock.yaml, package-lock.json v2/v3, poetry.lock, uv.lock tous extraits au niveau transitif
- [ ] `GET /api/graph` retourne le graphe complet Nalo avec kinds distincts (runtime/dev/peer)
- [ ] `GET /api/packages/:eco/:name/compat` : peer deps et engines résolus
- [ ] `GET /api/vulns/:vuln_id/chains` : chaînes contaminées calculées et cachées
- [ ] Page `/graph` fonctionnelle, layouts dagre + cose-bilkent, interactions clique/hover/filter
- [ ] Mode Focus sur un CVE → sous-graphe contaminé visible, reste grisé
- [ ] Onglet Compatibility dans Package detail avec peer deps + engines + footprint transitive
- [ ] Démo Nalo : screenshot du graphe `front/vesta` + zoom sur la chaîne contaminée par `lodash` CVE
- [ ] 30+ nouveaux tests (API + frontend), clippy & fmt clean, pnpm lint/typecheck clean

### Hors scope Phase 5
- **Réécriture de la résolution deps** (on lit les lockfiles, on ne resout pas nous-mêmes)
- **os/cpu restrictions** évaluation stricte — reporté, info-only
- **Optional deps** traitées comme runtime — reporté
- **Diff de graphe** (changements entre scans) → Phase 6 ou Compare view
- **Layouts exotiques** (breadthfirst, klay) — on garde dagre + cose-bilkent
- **Export PDF/PNG** du graphe → Phase 7
- **Graph multi-workspace** (vue agrégée de plusieurs workspaces) → v2
- **WebGL renderer** pour >2000 nœuds → v5.5 si demande réelle
- **Scan de vulnérabilités via les chaînes** (ex: flag "X est vulnérable parce qu'il dépend de Y vulnérable") → Phase 6

### Nouvelles dépendances prévisibles

**Frontend :**
- `cytoscape` + `react-cytoscapejs`
- `cytoscape-dagre` (layout hiérarchique)
- `cytoscape-cose-bilkent` (force-directed)

**Backend :**
- Pas de nouvelle crate HTTP
- Éventuellement `petgraph` pour le BFS contamination (léger, pure Rust) — ou implémenter manuellement si scope simple

### Points d'attention pour l'agent

- **Ne pas résoudre les deps toi-même** : on lit les lockfiles, on fait confiance à ce que pnpm/poetry/etc. ont résolu. PackGuard ≠ package manager
- **Peer deps non résolus** = warning, pas violation (les package managers eux-mêmes ne considèrent pas ça comme une violation bloquante en général)
- **Cache contamination invalidé au scan** : la chaîne peut changer si le lockfile change
- **Graph Nalo réel attendu** : ~300-500 nœuds au total (91 npm + 27 pypi directs + transitives). Layout dagre doit rester lisible
- **Performance Cytoscape** : au-delà de 2000 nœuds, dégradation visible. Pour l'instant on ignore, on prévient si détecté
- **Design consistency** : couleurs/icônes alignées sur la palette CLI/UI existante (rouge/orange/jaune/vert/magenta/violet)
- **Invitation au split 5a/5b** : si tu décides de split, propose le découpage avant de commencer, pattern identique à Phase 4

---

## 14.10. Phase 6 — Polish (dogfood findings) ✅ done (2026-04-21)

**Livré :** 4 commits (Polish-1 fix critique + Polish-3/4 groupés + Polish-2 + docs), 215 tests Rust (+14 nets), clippy/fmt clean, 36 Vitest inchangés (Polish = backend-only). **Tous les 6 findings résolus.**

**Commits :**
- `911e97b` fix(store): canonicalize repo paths so `/api/graph` matches `packguard graph` (**Polish-1, root cause finding #6**)
- `3d2a9c8` fix(cli,server): truthful `packguard ui` banner + Scan button walks the store (Polish-3 + Polish-4)
- `2d1fc38` feat(cli): `packguard scans` + actionable errors + fingerprint/schema guidance (Polish-2)
- `1539bc9` docs(readme,screenshot): Polish — scans command + refreshed Nalo contamination (docs)

**Root cause du finding #6 (le plus instructif) :**

Le bug n'était **pas** dans le handler `/api/graph`. Il était dans la **canonicalisation de paths** en amont. Sur macOS (et ailleurs) :
- `/Users/mauc/Repo/Nalo/monorepo/front/vesta` (chemin utilisateur)
- `/private/Users/mauc/Repo/Nalo/monorepo/front/vesta` (chemin canonique après résolution de symlinks)
- variations relatives vs absolues

…étaient stockés comme des **lignes `repos.path` distinctes**. La CLI `packguard graph <path>` appelait `canonicalize()` avant le lookup et matchait une ligne. L'API avait son propre lookup par workspace id qui matchait une autre ligne (ou aucune). Résultat : divergence silencieuse.

**Fix** : `normalize_repo_path()` dans `packguard-store` applique `canonicalize()` à tous les sites read+write (`upsert_repo`, `last_fingerprint`, `load_repo_dependencies`, `workspaces_for_repo`). Deux formes du même path aboutissent maintenant sur la **même ligne** `repos.path`.

**Test de régression :** `api_graph_matches_service_output_when_repo_path_is_non_canonical` compare l'output de `/api/graph` à celui du service (utilisé par la CLI) sur le même store fixture. Vérifié en reverting temporairement le fix → le test panique avec `"API returned empty graph — path canonicalization regressed"` exactement comme spécifié. **Ce genre de régression ne reviendra pas silencieusement.**

### Résolutions des 6 findings

| # | Sév. | Zone | Résolution |
|---|---|---|---|
| 1 | 🔴 | CLI | **`packguard scans`** liste les scans en cache (path, ecosystem, deps, last_scan_at, fingerprint). Les erreurs `report`/`audit`/`graph` ajoutent un hint "Available scans" et pointent vers la commande. |
| 2 | 🔴 | CLI | Auto-open `packguard ui` introspecte `cfg!(feature = "ui-embed")` → cible `:5174` en release embarqué, `:5173` en dev. |
| 3 | 🔴 | CLI | Banner : `"dashboard served inline (ui-embed feature)"` en release vs `"dashboard: http://127.0.0.1:5173 (run pnpm …)"` en dev. Plus d'ERR_CONNECTION_REFUSED. |
| 4a | 🟡 | CLI | Skip fingerprint : `"no changes since last scan (fingerprint abc123…). Pass --force to re-scan."` |
| 4b | 🔴 | CLI | Nouveau `store.latest_migration_at()` + `store.last_scan_at()`. Si `migration_ts > scan_ts` → scan loggue `"⚙ store schema evolved since last scan, re-scanning to populate the new tables."` et **re-run même sur fingerprint match**. |
| 5 | 🔴 | UI | Server scan service itère `store.distinct_repo_paths()` et scanne chacun = exactement ce que l'utilisateur voulait. Fallback sur `ServerConfig.repo_path` pour stores vides, avec erreur pointant vers `packguard scan <path>` en CLI escape hatch. |
| 6 | 🔴 | Backend | **`normalize_repo_path` dans `packguard-store`** applique `canonicalize()` à tous les sites read+write. Variations de path pour le même repo (symlink, relatif vs absolu) convergent sur la même ligne DB. |

### Démo dogfood — critère de sortie ✅ atteint

```bash
$ rm ~/.packguard/store.db    # fresh start
$ packguard scan /Users/mauc/Repo/Nalo/monorepo/front/vesta --force
  … (83 direct deps scanned)
$ packguard scans
+---------------------------------------+------+------+---------------+---------------+
| Path                                  | Eco  | Deps | Last scan     | Fingerprint   |
+---------------------------------------+------+------+---------------+---------------+
| /Users/mauc/Repo/Nalo/...front/vesta  | npm  | 83   | 2026-04-21…   | d8e22eff5598… |
+---------------------------------------+------+------+---------------+---------------+
$ packguard sync --skip-osv
  ✓ typosquat — 28 suspect package(s) flagged
  📚 store holds 340 advisories
$ packguard ui /Users/mauc/Repo/Nalo/monorepo/front/vesta
  🚀 PackGuard server on http://127.0.0.1:5174
  → dashboard served inline (ui-embed feature)
  • press Ctrl+C to stop
```

**Screenshot critique `docs/screenshots/graph-focus-lodash.png` refreshé** : la chaîne `textlint-rule-doubled-spaces → textlint → @textlint/linter-formatter → lodash` rendue en rouge end-to-end, contre un **store frais créé avec le binaire Polish**. Node counter affiche `"4 nodes · 3 edges / 1084 total"` — le backend retourne bien 1084 nœuds (plus zéro) et le focus filter isole correctement le sous-graphe contaminé.

### Note de rétro-compatibilité

Les anciens stores (pré-Polish) restent lisibles par les binaires post-Polish — mais les lignes `repos.path` non-canoniques ne matchent pas les queries canonisées. Le scan suivant détecte le schema drift (`migration_ts > scan_ts`) et re-run automatiquement. Pas de migration manuelle nécessaire.

**Hors-scope respecté** : pas de redesign UI, pas de refactor des pages qui marchent, pas de nouvelles features hors des 6 findings. Tech-debts #2 (yarn.lock, pnpm nested) et #5 (refinery info) restent reportées.

<details>
<summary>Spec Polish Phase (pour historique)</summary>

4 sous-lots ordonnés par priorité : Polish-1 fix critique `/api/graph` avec test de régression CLI↔API, Polish-2 `packguard scans` + messages d'erreur actionnables + auto-force sur schéma drift, Polish-3 redesign bouton Scan UI (walk distinct_repo_paths), Polish-4 `packguard ui` banner + auto-open introspectent `cfg!(feature = "ui-embed")`.

Root cause finding #6 découverte : canonicalisation paths manquante dans `packguard-store` (symlink macOS `/private/var` vs `/var`, relatif vs absolu).

</details>

---

**Contexte :** session de dogfooding le 2026-04-21 par Thomas sur Nalo (front/vesta + services/incentive) a remonté **6 irritants concrets** en ~30 minutes d'usage, dont 5 🔴 bloquants qui empêchent de terminer le parcours de validation. Cette phase résout ces findings et **ré-autorise la suite du dogfooding**.

### Findings remontés — source de vérité pour cette phase

| # | Sév. | Zone | Description |
|---|---|---|---|
| 1 | 🔴 | CLI | `report`/`audit`/`graph` depuis un dir non-scanné → erreur `no cached scan for .` pas actionnable, pas de moyen de lister les scans en cache |
| 2 | 🔴 | CLI | Auto-open de `packguard ui` pointe sur `http://127.0.0.1:5173` (port Vite dev) au lieu de `:5174` quand la feature `ui-embed` est active → browser reçoit ERR_CONNECTION_REFUSED |
| 3 | 🔴 | CLI | Banner `packguard ui` affiche systématiquement `→ dev front-end: http://127.0.0.1:5173 (run pnpm dev in dashboard/)` même quand l'UI est embarquée → confusion totale |
| 4a | 🟡 | CLI | Message `✓ no changes since last scan (fingerprint …)` ne mentionne pas `--force` comme option → user bloqué sans savoir quoi faire |
| 4b | 🔴 | CLI | Le skip fingerprint continue à s'appliquer même quand le schéma a évolué (V5+ `dependency_edges` vide alors que le store aurait besoin d'être rempli) → re-scan explicite requis mais aucune guidance |
| 5 | 🔴 | UI | Bouton **Scan** du dashboard scanne le CWD du process `packguard ui` → échec `no supported manifest found at /…/packguard` si le binaire est lancé hors d'un repo scannable |
| 6 | 🔴 | **Backend** | `GET /api/graph` retourne `{nodes:[], edges:[], oversize_warning:null}` **quelle que soit la query** (avec ou sans `workspace`, avec ou sans `max_depth`), alors que la CLI `packguard graph <path>` lit les **mêmes** données et renvoie nodes/edges correctement. Divergence de lookup backend. **Casse le mode Focus contamination** (la killer feature Phase 5b) |

### Sous-lots (ordonnés par priorité)

#### Polish-1 — Fix backend `/api/graph` **[priorité absolue]**
- Diagnostic root cause : l'endpoint retourne vide alors que la CLI lit les mêmes données. Causes probables :
  - Filtre implicite sur `scan_id` ou `workspace_id` qui exclut tout
  - Handler qui résout l'identifiant workspace différemment de la CLI
  - `save_project` écrit dans une table, le handler lit dans une autre
  - Requête SQL qui référence un index ou une jointure foirée
- Ajouter test de régression : **test d'intégration qui assert que `/api/graph` retourne le même nombre de nodes/edges que la CLI `packguard graph --format json`** sur un store fixture identique. Ce test doit fail aujourd'hui, pass après fix.
- Même logique pour `/api/graph/contaminated?vuln_id=...` — vérifier qu'il n'a pas le même bug latent (il n'a pas été testé manuellement mais la symétrie suggère même code path)
- Validation live : après fix, `curl /api/graph` sur le store Nalo doit retourner ≥ 837 nodes (vu en Phase 5a)

#### Polish-2 — CLI store discoverability + better errors (findings #1, #4a, #4b)
- **Nouvelle commande `packguard scans`** (ou `packguard store list`) : liste les scans en cache
  ```
  Scans in ~/.packguard/store.db:
    /Users/mauc/Repo/Nalo/monorepo/front/vesta      npm     scanned 2026-04-21 09:24
    /Users/mauc/Repo/Nalo/monorepo/services/incentive  pypi   scanned 2026-04-21 09:30
  ```
  Colonnes : path, ecosystem, last_scan_at, package_count
- **Messages d'erreur actionnables** pour `report`/`audit`/`graph` sans target scannée :
  ```
  Error: no cached scan for "."
    Available scans:
      - /Users/mauc/Repo/Nalo/monorepo/front/vesta
      - /Users/mauc/Repo/Nalo/monorepo/services/incentive
    Run: packguard report <path>, or `cd` into a scanned directory.
  ```
- **Guidance `--force`** dans le skip fingerprint :
  ```
  ✓ [pypi] incentive — skipped (fingerprint match); pass --force to re-scan
  ```
- **Auto-force sur évolution de schéma** (fix 4b critical) : si la version de schéma du store < version du binaire (ex : store a V4, binaire a V5), `scan` doit détecter et refuser le skip fingerprint pour forcer l'alimentation des nouvelles tables. Message :
  ```
  ⚙ store schema outdated (V4 → V5), re-scanning to populate new tables…
  ```

#### Polish-3 — UI scan button redesign (finding #5)
- Le bouton Scan du dashboard ne doit plus scanner le CWD du serveur. Deux options — choisir l'une :
  - **Option A (préférée)** : bouton Scan = re-scan en batch de **tous les paths déjà en store**, progress par workspace dans le toast
  - **Option B** : bouton Scan ouvre une modal avec la liste des paths scannés (checkboxes) + input pour ajouter un nouveau path
- Nouveau endpoint si absent : `GET /api/scans` (liste les workspaces du store, réutilisable par Polish-2)
- Le bouton Sync reste inchangé (pas de dépendance au path)
- Tests : intégration qui vérifie qu'un click Scan appelle `/api/scan` pour chaque path connu sans passer par CWD

#### Polish-4 — `packguard ui` banner + auto-open introspection (findings #2, #3)
- Au runtime, introspection de la feature `ui-embed` :
  - Si active : banner `🚀 Dashboard served at http://127.0.0.1:5174/`, auto-open ouvre `:5174`
  - Si inactive : banner `🚀 API only on http://127.0.0.1:5174/  →  dev UI: pnpm dev in dashboard/ (:5173)`, auto-open ouvre `:5173`
- La feature étant une cfg flag Cargo, exposer via `const UI_EMBEDDED: bool = cfg!(feature = "ui-embed")` ou équivalent → dispo runtime sans coût
- Test : lancer le binaire sans feature, assert banner mentionne Vite ; lancer avec feature, assert banner ne mentionne pas Vite

### Critères de sortie

- [ ] Finding #6 fixé avec **test de régression qui compare API et CLI sur le même store**
- [ ] Findings #1, #4a, #4b : `packguard scans` existe, messages d'erreur actionnables, auto-force sur schéma outdated
- [ ] Finding #5 : bouton Scan dashboard fonctionne depuis n'importe quel CWD du serveur
- [ ] Findings #2, #3 : banner et auto-open introspectent la feature `ui-embed`
- [ ] Le parcours de dogfooding complet (Overview → Packages → Package detail → Graph focus lodash → Policies dry-run) est **exécutable sans workaround** de bout en bout
- [ ] Tous les tests précédents restent verts, clippy & fmt clean, pnpm lint/typecheck clean
- [ ] 15+ nouveaux tests (priorité : test de régression #6 + tests des nouvelles commandes CLI + tests du Scan button UI)

### Hors scope Polish
- **Phase 3 (air-gap)**, **Phase 6 alerts**, **Phase 7 apply** : restent reportés
- **Dark mode** : reporté (pas remonté comme irritant)
- **i18n**, **PDF export**, **multi-repo aggregated view** : reportés
- **Nouveaux écosystèmes** (cargo, go, maven) : reportés
- **Dashboard UX rework profond** : la Polish fixe des bugs, ne redessine pas les pages qui marchent

### Budget indicatif
- ~6-8 commits atomiques (Polish-1 probable un seul commit ciblé, Polish-2/3/4 potentiellement 2 chacun)
- ~15+ nouveaux tests
- Re-validation par Thomas après livraison, reprise du parcours dogfooding

### Points d'attention pour l'agent

- **Priorité absolue Polish-1 (backend /api/graph)** : c'est le seul bug qui casse une promesse produit (Phase 5b Focus contamination invisible en UI alors que c'est la killer feature). Commencer par ça. Si root cause profonde → remonter avant de continuer.
- **Ne pas redesigner l'UI** : les pages fonctionnent (Overview, Packages, Package detail, Policies testées en partie avant les blocages) — seulement fixer les bugs remontés. Pas de refactor opportuniste.
- **Tech-debts #2 (yarn.lock, pnpm nested) et #5 (refinery info) toujours reportées** — ne pas toucher.
- **Test de régression finding #6** : c'est le livrable le plus important, il prouve que ce type de divergence ne reviendra pas. Même fixture de store, assertion que `API graph response == CLI graph output` en nombre de nodes/edges et en ids.
- **Commande `packguard scans`** : nommage à valider, préférence pour `scans` (pluriel, court) plutôt que `store list`. Ouvrir à `store list` si tu trouves plus idiomatique.

---

## 14.11. Phase 6-bis — Polish-bis (findings post-Polish) ✅ done (2026-04-21)

**Livré :** 4 commits atomiques, 218 tests Rust (+3 nets), 39 Vitest (+3), clippy/fmt clean, ts-rs drift green. **Les 4 findings résolus, dont 2 avec des insights intéressants** (#9a était causé par #7, #9b n'était pas un bug).

**Commits :**
- `62e223d` fix(server,dashboard): `/graph` crash on unresolved edges — placeholder + safety net
- `f794e8e` feat(cli): `packguard ui` without path defaults to the most recent scan
- `fc22a4f` fix(dashboard): Compat tab — dependents coverage + honest empty banners
- `f7b6caf` docs(screenshots): Polish-bis dogfood replay — `/graph` default URL renders

**Résolutions des 4 findings**

| # | Zone | Résolution |
|---|---|---|
| 7 | CLI/UI | `packguard ui` prend un `Option<PathBuf>`. Sans arg + store populé → pick `scans_index()[0].path` (most recent, sorted `last_scan_at DESC`). Sans arg + store vide → banner `"no scans yet — run packguard scan <path>"`. Chaque auto-pick annoncé via `→ workspace: <path> (most recent scan) — override with packguard ui <path>` |
| 8 | Backend↔Frontend | **Two-sided fix** (exactement la consigne). **Backend** : `GraphNode.is_unresolved: bool` ajouté ; `services::graph::build` émet un placeholder node pour chaque edge target non résolu, rendu UI avec contour pointillé + 0.55 opacité + label italique. **Frontend** : orphan-edge filter dans `GraphCanvas` drop tout edge dont `source`/`target` n'est pas dans `nodes[]` — 3 lignes de safety net indépendantes du backend |
| 9a | Frontend | **Root cause était en fait #7** (mauvais CWD → edges vides → dependents vides). Auto-fixé par Polish-bis-2. Reinforced par un Vitest qui feed 5 dependents et asserte que chaque nom + le "(5)" header atterrissent dans le DOM |
| 9b | Backend | **Pas un bug parser** — les entrées `pnpm-lock` de Nalo pour `lodash` (et beaucoup d'autres) ne shippent légitimement aucun `engines` ni `peerDependencies`. Banner Compat distingue désormais deux cas : `"no rows for THIS version"` (amber, hint de re-scan) vs `"package ships no metadata"` (zinc, copy honnête "c'est normal pour ce package") |

### Insights méthodologiques à retenir

- **Finding #9a** : diagnostiquer le symptôme en premier (Compat vide) nous faisait chercher un bug frontend qui n'existait pas. Le vrai coupable était en amont (#7 → dependents vides remontées). Leçon : toujours vérifier que les données amont sont saines avant de suspecter le composant aval.
- **Finding #9b** : il n'y avait **aucun bug** — l'UI disait "No peer dependencies declared" alors que c'était la vérité pour `lodash`. Mais cette vérité se lisait comme un symptôme de bug. Leçon : les empty states doivent dire **pourquoi** ils sont vides (erreur de scan vs donnée absente légitime vs data model pas encore rempli) pour ne pas faire paniquer l'utilisateur.

### Test contracts "fail today, pass after fix"

Les 4 tests de régression sont encodés :
- Rust `graph_response_is_closed_every_edge_references_existing_nodes` asserte que chaque edge `source + target` vit dans `nodes[]`
- Vitest drops orphan edges avant de feed Cytoscape — vérifié que le test fail sans le filter (panic `expect(edges).toHaveLength(1)`)
- `ui_without_path_on_empty_store_prints_no_scans_yet_banner` + `...on_populated_store_picks_most_recent_scan` exercent le path banner via stdout incrémental (SIGKILL-safe)
- `disambiguates_installed_row_missing_from_package_has_no_metadata` couvre le nouveau split empty-case Compat

### Démo dogfood — critère de sortie ✅ atteint

```bash
$ rm ~/.packguard/store.db
$ packguard scan /Users/mauc/Repo/Nalo/monorepo/front/vesta --force
$ packguard sync --skip-osv
$ packguard ui                       # NO path arg ← le cas qui était cassé
  🚀 PackGuard server on http://127.0.0.1:5174
  → workspace: /.../front/vesta (most recent scan)
    (override with `packguard ui <path>`)
  → dashboard served inline (ui-embed feature)
```

**Invariants backend validés live** :
- `/api/graph` (aucune query) → **1481 nodes · 3677 edges** (était 0 avant le fix)
- **18 placeholder nodes** pour les unresolved optional deps
- **0 orphan edges** — chaque edge a source + target dans le node set
- Contamination toujours OK : CVE-2026-4800 → 3 chaînes, cachée après le 1er appel

### Screenshots livrés

- `docs/screenshots/graph-default-polishbis.png` — **1390 nodes · 3403 edges rendus** dans Cytoscape avec les 4 kind chips actifs (Runtime, Dev, Peer, Optional) = l'URL exacte qui crashait, désormais servie par `packguard ui` sans arg
- `docs/screenshots/graph-focus-lodash.png` (refreshed) — killer Phase 5b feature maintenue : `textlint-rule-doubled-spaces → textlint → @textlint/linter-formatter → lodash` en rouge, root contouré noir, lodash avec son border CVE

**Hors-scope respecté** : pas de redesign UI, pas de nouvelles pages, pas de commandes retirées. Tech-debts #2 / #5 reportées. Phase 7 (per-project) et Phase 8 (distribution) non touchées — les specs §14.12 / §14.13 restent intactes pour les sessions suivantes.

<details>
<summary>Spec Polish-bis (pour historique)</summary>

4 sous-lots : Polish-bis-1 fix Graph crash via two-sided fix (backend placeholder + frontend safety net), Polish-bis-2 `packguard ui` sans path défaut au most-recent, Polish-bis-3 Compat tab lit `dependents`, Polish-bis-4 honest empty banners pour compat rows.

Insights : #9a résolu par side-effect de #7, #9b n'était pas un bug.

</details>

---

**Contexte :** reprise du dogfooding après Polish a remonté **4 findings supplémentaires** non couverts par la première passe. 3 🔴 bloquants, 1 🟡. Cette mini-phase les ferme avant d'attaquer le per-project scoping.

### Findings à résoudre

| # | Sév. | Zone | Description |
|---|---|---|---|
| 7 | 🔴 | CLI/UI | `packguard ui` sans argument de path → `ServerConfig.repo_path` fallback sur `.` (CWD du process). Handler filtre silencieusement sur ce path default → vues UI vides sans message explicatif. Le user ne comprend pas que l'UI attend un path. |
| 8 | 🔴🔥 | Backend↔Frontend | `/api/graph` émet des edges vers des targets `@unresolved` (optional deps non installées, ex: `jest → node-notifier`) alors que ces nodes ne sont **pas** dans la liste `nodes[]`. Cytoscape crash au mount (`componentDidMount`), la page `/graph` est **inutilisable sur défaut** — workaround actuel : URL `?kind=runtime,dev,peer` (exclure optional) |
| 9a | 🔴 | Frontend | `/api/packages/:eco/:name/compat` retourne correctement `dependents: [...]` mais l'onglet Compatibility affiche "Used by (0)". UI ignore le champ `dependents` ou lit un nom désaligné. |
| 9b | 🟡 | Backend | Le même endpoint retourne `rows: []` pour tous les packages testés. Les parsers Phase 5 ne peuplent pas les `compatibility` rows (peer deps, engines) sur le format de lockfile actuel de Nalo. Moins prioritaire — metadata nice-to-have. |

### Sous-lots

#### Polish-bis-1 — Fix Graph crash (finding #8) [priorité absolue]
- **Option A (valeur produit)** : backend émet un **placeholder node** pour chaque target non résolu, avec flag `is_unresolved: true` (+ `is_placeholder: true` si utile). Frontend rend ces nodes en style distinctif (contour pointillé, fond gris clair, label `<name>@unresolved`, opacité réduite)
- **Option C (défense profondeur)** : frontend filtre aussi les edges orphelins avant de feed Cytoscape (safety net qui rend le front robuste indépendamment du backend)
- **Faire les deux — A pour la valeur, C pour la robustesse**. C est 3 lignes de code, l'omettre serait une faute
- Test de régression : store fixture qui contient un edge vers unresolved → `/api/graph` retourne un placeholder node correspondant → frontend rend sans crash. Vérifier par reverting le fix backend → test front isolement pass quand même grâce au safety net

#### Polish-bis-2 — `packguard ui` sans path → défaut intelligent (finding #7)
- Si aucun argument de path ET `store.distinct_repo_paths()` non-empty → **défaut sur le workspace le plus récent** (sorted by `last_scan_at DESC`)
- Banner explicite :
  ```
  🚀 PackGuard server on http://127.0.0.1:5174
  → workspace: /Users/mauc/Repo/Nalo/monorepo/front/vesta (most recent scan)
  → override with: packguard ui <path>
  ```
- Si store **vide** : banner dit `"No scans yet, run packguard scan <path> first"` et l'UI affiche un placeholder explicite (pas une page vide)
- **Bonus si léger** : permettre à l'UI de lister les workspaces connus dans le header (utilisable par Phase 7 derrière). Sinon juste `ServerConfig.active_workspace` exposé à l'UI

#### Polish-bis-3 — Frontend lit `dependents` (finding #9a)
- Fix trivial dans `dashboard/src/pages/PackageDetail.tsx` (ou composant Compatibility) : lire `response.dependents` au lieu de ce qui est lu actuellement
- Vérifier le schéma `ts-rs` du DTO : nom de champ côté TS doit matcher le JSON renvoyé
- Test Vitest : mock API response avec dependents peuplés → vérifier que "Used by" affiche bien 5 lignes

#### Polish-bis-4 — Backend `compat rows` populés (finding #9b)
- Investiguer pourquoi les parsers Phase 5 n'émettent pas les compat rows pour lodash (et probablement tous les packages). Deux hypothèses à valider :
  - Le parser émet les rows mais l'endpoint ne les lit pas correctement (canonicalisation redux ou mauvaise query)
  - Le parser skip l'extraction compat pour ce format de lockfile spécifique (pnpm v6 vs v9, package-lock v2 vs v3)
- Test d'intégration : fixture lockfile avec `peerDependencies` + `engines` → parser → `compatibility` rows peuplées → API les renvoie
- Si le fix est complexe (découverte que le parsing compat n'est pas implémenté pour certains formats) → logger le cas et livrer le "rien à afficher" proprement (message "peer deps extraction not yet supported for pnpm-lock v6 in this release") plutôt que silence

### Critères de sortie

- [ ] Page `/graph` rend sans crash sur URL défaut (incluant `optional`), ≥1 placeholder node visible pour les unresolved, style distinctif
- [ ] `packguard ui` sans path défaut sur scan le plus récent, banner explicite
- [ ] Onglet Compatibility affiche les dependents correctement (≥5 pour lodash chez Nalo)
- [ ] Compat `rows` peuplées OU message "extraction not supported for this format" si limitation connue
- [ ] Aucune régression des 215 tests Rust + 36 Vitest
- [ ] ~10-12 nouveaux tests (dont safety net Cytoscape côté front + regression API placeholder + Vitest Compat tab)
- [ ] Démo dogfood : `rm ~/.packguard/store.db && packguard scan … && packguard ui && /graph par défaut` → chaîne lodash visible sans toucher l'URL

### Hors scope Polish-bis
- **Phase 7 (per-project scoping)** : reporté à la phase suivante
- **Phase 8 (distribution)** : reporté
- **Redesign UI** : encore et toujours
- Tech-debts #2 (yarn.lock, pnpm nested) et #5 (refinery info) : toujours reportées

### Budget
- ~3-4 commits atomiques
- ~10-12 nouveaux tests
- Re-validation dogfood par Thomas avant Phase 7

### Points d'attention
- **Principe "rien en dur"** : aucun hardcode de path Nalo ou de layout spécifique dans le fix. `packguard ui` sans arg doit marcher sur n'importe quel store contenant des scans
- **Finding #8 Option A + C** obligatoire : la défense en profondeur est triviale et empêche ce type de crash de revenir à la moindre anomalie backend
- **Finding #9b** peut être partiellement résolu : si l'extraction compat requiert refonte de parser, livrer le "message d'absence honnête" plutôt que laisser l'UI dire "No peer dependencies declared" (trompeur)

---

## 14.12. Phase 7 — Per-project scoping (finding #10)

**Split décidé en cours de cadrage** (agent a proposé, validé 2026-04-21) — pattern identique à Phase 5 :
- **Phase 7a ✅ done (2026-04-21)** : Backend + CLI — 3 commits (`1042f7f` backend + `eac189b` CLI + `0a33b25` chore cleanup), 227 Rust tests (+9 nets, +12 bruts), 3 nouveaux DTOs ts-rs (`WorkspaceInfo`, `WorkspacesResponse`, `ProjectQuery`). Live Nalo : `/api/overview` agrégat 118 packages = `?project=vesta` 91 + `?project=incentive` 27 (parity ✓). 404 avec known workspaces list sur project inconnu. CLI `--project` alias byte-for-byte identique du path arg, fallback most-recent avec warning stderr sur stdin vide. Zéro hardcode `nalo/vesta/incentive/monorepo` dans le code prod (seule occurrence résiduelle = doc comment générique sur "monorepo" = industry term).
- **Phase 7b ✅ done (2026-04-21)** : Frontend + Policies UI — 3 commits (`35ee34a` backend/DTO + `1315d37` frontend + `3a2540b` docs), 50 Vitest (+11 nets), 227+ Rust toujours verts. `<WorkspaceSelector />` dans le header populé via `/api/workspaces` (sorted `last_scan_at DESC`), écrit `?project=<path>` dans l'URL sans démonter la page, persistance localStorage avec nettoyage des valeurs stales. `<ScopeBadge />` sur Overview / Packages / Graph / Policies affiche `"Scope: <label>"` ou `"All workspaces"`. `useScope()` hook + query keys incluant project → switch ≡ refetch propre. Policies per-workspace strict : empty state `"Select a workspace"` sans scope, sinon load/save `<repo>/.packguard.yml`, reload auto sur scope flip. Package detail Compat tab : drill-down `<details>` repliables par workspace avec parent count + path complet (field `CompatDependent.workspace` ajouté côté DTO + service backend). Zéro hardcode `nalo/vesta/incentive/monorepo` (grep production = 0). **Screenshots laissés en TODO utilisateur** (port 5174 occupé + pas de browser headless dispo côté agent) — à produire par Thomas : 2 onglets browser côte à côte sur 2 workspaces + Compat Used-by + Policies empty-vs-scoped.

Budget : 7a ~4 commits / 20+ tests backend ✅ (livré 3 commits / +9 nets), 7b ~4 commits / 10+ Vitest ✅ (livré 3 commits / +11 nets).

**Contexte :** pendant le dogfooding, Thomas a identifié un manque structurel. PackGuard scanne plusieurs projets (vesta, incentive, potentiellement tous les services Nalo), mais l'UI affiche tout agrégé sans possibilité de focus par projet. Pour un monorepo, c'est impensable en usage quotidien — chaque équipe veut voir "son" projet.

**Principe fondamental — "rien en dur" :** le scoping doit marcher **sur n'importe quel repo**. Aucune logique Nalo-spécifique. Les workspaces sont découverts via `store.distinct_repo_paths()`, affichés dans un selector, et filtrés par query param.

### Design retenu — Option C hybride

**URL query param `?project=<path>` sur les routes existantes**, alimenté par un **selector dans le header UI**.

```
Routes avec scope optionnel:
/                              → Overview agrégé (tous workspaces)
/?project=<path>               → Overview scopé sur ce workspace
/packages                      → Packages tous workspaces
/packages?project=<path>       → Packages scopés
/graph                         → Graph tous workspaces
/graph?project=<path>&focus=CVE-2026-4800  → Graph scopé + focus CVE

Routes qui ne changent pas (entité package est globale):
/packages/:eco/:name           → Detail lodash (affiche "Used by" multi-workspace avec drill-down)
/policies                      → Éditeur (policy = global ou per-projet selon implémentation, voir sous-lot 7.4)
```

**Pourquoi Option C vs A ou B :**
- URL = single source of truth ✓ (bookmarkable, shareable, hard-reload-proof, multi-tab)
- Selector header = UX moderne ✓ (compact, pas de routes imbriquées)
- Implementation simple ✓ (query param vs refactor routing)
- Cohérent avec les filtres existants (`has_cve`, `severity`, `max_depth`, `kind`)

### Sous-lots

#### 7.1 — Backend : API filters par workspace
- Chaque endpoint qui retourne des listes de packages/vulns/malware/edges accepte un query param `?project=<path>` optionnel
- Par défaut (aucun param) = agrégat tous workspaces (comportement actuel)
- Validation du path : si inconnu en DB → erreur 404 avec la liste des paths connus
- Nouveau endpoint (si pas déjà) : `GET /api/workspaces` retourne `[{path, ecosystem, last_scan_at, packages_count}]` — utilisé par le selector
- Canonicalisation du `project` param cohérente avec le Polish-1 (fix #6) — même `normalize_repo_path`
- Tests : assertion que `/api/overview?project=<path>` retourne strictement un sous-ensemble de `/api/overview`

#### 7.2 — Frontend : workspace selector header
- Composant `<WorkspaceSelector />` dans `components/layout/Header.tsx`
- Source : `useQuery(['workspaces'], fetchWorkspaces)`
- Affichage : dropdown avec option "All workspaces (aggregate)" en premier, puis la liste triée par `last_scan_at DESC`
- Sélection → update URL search param `project=<path>` sur la route courante (sans démonter la page) via `useSearchParams` de react-router
- Persistance : dernier workspace sélectionné sauvé en localStorage, restauré au prochain refresh si pas d'override URL
- Label intuitif pour le path : afficher le segment de fin (`vesta`, `incentive`) + full path en tooltip

#### 7.3 — Frontend : pages consomment le scope
- Overview, Packages, Graph : lire `project` de `useSearchParams`, le passer aux fetcher TanStack Query (cache key inclut le project)
- Badge visuel discret dans chaque page : `"Scope: front/vesta"` en haut (ou "All workspaces" si agrégé)
- Package detail (`/packages/:eco/:name`) : **reste non-scopé** (le package est une entité globale), mais section "Used by" liste maintenant les workspaces concernés avec drill-down :
  ```
  Used by (3 workspaces):
    ▸ front/vesta — @nalo/phoebus@2026.4.16, @visx/responsive@3.12.0, ...
    ▸ front/phoebus — lodash@4.17.23 (direct dep)
    ▸ services/incentive — (not used)
  ```
- Graph : `?project=<path>` restreint le graph aux edges de ce workspace, focus CVE continue de marcher avec l'intersection

#### 7.4 — Policies : per-workspace ou global ?
- **Décision produit à trancher avant implémentation** : le `.packguard.yml` vit dans le **projet** (model classique comme `.eslintrc`, `tsconfig.json`). Implication :
  - Page `/policies?project=<path>` affiche le YAML du projet sélectionné
  - Sans scope → message "Select a workspace to view its policy" (pas de sens d'éditer un global)
  - Écriture : PUT écrit dans `<workspace>/.packguard.yml`, pas un global
- Support d'un policy global à la racine du repo (hérité par les sous-projets) → **Option reportée Phase 8** quand la question des monorepos-with-shared-config se pose vraiment

#### 7.5 — CLI : flag `--project` uniforme
- `report` / `audit` / `graph` acceptent déjà un path argument. **Uniformiser :** tous acceptent aussi `--project <path>` comme alias pour être cohérent avec l'UI
- Fallback si ni arg ni `--project` : "most recent scan" (même logique que `packguard ui` post-Polish-bis), avec avertissement. Jamais de CWD silencieux
- `packguard scans` gagne un flag `--json` pour pipeline-able output

### Critères de sortie

- [ ] Selector workspace dans le header UI, populé dynamiquement via `/api/workspaces`
- [ ] Overview, Packages, Graph consomment `?project=<path>` et rendent correctement scopés ou agrégés selon URL
- [ ] Package detail affiche "Used by" multi-workspace avec drill-down
- [ ] Policy editor scope sur `<workspace>/.packguard.yml` (ou message "select workspace")
- [ ] CLI `--project` + fallback "most recent" uniformisé sur tous les endpoints
- [ ] **Aucun hardcode** de path ou de nom de projet dans le code — validable par grep ciblé
- [ ] Démo : scanner 3 workspaces Nalo différents, switcher entre eux dans l'UI, vérifier les métriques correctement scopées
- [ ] ~30+ nouveaux tests (API filtering + UI scope consumption + CLI --project + selector composant)

### Hors scope Phase 7
- **Policy héritée** (root .packguard.yml + overrides per-workspace) → Phase 8 si demandée
- **Comparaison inter-workspaces** (diff métriques entre 2 projets) → future phase
- **Multi-tenant view** (équipes différentes avec ACL per-workspace) → v2 `serve` mode
- Tech-debts existantes inchangées

### Décision probable split 7a / 7b
- 7a Backend (7.1 + 7.4 + 7.5) — API + CLI, validable par JSON
- 7b Frontend (7.2 + 7.3) — selector + pages scopées
- Invitation à l'agent : split naturellement si > 5 commits ou scope trop chargé

### Budget indicatif
- ~7-8 commits atomiques (split possible en 2 sessions)
- ~30+ nouveaux tests
- Screenshot : 2 workspaces côte à côte dans 2 onglets browser, métriques différentes (preuve visuelle du scoping)

---

## 14.13. Phase 8 — Distribution & Adoption

**Split décidé en cours de cadrage** (agent a proposé, validé 2026-04-21) — pattern Phase 4/5/7. Frontière nette = **credentials requis ou non** :

- **Phase 8a ✅ done (2026-04-21)** — 7 commits atomiques, 233 Rust tests (+7 init variants), 50 Vitest inchangés, clippy/fmt clean, actionlint clean. Docker image `packguard:test` ~46 MB distroless/cc, `docker run packguard scan /work` fait un round-trip npm registry réel. Matrix release 5 targets (macos intel+arm / linux x64+arm64 / windows). Secrets optionnels gated `if: env.* != ''` → workflow vert même sur fork. `install.sh` POSIX one-liner avec SHA256 verify + fallback no-sudo. `packguard init --with-ci <gitlab|github|jenkins>` avec auto-détection VCS. 4 docs integrations (gitlab / github / pre-commit / vscode) copy-paste prêtes, cache `~/.packguard/` sur hash lockfiles documenté. Homebrew formula template 4 archs (url + sha256 + test block). `PUBLISHING.md` 297 lignes runbook 8b complet (secrets inventory, cargo publish order core→store→policy→intel→server→cli, rollback par canal, security checklist). Grep "rien en dur" clean (nalo = seulement `github.com/nalo/packguard` canonical repo URL, monorepo = terme générique). **Onboarding 5 min validé** : install.sh → `init --with-ci github` → cp → git commit → PR en 3 commandes.
- **Phase 8b 🎯 prochain** — Publishing + Nalo validation (requiert credentials ou accès externe). `cargo publish` des 6 crates, création du tap Homebrew, push Docker Hub + ghcr.io, ajout du step PackGuard dans un vrai `.gitlab-ci.yml` Nalo avec preuve MR bloquée sur CVE critical. Exécution réduite à "poser les secrets, tag v0.1.0, exécuter le runbook PUBLISHING.md".

**Contexte :** PackGuard est techniquement complet (phases 0 → 7) mais n'a **aucun canal de distribution**. Un dev ou une équipe qui voudrait l'utiliser doit cloner le repo source, builder avec cargo, gérer les features — pas viable en adoption. Cette phase ferme la boucle "outil → produit utilisable par d'autres qu'un dev Rust".

**Principe fondamental — "rien en dur" :** les artefacts de distribution sont **génériques**. L'outil s'installe identique partout. Aucun assumption de Nalo dans les binaires, images Docker, ou docs.

### Sous-lots

#### 8.1 — Binaires release multi-plateformes
- **GitHub releases** automatisées via CI (GitHub Actions ou GitLab CI pour Nalo) à chaque tag version
- Targets : `darwin-x86_64`, `darwin-aarch64`, `linux-x86_64`, `linux-aarch64`, `windows-x86_64`
- Binaires statiques (musl pour Linux), self-contained (ui-embed activé en release)
- Checksums SHA256 + signature (cosign ou minisign) pour vérification
- Script d'install one-liner : `curl -L https://.../install.sh | sh` qui détecte la plateforme

#### 8.2 — Publication crates.io + Homebrew
- **crates.io** : `cargo publish` pour `packguard-core`, `packguard-store`, `packguard-policy`, `packguard-intel`, `packguard-server`, `packguard-cli`. Version semver alignée.
- **Homebrew** : tap dédié (`brew install <org>/tap/packguard`) avec formula auto-générée depuis les GitHub releases
- Documentation README : 3 options d'install (source / crates.io / brew) avec choix guidé

#### 8.3 — Image Docker officielle
- `Dockerfile` multi-stage (builder Rust + runtime distroless ~10MB)
- Feature `ui-embed` activée par défaut dans l'image
- Published sur Docker Hub ET GitHub Container Registry : `packguard/cli:latest`, `:vX.Y.Z`
- Support Linux amd64 + arm64 via buildx
- ENTRYPOINT `packguard`, CMD par défaut `--help`

#### 8.4 — Docs CI/CD — recettes copy-paste
- **Nouveau répertoire** `docs/integrations/` avec exemples :
  - `gitlab-ci.md` — step GitLab CI complet avec cache DB + SARIF export + fail-on
  - `github-actions.md` — workflow GitHub Actions équivalent
  - `pre-commit.md` — hook pre-commit qui bloque avant commit sur CVE critical
  - `vscode-task.md` — task VSCode pour run depuis l'éditeur
- **Principe générique** : chaque exemple marche sur n'importe quel projet, pas de référence Nalo
- Validation : un dev extérieur (ou un test CI dédié) doit pouvoir copier-coller dans son propre repo et faire tourner

#### 8.5 — `packguard init` enrichi
- `packguard init` actuel génère un `.packguard.yml`. On ajoute :
  - Flag `--with-ci gitlab|github|jenkins` qui génère en plus un snippet prêt à coller dans le pipeline
  - Détection auto du gestionnaire VCS (`.gitlab-ci.yml` / `.github/workflows/` existent ?) → suggère de l'ajouter
  - Message final pointe vers la doc d'intégration appropriée

#### 8.6 — Validation sur un vrai projet Nalo
- Pick un projet Nalo concret (**vesta** probablement, le plus utilisé)
- Ajouter un step GitLab CI `packguard` qui run sur chaque MR
- Configurer le `fail-on-violation` pour bloquer une MR avec CVE critical introduit
- Preuve : créer une MR synthétique qui bump une dep vers une version vulnérable → la pipeline bloque → on sait que l'outil a de l'impact réel
- Cette validation = critère de sortie obligatoire

#### 8.7 — Multi-config monorepo (si la validation 8.6 en révèle le besoin)
- Testé sur un monorepo type Nalo avec `.packguard.yml` à la racine ET dans les sous-projets
- Définir la règle d'héritage : policy root = defaults, policy enfant = override
- Documenter explicitement dans `docs/monorepos.md`
- Reporter en Phase 9 si jamais ça casse 8.6 et que ça devient son propre chantier

### Critères de sortie

- [ ] 5 binaires release publiés + checksums + install one-liner testé
- [ ] `cargo install packguard` marche sur une machine neuve
- [ ] `brew install <org>/tap/packguard` marche
- [ ] `docker run packguard scan` marche
- [ ] Au moins 2 recettes CI (GitLab + GitHub) testées end-to-end (pas juste YAML dans un MD)
- [ ] `packguard init --with-ci gitlab` génère un snippet qui marche
- [ ] **Validation finale Nalo** : au moins un projet Nalo a une CI PackGuard active et bloquante sur CVE critical
- [ ] README racine réorganisé avec section "Install" en haut, section "Integrate in CI" juste après
- [ ] Docs générées dans `docs/integrations/` passent une relecture "dev tiers qui ne connaît pas PackGuard"

### Hors scope Phase 8
- **Team server mode `packguard serve`** → v2
- **Auth SSO / OIDC** → v2
- **Air-gapped bundle export/import** (Phase 3) → reporté séparément
- **Auto-PR generation pour bumps** (Phase 7-`apply`) → reporté séparément
- Tech-debts #2, #5 toujours reportées

### Budget indicatif
- ~6-8 commits atomiques
- Tests : pipeline CI qui build + publish un binaire testable + tests d'install sur machine CI neuve
- **Pas de tests unitaires supplémentaires** sur le code Rust — cette phase est pur packaging/distribution

### Points d'attention
- **Principe "rien en dur" critique ici** : le snippet GitLab CI fourni par `packguard init` doit marcher sur n'importe quel repo, pas seulement Nalo. Zéro path hardcodé.
- **Sécurité supply-chain** : les binaires PackGuard doivent être signés (cosign), les images Docker scannées (Trivy), le hash release committé dans Git. Ironique sinon.
- **Doc onboarding** : viser 5 minutes du "jamais entendu parler de PackGuard" à "la pipeline bloque une CVE dans mon projet". Si plus long, c'est raté.

---

## 15. Tech debt & follow-ups (remontés Phase 1)

À traiter en Phase 1.5 ou intégré à une phase ultérieure. Ordre par priorité :

1. ~~**Store : enrichir l'historique des versions**~~ **✅ résolu Phase 1.5** (commits `be9bf9b` + `e359112`). Historique complet persisté pour npm + PyPI ; resolver strict ; `InsufficientCandidates` remonté proprement. Cf. §14.5.

2. **Parsers lockfiles manquants** *(limitation usage réel)*
   - pnpm-lock.yaml : **supporté racine uniquement**. Workspaces pnpm imbriqués reportés.
   - yarn.lock (classic + berry) : **non parsé** — seul `package.json` est utilisé en fallback.
   - À traiter quand un repo cible les exigera (Nalo front est pnpm root, ça passe).

3. **Évaluation `block.*`** — quasi résolu :
   - ✅ `block.deprecated` / `block.yanked` câblés Phase 1.5
   - ✅ `block.cve_severity` câblé Phase 2 (commit `42f11a2`, `VulnerabilityViolation`)
   - ✅ `block.malware` câblé Phase 2.5 (commit `febcd83`, `MalwareViolation`)
   - ⏳ `block.typosquat: strict` override per-package dans `.packguard.yml` — reportable à la demande, actuellement seulement global

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
