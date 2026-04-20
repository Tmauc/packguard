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
| **1.5 — Historique versions** | Persister `package_versions` complet + resolver policy précis (offset exact, `min_age_days`, `stability`) | 🎯 en cours |
| **2 — Vuln intel online** | OSV + GH Advisory, cache, badges | |
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

## 14.5. Phase 1.5 — Historique versions 🎯 en cours

**Objectif :** tenir la promesse produit du policy engine. Aujourd'hui le store ne persiste que `latest_version` par package, donc le resolver a un fallback "major-distance" imprécis. `min_age_days` et `stability` sont parsés mais ne peuvent pas être évalués faute d'historique.

Cette mini-phase verrouille la promesse avant que OSV s'en serve (Phase 2 indexera les affected_ranges sur cet historique).

### Découpage en 3 sous-lots

#### 1.5.1 — Alimenter `package_versions` depuis les scanners
- Schéma SQL déjà prévu (§8) : `package_versions(pkg_id, version, published_at, deprecated, yanked, metadata_json)`
- **npm** : payload registre expose `time.<version>` (ISO timestamp) pour chaque version, `versions.<version>.deprecated` (string ou null), `dist-tags.latest`
- **PyPI** : payload expose `releases.<version> = [{upload_time, upload_time_iso_8601, yanked, yanked_reason, ...}]`
- Insertion bulk par package, idempotent (INSERT OR REPLACE keyé sur `(pkg_id, version)`)
- `scan` doit peupler `package_versions` quand il touche un package ; `--offline` doit continuer à marcher si l'historique est déjà en DB

#### 1.5.2 — Resolver policy consomme l'historique
- Remplacer le fallback "major-distance" dans `packguard-policy::evaluate_dependency`
- **`offset: N`** = recommandation = max version telle que `(latest_major - version_major) == abs(N)` (pour N négatif ; N = 0 → latest major exact)
- **`min_age_days`** = filtre : exclure toute version avec `published_at > now() - duration(days)` avant calcul du max
- **`stability: stable`** = filtre : exclure toute version pre-release (détectée via le dialecte semver de l'écosystème : `-` suffix pour SemVer npm, `a/b/rc/dev` pour PEP 440)
- Ordre d'application : `stability` → `min_age_days` → `offset/pin/overrides` → `block.*` (le bloc `block.*` reste non évalué hors `deprecated`/`yanked` optionnels — voir sous-lot 1.5.3)
- Si aucune version ne survit aux filtres → status `PolicyInsufficientCandidates` (nouveau variant) avec message clair, pas de panic

#### 1.5.3 — Tests + fixtures riches
- Fixtures JSON avec historiques réels (react, django, @babel/core) stockées en `tests/fixtures/registries/`
- Snapshot tests (`cargo-insta`) pour le resolver sur chaque combinaison policy × historique
- Cas couverts :
  - offset exact (`-1` avec majors 17/18/19 présents → 18.x.y le plus haut)
  - offset insuffisant (majors manquants → `PolicyInsufficientCandidates`)
  - `min_age_days: 7` filtre les versions trop récentes
  - `stability: stable` exclut `19.0.0-rc.1`, `3.0.0a1`
  - Interaction avec `overrides` (pin qui écrase offset, group qui écrase defaults)
- Test d'intégration : re-scanner Nalo/monorepo et vérifier que les recos sont cohérentes
- **Bonus si ça ne déborde pas** : câbler `block.deprecated` et `block.yanked` (trivial maintenant qu'on a les colonnes). `block.cve_severity` et `block.malware` restent Phase 2.

### Critères de sortie
- [ ] `scan` peuple `package_versions` (npm + pypi) : une ligne par version connue par le registre, avec `published_at`, `deprecated`, `yanked`
- [ ] Resolver supprime le fallback "major-distance" ; calcul d'offset strict ; `min_age_days` et `stability` actifs
- [ ] Variant d'état `PolicyInsufficientCandidates` remonté proprement dans `report`
- [ ] Snapshot tests sur 5+ fixtures d'historiques
- [ ] Démo `report` sur Nalo/monorepo montre un changement de reco vs Phase 1 (attendu : recommandations plus précises, potentiellement des warnings devenus patches réels)
- [ ] Tous les tests Phase 1 restent verts ; ajout de 15+ nouveaux tests
- [ ] clippy & fmt clean

### Hors scope Phase 1.5
- OSV / CVE / GH Advisory → Phase 2
- `block.cve_severity`, `block.malware` → Phase 2
- Parsing lockfiles manquants (pnpm nested, yarn.lock) → à la demande
- `PACKGUARD_LIVE_TESTS=1` automation → Phase 2

---

## 15. Tech debt & follow-ups (remontés Phase 1)

À traiter en Phase 1.5 ou intégré à une phase ultérieure. Ordre par priorité :

1. **Store : enrichir l'historique des versions** *(bloquant pour recos précises)*
   - Aujourd'hui le store ne persiste que `latest_version` par package. Le résolveur policy a donc un fallback "major-distance" : quand on ne peut pas calculer la recommandation faute d'historique, on compare la majeure installée vs majeure latest.
   - npm et PyPI renvoient déjà l'historique complet dans leur payload → l'absorber en DB.
   - Débloque : `offset: -1` précis (patch/minor réels), `min_age_days`, stability filters, recommandations exactes.
   - **Doit passer avant Phase 2** : OSV indexe les affected_ranges → besoin de l'historique pour matcher.

2. **Parsers lockfiles manquants** *(limitation usage réel)*
   - pnpm-lock.yaml : **supporté racine uniquement**. Workspaces pnpm imbriqués reportés.
   - yarn.lock (classic + berry) : **non parsé** — seul `package.json` est utilisé en fallback.
   - À traiter quand un repo cible les exigera (Nalo front est pnpm root, ça passe).

3. **Évaluation `block.*`** *(dépend de Phase 2)*
   - `block.cve_severity`, `block.malware`, `block.deprecated`, `block.yanked` : **parsés et stockés, non évalués**.
   - Naturellement adressé en Phase 2 quand OSV/GH Advisory entrent + extraction `deprecated`/`yanked` depuis les payloads npm/PyPI.

4. **Tests live gated** *(qualité process)*
   - `PACKGUARD_LIVE_TESTS=1` prévu, non implémenté Phase 1. Validations live = manuelles pour l'instant (documentées dans les commits).
   - À automatiser en Phase 2 avec fixtures réseau + dumps OSV.

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
