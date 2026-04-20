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
| **0 — Spike** | POC Rust qui scan un projet npm + query registry npm + classif semver + sortie table | 🎯 prochain |
| **1 — MVP CLI** | npm/pnpm/yarn + pip/poetry/uv, policy offset, SQLite, report CLI | |
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

## 13. Phase 0 — Spike (prochain pas)

**Durée cible :** ~1 semaine.

**Scope :**
1. `packguard scan ./un-projet-npm` → lit `package.json` + `package-lock.json`
2. Pour chaque dep directe, query `registry.npmjs.org` → `latest`
3. Compare installé vs latest → classifie (patch/minor/major)
4. Sortie table colorée en terminal

**Hors scope du spike :**
- Pas de SQLite encore (tout en mémoire)
- Pas de dashboard
- Pas de vulns
- Pas de policy (juste affichage brut)
- Pas de Python
- Pas de peer deps / graphe

**Ce que ça valide :**
- Détection manifest/lockfile
- Parsing
- Client registre + rate-limit basique
- Comparaison semver via `node-semver-rs`
- Ergonomie CLI de base

---

## 14. Décisions verrouillées ✅

| Dimension | Choix |
|---|---|
| Nom | **PackGuard** |
| Forme | 1 binaire, 3 modes (`scan` / `sync` / `ui`) |
| Core | Rust |
| Dashboard | Vite + React + shadcn/ui + Tailwind |
| Store | SQLite (WAL) |
| Offline | Niveaux 1 (online) + 2 (snapshot) en v1 |
| Écosystèmes MVP | npm/pnpm/yarn + pip/poetry/uv |
| Auth `serve` | Reportée v2 (basic login/pw à l'époque) |
| Cloud | Explicitement hors scope |

---

## 15. Questions en suspens

- Aucune bloquante. Prochaine étape = démarrer le spike Phase 0.
