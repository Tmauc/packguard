import Link from 'next/link'
import Image from 'next/image'
import Hero3D from '@/components/Hero3D'

const VALUE_PROPS = [
  {
    title: 'Offset policy, not lockstep',
    body: "Enforce `latest - N` with conservative defaults. Rust workspace, npm monorepo, pip-compile — all driven by one `.packguard.yml`.",
  },
  {
    title: 'Supply-chain intel included',
    body: 'OSV + GitHub Advisory + OSV-MAL + typosquat heuristic + optional Socket.dev — one sync, local SQLite, usable offline.',
  },
  {
    title: 'Graph with contamination chains',
    body: 'Trace any CVE from your workspace root to the vulnerable leaf. Transitive edges harvested from real lockfiles, not estimates.',
  },
  {
    title: '100% local, air-gap ready',
    body: 'One static Rust binary. No SaaS, no telemetry, no daemon. Bring your own intel dump and run on a disconnected build host.',
  },
]

const FEATURE_ROWS = [
  {
    title: 'Overview at a glance',
    body: 'Health score, tracked packages, CVE matches, and supply-chain signals. Every number is scoped to the active workspace.',
    image: '/screenshots/overview.png',
    alt: 'PackGuard dashboard Overview — health score, packages tracked, CVE matches, malware & typosquat donuts.',
  },
  {
    title: 'Trace a CVE to its root',
    body: 'The graph view runs a BFS from the vulnerable leaf and lights up every contamination chain. Same algorithm as `packguard graph --contaminated-by`.',
    image: '/screenshots/graph-focus-lodash.png',
    alt: 'Graph view highlighting a contamination chain from a textlint root down to a vulnerable lodash version.',
  },
  {
    title: 'Per-workspace policy',
    body: 'Monorepo-ready: each workspace has its own `.packguard.yml` with its own offset, stability, and block rules. Edit in the UI or on disk.',
    image: '/screenshots/policies.png',
    alt: 'Policies editor — CodeMirror YAML with dry-run preview vs current policy.',
  },
]

function BrandMark() {
  return (
    <Link href="/" className="flex items-center gap-2.5 text-slate-ink">
      <svg width="24" height="24" viewBox="0 0 32 32" aria-hidden>
        <rect width="32" height="32" rx="7" fill="#0B6B3A" />
        <path
          d="M16 6 L24 9.5 V16.5 C24 20.9 20.4 24.5 16 26 C11.6 24.5 8 20.9 8 16.5 V9.5 L16 6 Z"
          fill="none"
          stroke="#FBFAF7"
          strokeWidth="2"
          strokeLinejoin="round"
        />
        <path
          d="M12 16 L15 19 L20 14"
          stroke="#FBFAF7"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <span className="font-semibold tracking-tight">PackGuard</span>
    </Link>
  )
}

function TopNav() {
  return (
    <nav className="mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
      <BrandMark />
      <div className="flex items-center gap-7 text-[14px] text-mute">
        <Link href="/getting-started/install" className="hover:text-slate-ink">
          Install
        </Link>
        <Link href="/concepts/offset-policy" className="hover:text-slate-ink">
          Concepts
        </Link>
        <Link href="/cli/scan" className="hover:text-slate-ink">
          CLI
        </Link>
        <Link href="/dashboard/overview" className="hover:text-slate-ink">
          Dashboard
        </Link>
        <a
          href="https://github.com/Tmauc/packguard"
          className="hover:text-slate-ink"
          rel="noopener noreferrer"
        >
          GitHub
        </a>
      </div>
    </nav>
  )
}

function Hero() {
  return (
    <section className="mx-auto grid max-w-6xl grid-cols-1 gap-10 px-6 py-16 lg:grid-cols-[1.05fr_1fr] lg:items-center lg:py-24">
      <div>
        <div className="inline-flex items-center gap-2 rounded-full border border-divider bg-white/60 px-3 py-1 text-xs font-medium text-mute">
          <span
            aria-hidden
            className="inline-block h-1.5 w-1.5 rounded-full bg-shield-green"
          />
          v0.1.0 · MIT / Apache-2.0 · npm + PyPI
        </div>
        <h1 className="mt-6 text-[44px] font-semibold leading-[1.05] tracking-tight text-slate-ink lg:text-[56px]">
          Stop trusting dependencies
          <br />
          you never audited.
        </h1>
        <p className="mt-6 max-w-xl text-[17px] leading-relaxed text-mute">
          PackGuard is a local-first CLI and dashboard that governs package
          versions across every repo you own. Offset policy, supply-chain intel
          (CVE · malware · typosquat), and a live dependency graph — one Rust
          binary, no cloud.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <Link
            href="/getting-started/install"
            className="inline-flex items-center gap-2 rounded-lg bg-slate-ink px-5 py-3 text-sm font-medium text-warm-white hover:bg-slate-ink/90"
          >
            Install PackGuard
            <span aria-hidden>→</span>
          </Link>
          <a
            href="https://github.com/Tmauc/packguard"
            className="inline-flex items-center gap-2 rounded-lg border border-divider-strong px-5 py-3 text-sm font-medium text-slate-ink hover:border-slate-ink/40"
          >
            View on GitHub
          </a>
        </div>
        <p className="mt-5 text-xs text-mute">
          Works with npm (npm · pnpm · yarn) and PyPI (poetry · uv · pip).
          Cargo + Go modules next.
        </p>
      </div>

      <div className="relative h-[340px] w-full overflow-hidden rounded-2xl border border-divider bg-gradient-to-br from-white to-shield-green-soft/60 lg:h-[440px]">
        <Hero3D />
        <div className="pointer-events-none absolute bottom-3 left-4 right-4 flex items-center justify-between text-[11px] uppercase tracking-wider text-mute">
          <span className="inline-flex items-center gap-1.5">
            <span
              aria-hidden
              className="inline-block h-1.5 w-1.5 rounded-full bg-ember-red"
            />
            CVE contamination chain
          </span>
          <span>48 deps · 47 edges · 1 chain</span>
        </div>
      </div>
    </section>
  )
}

function ValueProps() {
  return (
    <section className="mx-auto max-w-6xl px-6 pb-16 lg:pb-24">
      <div className="grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-4">
        {VALUE_PROPS.map((v) => (
          <div
            key={v.title}
            className="rounded-xl border border-divider bg-white/60 p-5"
          >
            <h3 className="text-[15px] font-semibold tracking-tight text-slate-ink">
              {v.title}
            </h3>
            <p className="mt-2 text-[14px] leading-relaxed text-mute">{v.body}</p>
          </div>
        ))}
      </div>
    </section>
  )
}

function Features() {
  return (
    <section className="border-t border-divider bg-white/40 py-20">
      <div className="mx-auto max-w-6xl px-6">
        <div className="max-w-2xl">
          <h2 className="text-3xl font-semibold tracking-tight text-slate-ink">
            One binary. One dashboard. Every workspace.
          </h2>
          <p className="mt-4 text-[16px] leading-relaxed text-mute">
            PackGuard ships a single Rust binary that embeds the dashboard, the
            REST API, and every CLI command. Run `packguard ui` locally and the
            UI opens in your browser against the same SQLite store the CLI
            writes to.
          </p>
        </div>

        <div className="mt-12 grid grid-cols-1 gap-16">
          {FEATURE_ROWS.map((f, i) => (
            <div
              key={f.title}
              className="grid grid-cols-1 items-center gap-10 lg:grid-cols-2"
            >
              <div className={i % 2 === 1 ? 'lg:order-2' : ''}>
                <h3 className="text-2xl font-semibold tracking-tight text-slate-ink">
                  {f.title}
                </h3>
                <p className="mt-3 text-[15px] leading-relaxed text-mute">{f.body}</p>
              </div>
              <div
                className={`overflow-hidden rounded-xl border border-divider bg-white shadow-sm ${
                  i % 2 === 1 ? 'lg:order-1' : ''
                }`}
              >
                <Image
                  src={f.image}
                  alt={f.alt}
                  width={1440}
                  height={900}
                  className="h-auto w-full"
                  priority={i === 0}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

function InstallCTA() {
  return (
    <section className="mx-auto max-w-6xl px-6 py-20">
      <h2 className="text-3xl font-semibold tracking-tight text-slate-ink">
        Install in 30 seconds.
      </h2>
      <p className="mt-3 max-w-xl text-[15px] leading-relaxed text-mute">
        Four channels, one binary. Pick whichever you already have.
      </p>

      <div className="mt-8 grid grid-cols-1 gap-3 md:grid-cols-2">
        <pre className="overflow-x-auto rounded-lg border border-divider bg-slate-ink px-5 py-4 text-[13px] leading-relaxed text-warm-white">
          <span className="text-mute"># Homebrew</span>
          {'\n'}brew tap Tmauc/packguard
          {'\n'}brew install packguard
        </pre>
        <pre className="overflow-x-auto rounded-lg border border-divider bg-slate-ink px-5 py-4 text-[13px] leading-relaxed text-warm-white">
          <span className="text-mute"># install.sh (SHA256-verified)</span>
          {'\n'}curl -fsSL https://raw.githubusercontent.com/Tmauc/packguard/main/install.sh | sh
        </pre>
        <pre className="overflow-x-auto rounded-lg border border-divider bg-slate-ink px-5 py-4 text-[13px] leading-relaxed text-warm-white">
          <span className="text-mute"># Docker (~46 MB, multi-arch)</span>
          {'\n'}docker run --rm -v "$PWD":/workspace \\
          {'\n'}  ghcr.io/tmauc/packguard:latest scan /workspace
        </pre>
        <pre className="overflow-x-auto rounded-lg border border-divider bg-slate-ink px-5 py-4 text-[13px] leading-relaxed text-warm-white">
          <span className="text-mute"># Cargo (from source)</span>
          {'\n'}cargo install packguard-cli --features ui-embed
        </pre>
      </div>

      <div className="mt-8">
        <Link
          href="/getting-started/install"
          className="inline-flex items-center gap-2 text-sm font-medium text-shield-green hover:underline"
        >
          Read the full install guide
          <span aria-hidden>→</span>
        </Link>
      </div>
    </section>
  )
}

function LandingFooter() {
  return (
    <footer className="border-t border-divider">
      <div className="mx-auto flex max-w-6xl flex-col gap-4 px-6 py-8 text-sm text-mute md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-2.5">
          <BrandMark />
          <span className="text-divider-strong">/</span>
          <span>v0.1.0</span>
        </div>
        <div className="flex items-center gap-5">
          <Link href="/getting-started/install" className="hover:text-slate-ink">
            Docs
          </Link>
          <a
            href="https://github.com/Tmauc/packguard"
            className="hover:text-slate-ink"
          >
            GitHub
          </a>
          <a
            href="https://crates.io/crates/packguard-cli"
            className="hover:text-slate-ink"
          >
            crates.io
          </a>
          <a href="/llms.txt" className="hover:text-slate-ink">
            llms.txt
          </a>
        </div>
      </div>
    </footer>
  )
}

export default function Landing() {
  return (
    <main className="min-h-screen">
      <TopNav />
      <Hero />
      <ValueProps />
      <Features />
      <InstallCTA />
      <LandingFooter />
    </main>
  )
}
