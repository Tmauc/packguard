import Link from 'next/link'
import Image from 'next/image'
import Hero3D from '@/components/Hero3D'

const VALUE_PROPS = [
  {
    title: 'Offset policy, not lockstep',
    body: 'Enforce "latest - N" with conservative defaults. Rust workspace, npm monorepo, pip-compile — all driven by one .packguard.yml.',
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
    body: 'The graph view runs a BFS from the vulnerable leaf and lights up every contamination chain. Same algorithm as packguard graph --contaminated-by.',
    image: '/screenshots/graph-focus-lodash.png',
    alt: 'Graph view highlighting a contamination chain from a textlint root down to a vulnerable lodash version.',
  },
  {
    title: 'Per-workspace policy',
    body: 'Monorepo-ready: each workspace has its own .packguard.yml with its own offset, stability, and block rules. Edit in the UI or on disk.',
    image: '/screenshots/policies.png',
    alt: 'Policies editor — CodeMirror YAML with dry-run preview vs current policy.',
  },
]

const INSTALL_SNIPPETS = [
  {
    label: '~/packguard · homebrew',
    lines: [
      { kind: 'comment' as const, text: '# Homebrew — macOS recommended' },
      { kind: 'cmd' as const, text: 'brew tap Tmauc/packguard' },
      { kind: 'cmd' as const, text: 'brew install packguard' },
    ],
  },
  {
    label: '~/packguard · install.sh',
    lines: [
      { kind: 'comment' as const, text: '# install.sh — SHA256 verified, no sudo' },
      {
        kind: 'cmd' as const,
        text: 'curl -fsSL https://raw.githubusercontent.com/Tmauc/packguard/main/install.sh | sh',
      },
    ],
  },
  {
    label: '~/packguard · docker',
    lines: [
      { kind: 'comment' as const, text: '# Docker — ~46 MB, multi-arch' },
      { kind: 'cmd' as const, text: 'docker run --rm -v "$PWD":/workspace \\' },
      { kind: 'cmd' as const, text: '  ghcr.io/tmauc/packguard:latest scan /workspace' },
    ],
  },
  {
    label: '~/packguard · cargo',
    lines: [
      { kind: 'comment' as const, text: '# Cargo — from source, any platform' },
      { kind: 'cmd' as const, text: 'cargo install packguard-cli --features ui-embed' },
    ],
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

function TerminalCard({
  label,
  lines,
}: {
  label: string
  lines: ReadonlyArray<{ kind: 'comment' | 'cmd'; text: string }>
}) {
  return (
    <div className="terminal-card">
      <div className="terminal-bar">
        <span aria-hidden className="terminal-dot" />
        <span>{label}</span>
      </div>
      <div className="terminal-body">
        {lines.map((l, i) => (
          <div key={i} className={l.kind === 'comment' ? 'comment' : undefined}>
            {l.kind === 'cmd' ? (
              <span aria-hidden className="flag">$</span>
            ) : null}
            {l.kind === 'cmd' ? ' ' : ''}
            {l.text}
          </div>
        ))}
      </div>
    </div>
  )
}

function Hero() {
  return (
    <section className="mx-auto grid max-w-6xl grid-cols-1 gap-10 px-6 py-16 lg:grid-cols-[1.05fr_1fr] lg:items-center lg:py-24">
      <div>
        <div className="inline-flex items-center gap-2 rounded-full border border-divider bg-white/70 px-3 py-1 text-xs font-medium text-mute">
          <span aria-hidden className="inline-block h-1.5 w-1.5 rounded-full bg-shield-green" />
          v0.1.0 · MIT / Apache-2.0 · npm + PyPI
        </div>
        <h1 className="font-editorial mt-6 text-[48px] leading-[1.02] tracking-editorial text-slate-ink lg:text-[84px]">
          Stop trusting dependencies
          <br />
          you never audited.
        </h1>
        <p className="mt-7 max-w-xl text-[17px] leading-relaxed text-mute">
          PackGuard is a local-first CLI and dashboard that governs package
          versions across every repo you own. Offset policy, supply-chain intel
          <span className="font-editorial-roman"> — </span>
          <span className="font-editorial">CVE · malware · typosquat</span>
          <span className="font-editorial-roman"> — </span>
          and a live dependency graph. One Rust binary, no cloud.
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

      <div className="canvas-frame relative h-[340px] w-full overflow-hidden bg-gradient-to-br from-white to-shield-green-soft/60 lg:h-[460px]">
        <Hero3D />
        <div className="pointer-events-none absolute bottom-3 left-4 right-4 flex items-center justify-between text-[10px] uppercase tracking-[0.18em] text-mute">
          <span className="inline-flex items-center gap-1.5">
            <span aria-hidden className="inline-block h-1.5 w-1.5 rounded-full bg-ember-red" />
            contamination chain
          </span>
          <span>48 nodes · 47 edges · 1 chain</span>
        </div>
      </div>
    </section>
  )
}

function ValueProps() {
  return (
    <section className="mx-auto max-w-6xl px-6 pb-16 lg:pb-24">
      <div className="mb-8 flex items-baseline gap-4">
        <span className="section-numeral">ii.</span>
        <span className="micro-caps">what you get</span>
      </div>
      <div className="grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-4">
        {VALUE_PROPS.map((v, idx) => (
          <div key={v.title} className="rounded-xl border border-divider bg-white/70 p-5">
            <div className="font-editorial text-2xl text-shield-green">
              {String(idx + 1).padStart(2, '0')}
            </div>
            <h3 className="mt-3 text-[15px] font-semibold tracking-tight text-slate-ink">
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
        <div className="mb-8 flex items-baseline gap-4">
          <span className="section-numeral">iii.</span>
          <span className="micro-caps">the dashboard</span>
        </div>
        <div className="max-w-2xl">
          <h2 className="font-editorial text-[40px] leading-[1.05] tracking-editorial text-slate-ink lg:text-[52px]">
            One binary. One dashboard. Every workspace.
          </h2>
          <p className="mt-5 text-[16px] leading-relaxed text-mute">
            PackGuard ships a single Rust binary that embeds the dashboard, the
            REST API, and every CLI command. Run{' '}
            <code className="rounded bg-divider px-1.5 py-0.5 text-[0.88em]">
              packguard ui
            </code>{' '}
            locally and the UI opens in your browser against the same SQLite
            store the CLI writes to.
          </p>
        </div>

        <div className="mt-14 grid grid-cols-1 gap-16">
          {FEATURE_ROWS.map((f, i) => (
            <div
              key={f.title}
              className="grid grid-cols-1 items-center gap-10 lg:grid-cols-2"
            >
              <div className={i % 2 === 1 ? 'lg:order-2' : ''}>
                <div className="font-editorial text-lg text-shield-green">
                  {String(i + 1).padStart(2, '0')}
                </div>
                <h3 className="mt-2 font-editorial text-[30px] leading-[1.1] tracking-editorial text-slate-ink lg:text-[36px]">
                  {f.title}
                </h3>
                <p className="mt-4 text-[15px] leading-relaxed text-mute">{f.body}</p>
              </div>
              <div
                className={`canvas-frame overflow-hidden rounded-xl bg-white ${
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
      <div className="mb-8 flex items-baseline gap-4">
        <span className="section-numeral">iv.</span>
        <span className="micro-caps">30 seconds in</span>
      </div>
      <h2 className="font-editorial text-[40px] leading-[1.05] tracking-editorial text-slate-ink lg:text-[52px]">
        Install in thirty seconds.
      </h2>
      <p className="mt-4 max-w-xl text-[15px] leading-relaxed text-mute">
        Four channels, one binary. Pick whichever you already have on your path.
      </p>

      <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-2">
        {INSTALL_SNIPPETS.map((s) => (
          <TerminalCard key={s.label} label={s.label} lines={s.lines} />
        ))}
      </div>

      <div className="mt-10">
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
          <span className="font-editorial">v0.1.0</span>
        </div>
        <div className="flex items-center gap-5">
          <Link href="/getting-started/install" className="hover:text-slate-ink">
            Docs
          </Link>
          <a href="https://github.com/Tmauc/packguard" className="hover:text-slate-ink">
            GitHub
          </a>
          <a href="https://crates.io/crates/packguard-cli" className="hover:text-slate-ink">
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
