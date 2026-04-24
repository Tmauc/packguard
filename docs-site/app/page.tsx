import Link from 'next/link'
import Image from 'next/image'
import Hero3D from '@/components/Hero3D'
import { BrandMark, SiteNav } from '@/components/SiteNav'

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
    title: 'From findings to next steps',
    body: 'Every CVE, malware hit, or policy violation becomes a prioritized action with a copyable fix command (pnpm · uv · poetry — auto-detected). Dismiss in the UI, the CI gate respects it.',
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

type SnippetLine = { kind: 'comment' | 'cmd' | 'cont'; text: string }

const INSTALL_SNIPPETS: ReadonlyArray<{
  label: string
  lines: ReadonlyArray<SnippetLine>
}> = [
  {
    label: '~/packguard · homebrew',
    lines: [
      { kind: 'comment', text: '# Homebrew — macOS recommended' },
      { kind: 'cmd', text: 'brew tap Tmauc/packguard' },
      { kind: 'cmd', text: 'brew install packguard' },
    ],
  },
  {
    label: '~/packguard · install.sh',
    lines: [
      { kind: 'comment', text: '# install.sh — SHA256-verified, no sudo' },
      { kind: 'cmd', text: 'curl -fsSL \\' },
      {
        kind: 'cont',
        text: '  https://raw.githubusercontent.com/Tmauc/packguard/main/install.sh \\',
      },
      { kind: 'cont', text: '  | sh' },
    ],
  },
  {
    label: '~/packguard · docker',
    lines: [
      { kind: 'comment', text: '# Docker — ~46 MB, multi-arch' },
      { kind: 'cmd', text: 'docker run --rm \\' },
      { kind: 'cont', text: '  -v "$PWD":/workspace \\' },
      {
        kind: 'cont',
        text: '  ghcr.io/tmauc/packguard:latest scan /workspace',
      },
    ],
  },
  {
    label: '~/packguard · cargo',
    lines: [
      { kind: 'comment', text: '# Cargo — from source, any platform' },
      { kind: 'cmd', text: 'cargo install packguard-cli --features ui-embed' },
    ],
  },
]

// BrandMark + SiteNav moved to components/SiteNav.tsx so /live can reuse them.

function TerminalCard({
  label,
  lines,
}: {
  label: string
  lines: ReadonlyArray<SnippetLine>
}) {
  return (
    <div className="terminal-card">
      <div className="terminal-bar">
        <span aria-hidden className="terminal-dot" />
        <span>{label}</span>
      </div>
      <div className="terminal-body">
        {lines.map((l, i) => {
          if (l.kind === 'comment') {
            return (
              <div key={i} className="comment">
                {l.text}
              </div>
            )
          }
          return (
            <div key={i}>
              {l.kind === 'cmd' ? (
                <>
                  <span aria-hidden className="flag">
                    $
                  </span>{' '}
                </>
              ) : null}
              {l.text}
            </div>
          )
        })}
      </div>
    </div>
  )
}

const HERO_LINE_1 = ['Stop', 'trusting', 'dependencies']
const HERO_LINE_2 = ['you', 'never', 'audited.']

function Hero() {
  return (
    <section className="relative mx-auto max-w-6xl px-6 py-16 lg:py-24">
      <span
        aria-hidden
        className="vertical-label absolute left-2 top-32 hidden lg:block xl:left-[-12px]"
      >
        § 01 — Living dependency graph
      </span>

      <div className="grid grid-cols-1 items-center gap-10 lg:grid-cols-12 lg:gap-8">
        {/* Copy — 7 cols */}
        <div className="lg:col-span-7">
          <div
            className="reveal-block flex items-baseline gap-4"
            style={{ '--delay': '60ms' } as React.CSSProperties}
          >
            <span className="section-numeral">i.</span>
            <span className="micro-caps">what it is</span>
            <span aria-hidden className="h-px flex-1 bg-divider-strong/70 hidden md:block" />
          </div>

          <h1 className="font-editorial mt-5 text-[48px] leading-[1.02] tracking-editorial text-slate-ink lg:text-[88px]">
            {HERO_LINE_1.map((w, i) => (
              <span
                key={`l1-${i}`}
                className="reveal-word"
                style={{ '--i': i } as React.CSSProperties}
              >
                {w}{' '}
              </span>
            ))}
            <br />
            {HERO_LINE_2.map((w, i) => (
              <span
                key={`l2-${i}`}
                className="reveal-word"
                style={{ '--i': i + HERO_LINE_1.length } as React.CSSProperties}
              >
                {w}{' '}
              </span>
            ))}
          </h1>

          <p
            className="reveal-block mt-7 max-w-xl text-[17px] leading-relaxed text-mute"
            style={{ '--delay': '520ms' } as React.CSSProperties}
          >
            PackGuard is a local-first CLI and dashboard that governs package
            versions across every repo you own. Offset policy, supply-chain
            intel
            <span className="font-editorial-roman"> — </span>
            <span className="font-editorial">CVE · malware · typosquat</span>
            <span className="font-editorial-roman"> — </span>
            and a live dependency graph. One Rust binary, no cloud.
          </p>

          <div
            className="reveal-block mt-8 flex flex-wrap items-center gap-3"
            style={{ '--delay': '640ms' } as React.CSSProperties}
          >
            <Link
              href="/getting-started/install"
              className="inline-flex items-center gap-2 rounded-lg bg-slate-ink px-5 py-3 text-sm font-medium text-warm-white transition-colors hover:bg-slate-ink/90"
            >
              Install PackGuard
              <span aria-hidden>→</span>
            </Link>
            <a
              href="https://github.com/Tmauc/packguard"
              className="inline-flex items-center gap-2 rounded-lg border border-divider-strong px-5 py-3 text-sm font-medium text-slate-ink transition-colors hover:border-slate-ink/40"
            >
              View on GitHub
            </a>
          </div>

          <p
            className="reveal-block mt-5 text-xs text-mute"
            style={{ '--delay': '760ms' } as React.CSSProperties}
          >
            Works with npm (npm · pnpm · yarn) and PyPI (poetry · uv · pip).
            Cargo + Go modules next.
          </p>
        </div>

        {/* 3D — 5 cols, overflowing right */}
        <div
          className="reveal-block relative lg:col-span-5 lg:-mr-6 xl:-mr-16"
          style={{ '--delay': '350ms' } as React.CSSProperties}
        >
          <div className="canvas-frame relative h-[340px] w-full overflow-hidden bg-gradient-to-br from-white to-shield-green-soft/50 lg:h-[500px]">
            <Hero3D />
            <div className="pointer-events-none absolute bottom-3 left-4 right-4 flex items-center justify-between text-[10px] uppercase tracking-[0.18em] text-mute">
              <span className="inline-flex items-center gap-1.5">
                <span
                  aria-hidden
                  className="inline-block h-1.5 w-1.5 rounded-full bg-ember-red"
                />
                contamination chain
              </span>
              <span>48 nodes · 47 edges · 1 chain</span>
            </div>
          </div>
          <div className="absolute -bottom-6 right-0 hidden items-center gap-2 text-[10px] uppercase tracking-[0.2em] text-mute lg:flex">
            <span aria-hidden className="h-px w-10 bg-divider-strong" />
            fig. i · dependency graph, 48 nodes
          </div>
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
      <div className="grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-5">
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
      <SiteNav />
      <Hero />
      <ValueProps />
      <Features />
      <InstallCTA />
      <LandingFooter />
    </main>
  )
}
