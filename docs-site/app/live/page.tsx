import type { Metadata } from 'next'
import Link from 'next/link'
import snapshotJson from '@/content/live/snapshot.json'
import type { Snapshot } from '@/types/snapshot'
import { SiteNav } from '@/components/SiteNav'
import { FreshnessBadge } from '@/components/LiveDemo/FreshnessBadge'
import { StatsCards } from '@/components/LiveDemo/StatsCards'
import { TopRisks } from '@/components/LiveDemo/TopRisks'
import { PolicyCard } from '@/components/LiveDemo/PolicyCard'
import { MiniDepGraph } from '@/components/LiveDemo/MiniDepGraph'

const snapshot = snapshotJson as unknown as Snapshot

export const metadata: Metadata = {
  title: 'Live demo — PackGuard auditing itself',
  description:
    'Weekly snapshot of PackGuard running against the docs site that ships its install page. Real CLI output, no fabricated data.',
}

function SectionHeading({
  numeral,
  label,
  title,
  sub,
}: {
  numeral: string
  label: string
  title: string
  sub?: string
}) {
  return (
    <div>
      <div className="flex items-baseline gap-4">
        <span className="section-numeral">{numeral}</span>
        <span className="micro-caps">{label}</span>
        <span aria-hidden className="hidden h-px flex-1 bg-divider-strong/70 md:block" />
      </div>
      <h2 className="font-editorial mt-4 text-[36px] leading-[1.06] tracking-editorial text-slate-ink lg:text-[48px]">
        {title}
      </h2>
      {sub ? (
        <p className="mt-3 max-w-2xl text-[15px] leading-relaxed text-mute">{sub}</p>
      ) : null}
    </div>
  )
}

export default function LivePage() {
  const {
    scanned_at,
    packguard_version,
    target,
    summary,
    audit,
    graph,
  } = snapshot

  const typosquatCount = audit.typosquat.length
  const malwareCount = audit.malware.length
  const cveCount =
    summary.cve_by_severity.critical +
    summary.cve_by_severity.high +
    summary.cve_by_severity.medium +
    summary.cve_by_severity.low

  return (
    <main className="min-h-screen">
      <SiteNav active="live" />

      {/* ---------- hero ---------- */}
      <section className="mx-auto max-w-6xl px-5 py-16 sm:px-6 lg:py-24">
        <div className="flex items-baseline gap-4">
          <span className="section-numeral">i.</span>
          <span className="micro-caps">live</span>
          <span aria-hidden className="hidden h-px flex-1 bg-divider-strong/70 md:block" />
        </div>

        <h1 className="font-editorial mt-5 max-w-4xl text-[44px] leading-[1.02] tracking-editorial text-slate-ink lg:text-[80px]">
          PackGuard, auditing itself.
        </h1>

        <p className="mt-6 max-w-2xl text-[17px] leading-relaxed text-mute">
          Every week a GitHub Action runs{' '}
          <code className="rounded bg-divider px-1.5 py-0.5 text-[0.88em]">
            packguard scan
          </code>{' '}
          against the docs site that ships the install page you just read.
          The output below is real CLI JSON — no screenshots, no fixtures. If
          the scanner surfaces a new CVE or a malware hit on our own stack,
          you read about it here before we do.
        </p>

        <div className="mt-7">
          <FreshnessBadge
            scannedAt={scanned_at}
            packguardVersion={packguard_version}
          />
        </div>
      </section>

      {/* ---------- stats ---------- */}
      <section className="mx-auto max-w-6xl px-5 pb-16 sm:px-6 lg:pb-20">
        <div className="mb-6 flex items-baseline gap-4">
          <span className="section-numeral">ii.</span>
          <span className="micro-caps">headline</span>
          <span aria-hidden className="hidden h-px flex-1 bg-divider-strong/70 md:block" />
        </div>
        <StatsCards snapshot={snapshot} />
        <p className="mt-5 text-xs text-mute">
          Target:{' '}
          <code className="rounded bg-divider px-1.5 py-0.5">
            {target.name}
          </code>{' '}
          · Ecosystems: {target.ecosystems.join(', ')} · Package manager:{' '}
          {target.package_manager} · Total transitive deps: {graph.total_nodes}
          {' '}(edges: {graph.total_edges})
        </p>
      </section>

      {/* ---------- policy + top risks ---------- */}
      <section className="border-t border-divider bg-white/40 py-20">
        <div className="mx-auto max-w-6xl px-5 sm:px-6">
          <SectionHeading
            numeral="iii."
            label="compliance"
            title="Policy and the rows it flags."
            sub="The site's own .packguard.yml sits here. Every risk row below is a package drifting against that policy — not a synthetic fixture."
          />

          <div className="mt-10 grid grid-cols-1 gap-6 lg:grid-cols-[1fr_1.5fr]">
            <PolicyCard snapshot={snapshot} />
            <TopRisks snapshot={snapshot} />
          </div>
        </div>
      </section>

      {/* ---------- supply-chain summary ---------- */}
      <section className="mx-auto max-w-6xl px-5 py-20 sm:px-6">
        <SectionHeading
          numeral="iv."
          label="supply-chain"
          title={
            cveCount === 0 && malwareCount === 0
              ? 'No CVE matches. No malware.'
              : 'Supply-chain signals.'
          }
          sub={
            cveCount === 0 && malwareCount === 0
              ? `One typosquat suspect flagged — ${typosquatCount === 1 ? 'a known false positive' : 'to review manually'}. Real CVE / malware matches would show up here.`
              : `Sourced from OSV dumps, GitHub Advisory Database, OSV-MAL, and the in-binary typosquat heuristic.`
          }
        />

        {audit.typosquat.length > 0 ? (
          <div className="mt-10 rounded-xl border border-divider bg-white/70 p-6">
            <div className="flex items-baseline justify-between">
              <h3 className="font-editorial text-[22px] italic text-slate-ink">
                Typosquat heuristic
              </h3>
              <span className="micro-caps">human review</span>
            </div>
            <ul className="mt-4 divide-y divide-divider/60">
              {audit.typosquat.map((t) => (
                <li
                  key={t.package}
                  className="flex flex-col gap-1 py-3 md:flex-row md:items-baseline md:justify-between"
                >
                  <div className="flex items-baseline gap-2 font-mono text-[13px]">
                    <span className="text-slate-ink">{t.package}</span>
                    <span className="text-mute">
                      resembles {t.evidence.resembles}
                    </span>
                  </div>
                  <div className="text-[12px] text-mute">
                    {t.evidence.reason} · score {t.evidence.score}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </section>

      {/* ---------- graph ---------- */}
      <section className="border-t border-divider bg-white/40 py-20">
        <div className="mx-auto max-w-6xl px-5 sm:px-6">
          <SectionHeading
            numeral="v."
            label="graph"
            title="The dependency tree, slimmed."
            sub={`A procedural view over ${graph.nodes.length} of the ${graph.total_nodes} total transitive dependencies — roots and their first neighbours, plus anything risk-flagged. The full graph lives behind packguard graph.`}
          />

          <div className="canvas-frame relative mt-10 h-[380px] w-full overflow-hidden rounded-xl bg-gradient-to-br from-white to-shield-green-soft/50 lg:h-[480px]">
            <MiniDepGraph nodes={graph.nodes} edges={graph.edges} />
            <div className="pointer-events-none absolute bottom-3 left-4 right-4 flex items-center justify-between text-[10px] uppercase tracking-[0.18em] text-mute">
              <span>live snapshot</span>
              <span>
                {graph.nodes.length} / {graph.total_nodes} nodes · {graph.edges.length}{' '}
                edges rendered
              </span>
            </div>
          </div>
          <div className="mt-6 font-mono text-[12px] text-mute">
            For the full traversal:{' '}
            <code className="rounded bg-divider px-1.5 py-0.5">
              packguard graph docs-site/ --format json
            </code>
          </div>
        </div>
      </section>

      {/* ---------- cta ---------- */}
      <section className="mx-auto max-w-6xl px-5 py-20 sm:px-6">
        <div className="flex flex-col items-start gap-6 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="font-editorial text-[32px] italic leading-tight tracking-editorial text-slate-ink lg:text-[40px]">
              Run it against your own repo.
            </h2>
            <p className="mt-2 max-w-xl text-[14px] text-mute">
              Same CLI that produced this page. Reads your lockfiles, pulls
              OSV + GHSA intel, writes to a local SQLite store. No cloud.
            </p>
          </div>
          <Link
            href="/getting-started/install"
            className="inline-flex flex-shrink-0 items-center gap-2 rounded-lg bg-slate-ink px-5 py-3 text-sm font-medium text-warm-white hover:bg-slate-ink/90"
          >
            Install PackGuard
            <span aria-hidden>→</span>
          </Link>
        </div>
      </section>

      <footer className="border-t border-divider">
        <div className="mx-auto flex max-w-6xl flex-col gap-4 px-5 py-8 text-sm text-mute sm:px-6 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-2.5 font-mono text-[12px]">
            <span>live snapshot</span>
            <span className="text-divider-strong">/</span>
            <span>
              {new Date(scanned_at).toISOString().replace('T', ' ').slice(0, 16)} UTC
            </span>
          </div>
          <div className="flex items-center gap-5">
            <Link href="/" className="hover:text-slate-ink">
              Home
            </Link>
            <Link href="/getting-started/install" className="hover:text-slate-ink">
              Docs
            </Link>
            <a href="https://github.com/Tmauc/packguard" className="hover:text-slate-ink">
              GitHub
            </a>
          </div>
        </div>
      </footer>
    </main>
  )
}
