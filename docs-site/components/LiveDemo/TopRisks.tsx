import type { Snapshot, ReportRow, PolicyStatus } from '@/types/snapshot'

const STATUS_ORDER: PolicyStatus[] = [
  'malware',
  'cve-violation',
  'violation',
  'typosquat',
  'insufficient',
  'warning',
  'compliant',
]

const STATUS_TONE: Record<PolicyStatus, string> = {
  malware: 'bg-[#7c4dcc]/10 text-[#7c4dcc] border-[#7c4dcc]/30',
  'cve-violation': 'bg-ember-red-soft text-ember-red border-ember-red/30',
  violation: 'bg-ember-red-soft text-ember-red border-ember-red/30',
  typosquat: 'bg-[#b04289]/10 text-[#b04289] border-[#b04289]/30',
  insufficient: 'bg-amber-100 text-amber-800 border-amber-300/50',
  warning: 'bg-shield-green-soft text-shield-green border-shield-green/30',
  compliant: 'bg-emerald-50 text-emerald-800 border-emerald-300/50',
}

function StatusPill({ status }: { status: PolicyStatus }) {
  return (
    <span
      className={`inline-flex flex-shrink-0 items-center rounded-full border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider ${STATUS_TONE[status]}`}
    >
      {status}
    </span>
  )
}

function sortRows(rows: ReportRow[]): ReportRow[] {
  const rank = (r: ReportRow) => {
    const i = STATUS_ORDER.indexOf(r.status)
    return i === -1 ? STATUS_ORDER.length : i
  }
  return [...rows].sort(
    (a, b) => rank(a) - rank(b) || a.package.localeCompare(b.package),
  )
}

function MobileRow({ row }: { row: ReportRow }) {
  return (
    <li className="space-y-2 p-4">
      <div className="flex items-start justify-between gap-3">
        <span className="break-all font-mono text-[13px] text-slate-ink">
          {row.package}
        </span>
        <StatusPill status={row.status} />
      </div>
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1 font-mono text-[11px] text-mute">
        <span>{row.ecosystem}</span>
        <span aria-hidden>·</span>
        <span>{row.installed ?? '—'}</span>
        <span aria-hidden>→</span>
        <span>{row.latest ?? '—'}</span>
      </div>
      <p className="text-[12px] leading-snug text-mute">{row.message}</p>
    </li>
  )
}

export function TopRisks({ snapshot }: { snapshot: Snapshot }) {
  const risky = snapshot.report.rows.filter((r) => r.status !== 'compliant')
  const sorted = sortRows(risky).slice(0, 12)

  if (sorted.length === 0) {
    return (
      <div className="rounded-xl border border-divider bg-white/70 p-8 text-center">
        <p className="font-editorial text-2xl italic text-shield-green">
          No risks in the current snapshot.
        </p>
        <p className="mt-2 text-sm text-mute">
          Every tracked package is compliant with the policy — clean run.
        </p>
      </div>
    )
  }

  return (
    <div className="rounded-xl border border-divider bg-white/70">
      {/* Mobile — stacked cards. Hidden on md+. */}
      <ul className="divide-y divide-divider/60 md:hidden">
        {sorted.map((r, i) => (
          <MobileRow key={`m-${r.package}-${i}`} row={r} />
        ))}
      </ul>

      {/* Desktop — real table with visible horizontal scroll if the
          viewport ever gets squeezed below the comfortable minimum. */}
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full min-w-[620px] table-fixed text-[13px]">
          <colgroup>
            <col className="w-[26%]" />
            <col className="w-[9%]" />
            <col className="w-[11%]" />
            <col className="w-[11%]" />
            <col className="w-[13%]" />
            <col className="w-[30%]" />
          </colgroup>
          <thead>
            <tr className="border-b border-divider">
              {['package', 'eco', 'installed', 'latest', 'status', 'note'].map((col) => (
                <th
                  key={col}
                  className="px-3 py-3 text-left font-mono text-[10px] uppercase tracking-[0.14em] text-mute"
                >
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((r, i) => (
              <tr
                key={`${r.package}-${i}`}
                className={`border-b border-divider/60 align-top last:border-b-0 ${
                  i % 2 === 0 ? 'bg-transparent' : 'bg-white/40'
                }`}
              >
                <td className="break-all px-3 py-3 font-mono text-slate-ink">
                  {r.package}
                </td>
                <td className="px-3 py-3 text-mute">{r.ecosystem}</td>
                <td className="px-3 py-3 font-mono text-mute">
                  {r.installed ?? '—'}
                </td>
                <td className="px-3 py-3 font-mono text-mute">
                  {r.latest ?? '—'}
                </td>
                <td className="px-3 py-3">
                  <StatusPill status={r.status} />
                </td>
                <td className="break-words px-3 py-3 text-[12px] leading-snug text-mute">
                  {r.message}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
