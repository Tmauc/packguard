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
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider ${STATUS_TONE[status]}`}
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
  return [...rows].sort((a, b) => rank(a) - rank(b) || a.package.localeCompare(b.package))
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
    <div className="overflow-hidden rounded-xl border border-divider bg-white/70">
      <table className="w-full text-[13px]">
        <thead>
          <tr className="border-b border-divider">
            {['package', 'ecosystem', 'installed', 'latest', 'status', 'note'].map(
              (col) => (
                <th
                  key={col}
                  className="px-4 py-3 text-left font-mono text-[10px] uppercase tracking-[0.16em] text-mute"
                >
                  {col}
                </th>
              ),
            )}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r, i) => (
            <tr
              key={`${r.package}-${i}`}
              className={`border-b border-divider/60 last:border-b-0 ${
                i % 2 === 0 ? 'bg-transparent' : 'bg-white/40'
              }`}
            >
              <td className="px-4 py-3 font-mono text-slate-ink">{r.package}</td>
              <td className="px-4 py-3 text-mute">{r.ecosystem}</td>
              <td className="px-4 py-3 font-mono text-mute">
                {r.installed ?? '—'}
              </td>
              <td className="px-4 py-3 font-mono text-mute">{r.latest ?? '—'}</td>
              <td className="px-4 py-3">
                <StatusPill status={r.status} />
              </td>
              <td className="px-4 py-3 text-mute">
                <span className="line-clamp-2">{r.message}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
