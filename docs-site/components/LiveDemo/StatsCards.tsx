import type { Snapshot } from '@/types/snapshot'

function Card({
  numeral,
  label,
  main,
  detail,
  tone = 'neutral',
}: {
  numeral: string
  label: string
  main: string
  detail: React.ReactNode
  tone?: 'neutral' | 'warning' | 'good' | 'alert'
}) {
  const mainColor =
    tone === 'alert'
      ? 'text-ember-red'
      : tone === 'warning'
        ? 'text-shield-green'
        : tone === 'good'
          ? 'text-shield-green'
          : 'text-slate-ink'
  return (
    <div className="rounded-xl border border-divider bg-white/70 p-5">
      <div className="flex items-baseline justify-between">
        <span className="micro-caps">{label}</span>
        <span className="font-editorial text-sm text-mute">{numeral}</span>
      </div>
      <div
        className={`mt-5 font-editorial text-[44px] leading-none tracking-editorial ${mainColor}`}
      >
        {main}
      </div>
      <div className="mt-3 text-[13px] leading-relaxed text-mute">{detail}</div>
    </div>
  )
}

export function StatsCards({ snapshot }: { snapshot: Snapshot }) {
  const { summary, target } = snapshot
  const s = summary.by_status
  const cve = summary.cve_by_severity

  const nonCompliant =
    s.warning + s.violation + s['cve-violation'] + s.malware + s.typosquat + s.insufficient
  const criticalHigh = cve.critical + cve.high

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card
        numeral="01"
        label="tracked"
        main={String(summary.total_packages)}
        detail={
          <>
            {target.ecosystems.join(' · ')} · {target.package_manager}
          </>
        }
      />
      <Card
        numeral="02"
        label="policy"
        main={`${s.violation + s['cve-violation'] + s.malware}`}
        detail={
          <>
            {s.violation + s['cve-violation'] + s.malware} violation
            {s.violation + s['cve-violation'] + s.malware === 1 ? '' : 's'} ·{' '}
            {s.warning} warnings · {s.insufficient} insufficient
          </>
        }
        tone={s.violation + s['cve-violation'] + s.malware > 0 ? 'alert' : 'good'}
      />
      <Card
        numeral="03"
        label="cves matched"
        main={String(criticalHigh + cve.medium + cve.low)}
        detail={
          <>
            {cve.critical} critical · {cve.high} high · {cve.medium} medium ·{' '}
            {cve.low} low
          </>
        }
        tone={criticalHigh > 0 ? 'alert' : 'good'}
      />
      <Card
        numeral="04"
        label="supply-chain"
        main={String(summary.malware_confirmed + summary.typosquat_suspects)}
        detail={
          <>
            {summary.malware_confirmed} malware ·{' '}
            {summary.typosquat_suspects} typosquat suspect
            {summary.typosquat_suspects === 1 ? '' : 's'}
          </>
        }
        tone={summary.malware_confirmed > 0 ? 'alert' : 'good'}
      />
    </div>
  )
}
