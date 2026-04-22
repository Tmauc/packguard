function humanizeAge(isoDate: string, now: Date): { label: string; days: number } {
  const scanned = new Date(isoDate)
  const diffMs = now.getTime() - scanned.getTime()
  const days = Math.floor(diffMs / (1000 * 60 * 60 * 24))
  if (days <= 0) return { label: 'today', days: 0 }
  if (days === 1) return { label: 'yesterday', days: 1 }
  if (days < 14) return { label: `${days} days ago`, days }
  if (days < 60) return { label: `${Math.floor(days / 7)} weeks ago`, days }
  return { label: `${Math.floor(days / 30)} months ago`, days }
}

export function FreshnessBadge({
  scannedAt,
  packguardVersion,
}: {
  scannedAt: string
  packguardVersion: string
}) {
  const now = new Date()
  const { label, days } = humanizeAge(scannedAt, now)
  const stale = days > 14
  const scanned = new Date(scannedAt)

  return (
    <div
      className={`inline-flex items-center gap-3 rounded-full border px-3.5 py-1.5 text-[12px] ${
        stale
          ? 'border-ember-red/40 bg-ember-red-soft/60 text-ember-red'
          : 'border-divider bg-white/70 text-mute'
      }`}
    >
      <span aria-hidden className="flex items-center gap-1.5">
        <span
          className={`inline-block h-1.5 w-1.5 rounded-full ${
            stale ? 'bg-ember-red' : 'bg-shield-green'
          }`}
        />
      </span>
      <span>
        Scanned{' '}
        <time dateTime={scannedAt} title={scanned.toUTCString()}>
          {label}
        </time>
      </span>
      <span aria-hidden className="h-3 w-px bg-current opacity-30" />
      <span className="font-mono text-[11px] uppercase tracking-wider">
        packguard v{packguardVersion}
      </span>
      {stale ? (
        <>
          <span aria-hidden className="h-3 w-px bg-current opacity-30" />
          <span className="font-mono text-[11px] uppercase tracking-wider">stale</span>
        </>
      ) : null}
    </div>
  )
}
