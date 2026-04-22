import type { Snapshot } from '@/types/snapshot'

// Extracted from the committed docs-site/.packguard.yml. Keep in sync
// with that file — if Thomas later changes the policy, edit both.
const POLICY = {
  offset: {
    major: '0',
    minor: '-1',
    patch: '0',
  },
  allow_patch: 'true',
  allow_security_patch: 'true',
  stability: 'stable',
  min_age_days: '7',
  block: {
    cve_severity: '[high, critical]',
    malware: 'true',
    deprecated: 'true',
    yanked: 'true',
    typosquat: 'warn',
  },
}

export function PolicyCard({ snapshot }: { snapshot: Snapshot }) {
  return (
    <div className="rounded-xl border border-divider bg-white/70 p-6">
      <div className="flex items-baseline justify-between">
        <h3 className="font-editorial text-[22px] italic text-slate-ink">
          Effective policy
        </h3>
        <span className="micro-caps">.packguard.yml</span>
      </div>
      <p className="mt-3 text-[13px] leading-relaxed text-mute">
        Conservative defaults, no overrides. The three-axis{' '}
        <code className="rounded bg-divider px-1.5 py-0.5 text-[0.88em]">
          offset: {'{'} major: 0, minor: -1, patch: 0 {'}'}
        </code>{' '}
        says <em>latest major, one minor behind, always grab the latest patch</em>.
        On a stack pinned to Next{' '}
        {snapshot.target.name === 'docs-site' ? '16' : 'latest'} / React 19 /
        Nextra 4, any dep living more than one minor ahead of its target shows
        up as drift. That drift is the signal.
      </p>
      <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-2 font-mono text-[12px]">
        <div className="flex items-baseline justify-between border-b border-divider/60 py-1.5">
          <dt className="text-mute">offset.major</dt>
          <dd className="text-slate-ink">{POLICY.offset.major}</dd>
        </div>
        <div className="flex items-baseline justify-between border-b border-divider/60 py-1.5">
          <dt className="text-mute">offset.minor</dt>
          <dd className="text-slate-ink">{POLICY.offset.minor}</dd>
        </div>
        <div className="flex items-baseline justify-between border-b border-divider/60 py-1.5">
          <dt className="text-mute">offset.patch</dt>
          <dd className="text-slate-ink">{POLICY.offset.patch}</dd>
        </div>
        <div className="flex items-baseline justify-between border-b border-divider/60 py-1.5">
          <dt className="text-mute">stability</dt>
          <dd className="text-slate-ink">{POLICY.stability}</dd>
        </div>
        <div className="flex items-baseline justify-between border-b border-divider/60 py-1.5">
          <dt className="text-mute">allow_patch</dt>
          <dd className="text-slate-ink">{POLICY.allow_patch}</dd>
        </div>
        <div className="flex items-baseline justify-between border-b border-divider/60 py-1.5">
          <dt className="text-mute">min_age_days</dt>
          <dd className="text-slate-ink">{POLICY.min_age_days}</dd>
        </div>
        <div className="flex items-baseline justify-between border-b border-divider/60 py-1.5">
          <dt className="text-mute">block.cve_severity</dt>
          <dd className="text-slate-ink">{POLICY.block.cve_severity}</dd>
        </div>
        <div className="flex items-baseline justify-between border-b border-divider/60 py-1.5">
          <dt className="text-mute">block.malware</dt>
          <dd className="text-slate-ink">{POLICY.block.malware}</dd>
        </div>
        <div className="flex items-baseline justify-between border-b border-divider/60 py-1.5">
          <dt className="text-mute">block.typosquat</dt>
          <dd className="text-slate-ink">{POLICY.block.typosquat}</dd>
        </div>
        <div className="flex items-baseline justify-between border-b border-divider/60 py-1.5">
          <dt className="text-mute">block.yanked</dt>
          <dd className="text-slate-ink">{POLICY.block.yanked}</dd>
        </div>
      </dl>
    </div>
  )
}
