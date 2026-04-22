import Link from 'next/link'

export function BrandMark() {
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

const NAV_ITEMS: Array<{ key: string; label: string; href: string; external?: boolean }> = [
  { key: 'install', label: 'Install', href: '/getting-started/install' },
  { key: 'live', label: 'Live demo', href: '/live' },
  { key: 'concepts', label: 'Concepts', href: '/concepts/offset-policy' },
  { key: 'cli', label: 'CLI', href: '/cli/scan' },
  { key: 'dashboard', label: 'Dashboard', href: '/dashboard/overview' },
  {
    key: 'github',
    label: 'GitHub',
    href: 'https://github.com/Tmauc/packguard',
    external: true,
  },
]

export function SiteNav({ active }: { active?: string }) {
  return (
    <nav className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-5 py-5 sm:px-6">
      <BrandMark />
      <div className="hidden items-center gap-6 text-[14px] text-mute md:flex lg:gap-7">
        {NAV_ITEMS.map((item) => {
          const isActive = active === item.key
          const className = isActive
            ? 'font-medium text-slate-ink'
            : 'hover:text-slate-ink'
          if (item.external) {
            return (
              <a
                key={item.key}
                href={item.href}
                className={className}
                rel="noopener noreferrer"
              >
                {item.label}
              </a>
            )
          }
          return (
            <Link key={item.key} href={item.href} className={className}>
              {item.label}
            </Link>
          )
        })}
      </div>
      <Link
        href={active === 'live' ? '/' : '/live'}
        className="inline-flex items-center gap-1.5 text-[14px] text-mute hover:text-slate-ink md:hidden"
      >
        {active === 'live' ? 'Home' : 'Live demo'}
        <span aria-hidden>→</span>
      </Link>
    </nav>
  )
}
