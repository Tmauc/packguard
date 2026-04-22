import { Footer, Layout, Navbar } from 'nextra-theme-docs'
import { getPageMap } from 'nextra/page-map'
import Link from 'next/link'

function BrandMark() {
  return (
    <Link href="/" className="flex items-center gap-2.5">
      <svg
        width="22"
        height="22"
        viewBox="0 0 32 32"
        aria-hidden
        className="flex-shrink-0"
      >
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
      <span className="font-semibold tracking-tight text-[15px]">PackGuard</span>
    </Link>
  )
}

export default async function DocsLayout({ children }: { children: React.ReactNode }) {
  const pageMap = await getPageMap()
  return (
    <Layout
      nextThemes={{ forcedTheme: 'light', defaultTheme: 'light' }}
      navbar={<Navbar logo={<BrandMark />} projectLink="https://github.com/Tmauc/packguard" />}
      footer={
        <Footer>
          <div className="flex w-full flex-col gap-2 text-sm text-mute md:flex-row md:items-center md:justify-between">
            <span>
              PackGuard · Dual-licensed MIT / Apache-2.0 · Built by{' '}
              <a
                className="underline decoration-divider underline-offset-4 hover:text-slate-ink"
                href="https://github.com/Tmauc"
              >
                Tmauc
              </a>
            </span>
            <div className="flex items-center gap-4">
              <a
                className="underline decoration-divider underline-offset-4 hover:text-slate-ink"
                href="https://github.com/Tmauc/packguard"
              >
                GitHub
              </a>
              <a
                className="underline decoration-divider underline-offset-4 hover:text-slate-ink"
                href="https://crates.io/crates/packguard-cli"
              >
                crates.io
              </a>
              <a
                className="underline decoration-divider underline-offset-4 hover:text-slate-ink"
                href="/llms.txt"
              >
                llms.txt
              </a>
            </div>
          </div>
        </Footer>
      }
      pageMap={pageMap}
      docsRepositoryBase="https://github.com/Tmauc/packguard/tree/main/docs-site"
      sidebar={{ defaultMenuCollapseLevel: 1, toggleButton: false }}
      editLink=""
      feedback={{ content: null }}
    >
      {children}
    </Layout>
  )
}
