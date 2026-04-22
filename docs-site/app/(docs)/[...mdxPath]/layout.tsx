import { Footer, Layout, Navbar } from 'nextra-theme-docs'
import { getPageMap } from 'nextra/page-map'
import Link from 'next/link'

export default async function DocsLayout({ children }: { children: React.ReactNode }) {
  const pageMap = await getPageMap()
  return (
    <Layout
      nextThemes={{ forcedTheme: 'light', defaultTheme: 'light' }}
      navbar={
        <Navbar
          logo={
            <Link href="/" className="flex items-center gap-2 text-slate-ink">
              <span
                aria-hidden
                className="inline-block h-5 w-5 rounded-sm"
                style={{ background: 'var(--color-shield-green)' }}
              />
              <span className="font-semibold tracking-tight">PackGuard</span>
            </Link>
          }
          projectLink="https://github.com/Tmauc/packguard"
        />
      }
      footer={
        <Footer>
          <div className="flex w-full items-center justify-between text-sm text-mute">
            <span>
              PackGuard · Dual-licensed MIT / Apache-2.0 · Built by{' '}
              <a
                className="underline decoration-divider underline-offset-4 hover:text-slate-ink"
                href="https://github.com/Tmauc"
              >
                Tmauc
              </a>
            </span>
            <a
              className="underline decoration-divider underline-offset-4 hover:text-slate-ink"
              href="https://github.com/Tmauc/packguard"
            >
              github.com/Tmauc/packguard
            </a>
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
