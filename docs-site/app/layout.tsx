import type { Metadata } from 'next'
import { Geist, Geist_Mono, Instrument_Serif } from 'next/font/google'
import { Head } from 'nextra/components'
import 'nextra-theme-docs/style.css'
import './globals.css'

const geist = Geist({ subsets: ['latin'], variable: '--font-geist', display: 'swap' })
const geistMono = Geist_Mono({ subsets: ['latin'], variable: '--font-geist-mono', display: 'swap' })
const editorial = Instrument_Serif({
  subsets: ['latin'],
  weight: '400',
  style: ['normal', 'italic'],
  variable: '--font-editorial',
  display: 'swap',
})

export const metadata: Metadata = {
  title: {
    default: 'PackGuard — Local package version governance',
    template: '%s · PackGuard',
  },
  description:
    'Local, multi-repo, multi-ecosystem package version governance. Offset policy engine, supply-chain intel (CVE / malware / typosquat), dependency graph — one Rust binary, no cloud.',
  metadataBase: new URL('https://packguard-docs.vercel.app'),
  icons: {
    icon: [{ url: '/favicon.svg', type: 'image/svg+xml' }],
  },
  openGraph: {
    title: 'PackGuard',
    description: 'Local package version governance with a native offset policy engine.',
    url: '/',
    siteName: 'PackGuard',
    type: 'website',
    images: [
      {
        url: '/screenshots/overview.png',
        width: 1440,
        height: 900,
        alt: 'PackGuard dashboard Overview',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'PackGuard',
    description: 'Local package version governance with a native offset policy engine.',
    images: ['/screenshots/overview.png'],
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      dir="ltr"
      className={`${geist.variable} ${geistMono.variable} ${editorial.variable}`}
      suppressHydrationWarning
    >
      <Head color={{ hue: 150, saturation: 70, lightness: { dark: 50, light: 32 } }} />
      <body>{children}</body>
    </html>
  )
}
