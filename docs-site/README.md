# packguard-docs

Documentation site for [PackGuard](https://github.com/Tmauc/packguard).

Standalone Next.js 16 + Nextra 4 app. Not part of the Cargo workspace, not part of the `dashboard/` pnpm project.

## Develop

```bash
pnpm install
pnpm dev             # http://127.0.0.1:3003
pnpm typecheck
pnpm build && pnpm start
```

## Stack

- Next.js 16.2.4 (App Router, Turbopack)
- Nextra 4.6.1 + `nextra-theme-docs` (light mode only, locked)
- Tailwind CSS v4 (CSS-first `@theme`)
- React Three Fiber 9 + Drei 10 + three 0.184 on the landing
- TypeScript strict

## Structure

```
app/
  layout.tsx                 root shell + fonts + Nextra <Head>
  page.tsx                   custom 3D landing (no Nextra chrome)
  (docs)/[...mdxPath]/
    layout.tsx               wraps Nextra <Layout>
    page.tsx                 catch-all MDX gateway
content/                     MDX pages + _meta.js per folder
components/                  React components (Hero3D, InstallTabs, …)
public/                      static assets, screenshots, og-image
scripts/generate-llms.mjs    prebuild — emits public/llms.txt
```

The landing lives at `app/page.tsx` and does NOT render the Nextra sidebar/navbar. The MDX catch-all lives inside `app/(docs)/` so a dedicated nested layout wraps Nextra's shell around docs content without leaking it onto `/`.

## Deploy

See [`DEPLOY.md`](./DEPLOY.md) for Vercel setup.
