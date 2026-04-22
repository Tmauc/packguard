# Deploying `packguard-docs` to Vercel

Vercel was picked because Next.js 16 + Turbopack is a first-class target there and preview URLs per PR come for free. No serverless functions involved — every route on this site is statically prerendered.

> ⚠ These steps need **your** Vercel account. Claude does not have — and should not have — Vercel credentials.

## First-time setup (once)

1. **Create the Vercel project**

   - Log in at [vercel.com](https://vercel.com).
   - `Add New… → Project` → import from GitHub → select **`Tmauc/packguard`**.
   - When prompted for framework: Vercel auto-detects Next.js. Leave.
   - **Root directory**: set to `docs-site`. This is the critical step — without it Vercel will try to build the Cargo workspace and fail.
   - Build & Output settings — leave as "Use Vercel defaults". With the root directory pinned to `docs-site/`, Vercel will pick up the correct `package.json` and run `pnpm install` + `pnpm build`.
   - Node version: 20.x (default is fine — `"engines": { "node": ">=20.9" }` is honoured).

2. **Deploy**

   Hit **Deploy**. First build takes ~2 min; subsequent preview builds are ~40 s (cached `node_modules` + Next cache).

3. **Confirm the preview**

   Open the generated `packguard-docs-<hash>.vercel.app` URL. Verify:
   - Landing loads with the 3D hero rotating.
   - `/getting-started/install` shows Nextra chrome + sidebar.
   - Footer links to `/llms.txt` open a real index (not a 404).

4. **Pick a canonical domain**

   - For now the briefing says `packguard-docs.vercel.app` is enough. That's Vercel's default production URL — no extra configuration needed.
   - If you want a custom domain later (e.g. `docs.packguard.dev`), `Project Settings → Domains → Add`. Vercel handles the TLS cert.

## Per-PR preview URLs

Already wired as soon as the project exists:

- Every PR opened against `main` gets a unique preview URL auto-posted as a comment by the Vercel GitHub app.
- Merging to `main` promotes the preview to production.
- No GitHub Actions changes needed — Vercel's own GitHub app handles the trigger.

## Environment variables

None required as of v0.1.0. The site is 100 % static. If we later add:

- Analytics → `NEXT_PUBLIC_*` for a client-side tracker.
- A search backend → a server-side key.

Those would go in **Project Settings → Environment Variables**. For now, there's nothing to configure.

## Rollback

Vercel keeps every production deployment addressable by its original URL. To roll back:

- **Project → Deployments → pick the last good one → "Promote to Production"**.

That swaps the production alias back in under 10 seconds. No rebuild required.

## Local parity

The Vercel build runs the same commands as local:

```bash
pnpm install
pnpm build      # runs scripts/generate-llms.mjs then next build
```

If `pnpm build` works locally, it will work on Vercel. If a Vercel build fails but your local succeeds, the most common cause is a missing or outdated lockfile — always commit `pnpm-lock.yaml` alongside `package.json` changes.

## When to re-deploy manually

Vercel auto-deploys on push. The only time you'd deploy manually is:

- Using the Vercel CLI from this directory: `vercel --prod` (skip; the GitHub integration already covers production).
- Forcing a rebuild after changing a root-level Vercel setting (env var, domain, …) — Vercel prompts you to redeploy when you do that.

## Troubleshooting

- **Build fails with "no such file or directory: pnpm-lock.yaml"** → root directory is wrong. Should be `docs-site`, not repo root.
- **Build succeeds but `/llms.txt` 404s** → the prebuild script didn't run. Check the build log for `[llms] wrote llms.txt (N pages)`.
- **Hero 3D shows nothing** → the Canvas failed to mount client-side. Open the browser devtools — the Fallback2D should render as SVG if WebGL is absent. If neither shows, inspect the runtime error.
- **Sidebar collapsed on every page** → Nextra's `defaultMenuCollapseLevel` is intentionally `1`. Override in `app/(docs)/[...mdxPath]/layout.tsx` if you want the whole tree open by default.
