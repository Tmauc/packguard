#!/usr/bin/env node
// Generate public/llms.txt + public/llms-full.txt from content/**/*.mdx.
// Strips frontmatter, JSX components, and common MDX imports, keeping prose + code.

import { readdir, readFile, writeFile, mkdir } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import matter from 'gray-matter'

const ROOT = resolve(new URL('..', import.meta.url).pathname)
const CONTENT_DIR = join(ROOT, 'content')
const PUBLIC_DIR = join(ROOT, 'public')
const SITE = 'https://packguard-docs.vercel.app'

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) {
      files.push(...(await walk(path)))
    } else if (entry.name.endsWith('.mdx') || entry.name.endsWith('.md')) {
      files.push(path)
    }
  }
  return files.sort()
}

function stripMDX(src) {
  return src
    .replace(/^import\s+.+?from\s+['"][^'"]+['"];?\s*$/gm, '')
    .replace(/^export\s+.+?;?\s*$/gm, '')
    .replace(/<[A-Z][A-Za-z0-9]*[^>]*\/>/g, '')
    .replace(/<([A-Z][A-Za-z0-9]*)[^>]*>[\s\S]*?<\/\1>/g, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

function toUrl(absPath) {
  const rel = relative(CONTENT_DIR, absPath).replace(/\\/g, '/')
  const noExt = rel.replace(/\.mdx?$/, '')
  const slug = noExt.endsWith('/index') ? noExt.slice(0, -'/index'.length) : noExt
  return `${SITE}/${slug}`
}

async function main() {
  if (!existsSync(CONTENT_DIR)) {
    console.log('[llms] content/ missing — skipping')
    return
  }
  await mkdir(PUBLIC_DIR, { recursive: true })
  const files = await walk(CONTENT_DIR)

  const index = ['# PackGuard', '', '> Local, multi-repo, multi-ecosystem package version governance.', '']
  const full = ['# PackGuard — full documentation dump', '']

  for (const file of files) {
    const raw = await readFile(file, 'utf8')
    const { data, content } = matter(raw)
    const body = stripMDX(content)
    const url = toUrl(file)
    const title =
      data.title ||
      (body.match(/^#\s+(.+)$/m)?.[1] ?? relative(CONTENT_DIR, file).replace(/\.mdx?$/, ''))
    index.push(`- [${title}](${url})`)
    full.push(`\n\n---\n\n# ${title}\n\nsource: ${url}\n\n${body}`)
  }

  await writeFile(join(PUBLIC_DIR, 'llms.txt'), index.join('\n') + '\n', 'utf8')
  await writeFile(join(PUBLIC_DIR, 'llms-full.txt'), full.join('\n') + '\n', 'utf8')
  console.log(`[llms] wrote llms.txt (${files.length} pages) + llms-full.txt`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
