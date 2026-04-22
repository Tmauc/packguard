import { notFound } from 'next/navigation'
import { generateStaticParamsFor, importPage } from 'nextra/pages'
import { useMDXComponents as getMDXComponents } from '../../../mdx-components'

const baseGenerate = generateStaticParamsFor('mdxPath')

export const generateStaticParams = async () => {
  const params = await baseGenerate()
  return params.filter(
    (p: { mdxPath?: string[] }) => Array.isArray(p.mdxPath) && p.mdxPath.length > 0,
  )
}

type PageProps = {
  params: Promise<{ mdxPath: string[] }>
}

// Pre-compute the allowlist of real MDX paths from content/.
// Nextra logs to stderr from inside importPage when asked for an
// unknown path — wrapping in try/catch doesn't silence that.
// Short-circuit on the allowlist before Nextra sees the request, so
// probes like /.well-known/appspecific/com.chrome.devtools.json return
// 404 without any [nextra] log line.
let VALID_MDX_PATHS: Set<string> | null = null
async function getValidMdxPaths(): Promise<Set<string>> {
  if (VALID_MDX_PATHS) return VALID_MDX_PATHS
  const params = (await baseGenerate()) as Array<{ mdxPath?: string[] }>
  const set = new Set<string>()
  for (const p of params) {
    if (Array.isArray(p.mdxPath) && p.mdxPath.length > 0) {
      set.add(p.mdxPath.join('/'))
    }
  }
  VALID_MDX_PATHS = set
  return set
}

async function safeImportPage(mdxPath: string[] | undefined) {
  if (!Array.isArray(mdxPath) || mdxPath.length === 0) notFound()
  const valid = await getValidMdxPaths()
  if (!valid.has(mdxPath.join('/'))) notFound()
  try {
    return await importPage(mdxPath)
  } catch {
    notFound()
  }
}

export async function generateMetadata(props: PageProps) {
  const params = await props.params
  const result = await safeImportPage(params.mdxPath)
  return result.metadata
}

const Wrapper = getMDXComponents({}).wrapper

export default async function Page(props: PageProps) {
  const params = await props.params
  const result = await safeImportPage(params.mdxPath)
  const { default: MDXContent, ...rest } = result
  if (Wrapper) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const W = Wrapper as any
    return (
      <W {...rest}>
        <MDXContent {...props} params={params} />
      </W>
    )
  }
  return <MDXContent {...props} params={params} />
}
