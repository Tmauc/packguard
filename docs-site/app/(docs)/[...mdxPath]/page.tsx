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

// Catch-all receives every unmatched URL — Chrome DevTools probing
// /.well-known/*, scanners, typos. Nextra's importPage throws
// 'MODULE_NOT_FOUND' for unknown paths; translate that into a clean
// 404 instead of leaking a stacktrace.
async function safeImportPage(mdxPath: string[]) {
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
