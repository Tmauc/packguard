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

export async function generateMetadata(props: PageProps) {
  const params = await props.params
  const { metadata } = await importPage(params.mdxPath)
  return metadata
}

const Wrapper = getMDXComponents({}).wrapper

export default async function Page(props: PageProps) {
  const params = await props.params
  const result = await importPage(params.mdxPath)
  const { default: MDXContent, ...rest } = result
  if (Wrapper) {
    // Nextra's Wrapper expects the full EvaluateResult minus `default`.
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
