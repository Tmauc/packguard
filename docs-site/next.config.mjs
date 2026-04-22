import nextra from 'nextra'

const withNextra = nextra({
  contentDirBasePath: '/',
  defaultShowCopyCode: true,
  search: {
    codeblocks: false,
  },
})

export default withNextra({
  reactStrictMode: true,
  images: {
    unoptimized: false,
  },
})
