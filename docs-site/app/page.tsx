import Link from 'next/link'

export default function LandingPlaceholder() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-24">
      <h1 className="text-4xl font-semibold tracking-tight">PackGuard</h1>
      <p className="mt-4 text-mute">Landing scaffold — 3D hero lands in the next commit.</p>
      <Link href="/getting-started/install" className="mt-8 inline-block text-shield-green underline">
        Read the docs →
      </Link>
    </main>
  )
}
