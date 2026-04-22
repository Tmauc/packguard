'use client'

import { Canvas } from '@react-three/fiber'
import dynamic from 'next/dynamic'
import { useEffect, useMemo, useState } from 'react'
import { buildGraph } from './graph-data'

const Hero3DScene = dynamic(() => import('./Hero3DScene'), { ssr: false })

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReduced(mq.matches)
    const handler = (e: MediaQueryListEvent) => setReduced(e.matches)
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])
  return reduced
}

function hasWebGL() {
  if (typeof window === 'undefined') return true
  try {
    const canvas = document.createElement('canvas')
    return !!(
      window.WebGLRenderingContext &&
      (canvas.getContext('webgl2') || canvas.getContext('webgl'))
    )
  } catch {
    return false
  }
}

function Fallback2D() {
  const graph = useMemo(() => buildGraph(48, 17), [])
  // Project the 3D positions onto 2D by dropping Z and scaling.
  const SCALE = 60
  const OFFSET = 260

  return (
    <svg
      viewBox="0 0 520 440"
      role="img"
      aria-label="Dependency graph with a contamination chain highlighted in ember red"
      className="h-full w-full"
    >
      {graph.edges.map(([a, b], i) => {
        const key = `${a}-${b}`
        const isChain = graph.chainEdgeKeys.has(key)
        const [x1, y1] = graph.nodes[a].pos
        const [x2, y2] = graph.nodes[b].pos
        return (
          <line
            key={i}
            x1={x1 * SCALE + OFFSET}
            y1={y1 * SCALE + OFFSET * 0.85}
            x2={x2 * SCALE + OFFSET}
            y2={y2 * SCALE + OFFSET * 0.85}
            stroke={isChain ? '#C4442B' : '#c9c2b0'}
            strokeWidth={isChain ? 2.2 : 1}
            strokeOpacity={isChain ? 0.85 : 0.55}
          />
        )
      })}
      {graph.nodes.map((n) => {
        const isChain = graph.chainNodeIds.has(n.id) && n.id !== 0
        const [x, y] = n.pos
        return (
          <circle
            key={n.id}
            cx={x * SCALE + OFFSET}
            cy={y * SCALE + OFFSET * 0.85}
            r={n.size * SCALE * 0.35}
            fill={isChain ? '#C4442B' : n.color}
          />
        )
      })}
    </svg>
  )
}

export default function Hero3D() {
  const reducedMotion = usePrefersReducedMotion()
  const [webgl, setWebgl] = useState<boolean | null>(null)
  useEffect(() => {
    setWebgl(hasWebGL())
  }, [])

  if (webgl === false) {
    return <Fallback2D />
  }

  return (
    <Canvas
      camera={{ position: [0, 0, 7.2], fov: 42 }}
      gl={{ antialias: true, alpha: true, powerPreference: 'low-power' }}
      dpr={[1, 2]}
      frameloop={reducedMotion ? 'demand' : 'always'}
      style={{ background: 'transparent' }}
    >
      <Hero3DScene reducedMotion={reducedMotion} />
    </Canvas>
  )
}
