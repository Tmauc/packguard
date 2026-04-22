'use client'

import { Canvas, useFrame } from '@react-three/fiber'
import { Line } from '@react-three/drei'
import dynamic from 'next/dynamic'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { Group } from 'three'
import type { GraphNode, GraphEdge } from '@/types/snapshot'

const ECO_COLORS: Record<string, string> = {
  npm: '#2E6BD4',
  pypi: '#2F855A',
}
const ROOT_COLOR = '#0F1419'
const ALERT_COLOR = '#C4442B'

function hashToUnit(s: string, salt = 0): number {
  let h = 2166136261 ^ salt
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return ((h >>> 0) % 1_000_000) / 1_000_000
}

function nodePosition(node: GraphNode): [number, number, number] {
  if (node.is_root) return [0, 0.2, 0.3]
  const u = hashToUnit(node.id, 17)
  const v = hashToUnit(node.id, 53)
  const w = hashToUnit(node.id, 97)
  const r = 2.0 + u * 2.0
  const theta = v * Math.PI * 2
  const phi = Math.acos(2 * w - 1)
  const x = r * Math.sin(phi) * Math.cos(theta)
  const y = r * Math.sin(phi) * Math.sin(theta) * 0.55
  const z = r * Math.cos(phi) * 0.75
  return [x, y, z]
}

function nodeColor(n: GraphNode): string {
  if (n.is_root) return ROOT_COLOR
  if (n.cve_severity || n.has_malware) return ALERT_COLOR
  if (n.has_typosquat) return '#B04289'
  return ECO_COLORS[n.ecosystem] ?? '#5A6472'
}

function nodeSize(n: GraphNode): number {
  if (n.is_root) return 0.28
  if (n.cve_severity || n.has_malware) return 0.17
  return 0.11
}

function GraphScene({
  nodes,
  edges,
  reducedMotion,
}: {
  nodes: GraphNode[]
  edges: GraphEdge[]
  reducedMotion: boolean
}) {
  const group = useRef<Group>(null)
  const positions = useMemo(() => {
    const m = new Map<string, [number, number, number]>()
    for (const n of nodes) m.set(n.id, nodePosition(n))
    return m
  }, [nodes])

  useFrame((state, delta) => {
    if (!group.current || reducedMotion) return
    group.current.rotation.y += delta * 0.06
    group.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.08) * 0.07
  })

  return (
    <group ref={group}>
      {edges.map((e, i) => {
        const from = positions.get(e.source)
        const to = positions.get(e.target)
        if (!from || !to) return null
        return (
          <Line
            key={i}
            points={[from, to]}
            color="#c9c2b0"
            lineWidth={1}
            transparent
            opacity={0.45}
          />
        )
      })}
      {nodes.map((n) => (
        <mesh key={n.id} position={positions.get(n.id)!}>
          <sphereGeometry args={[nodeSize(n), 14, 14]} />
          <meshBasicMaterial color={nodeColor(n)} />
        </mesh>
      ))}
    </group>
  )
}

const GraphSceneClient = dynamic(() => Promise.resolve(GraphScene), { ssr: false })

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReduced(mq.matches)
    const h = (e: MediaQueryListEvent) => setReduced(e.matches)
    mq.addEventListener('change', h)
    return () => mq.removeEventListener('change', h)
  }, [])
  return reduced
}

export function MiniDepGraph({
  nodes,
  edges,
}: {
  nodes: GraphNode[]
  edges: GraphEdge[]
}) {
  const reducedMotion = usePrefersReducedMotion()
  return (
    <Canvas
      camera={{ position: [0, 0, 6.5], fov: 42 }}
      gl={{ antialias: true, alpha: true, powerPreference: 'low-power' }}
      dpr={[1, 2]}
      frameloop={reducedMotion ? 'demand' : 'always'}
      style={{ background: 'transparent' }}
    >
      <GraphSceneClient nodes={nodes} edges={edges} reducedMotion={reducedMotion} />
    </Canvas>
  )
}
