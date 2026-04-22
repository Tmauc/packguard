'use client'

import { useFrame } from '@react-three/fiber'
import { Line } from '@react-three/drei'
import { useMemo, useRef } from 'react'
import type { Group } from 'three'
import { buildGraph, type Graph } from './graph-data'

const EMBER = '#C4442B'
const EDGE_IDLE = '#c9c2b0'

function ChainEdge({
  from,
  to,
  pulseRef,
}: {
  from: [number, number, number]
  to: [number, number, number]
  pulseRef: React.MutableRefObject<number>
}) {
  const lineRef = useRef<{
    material: { opacity: number; color: { set: (hex: string) => void } }
  } | null>(null)

  useFrame(() => {
    if (!lineRef.current) return
    lineRef.current.material.opacity = 0.55 + pulseRef.current * 0.45
  })

  return (
    <Line
      // @ts-expect-error drei Line runtime ref shape is looser than its types
      ref={lineRef}
      points={[from, to]}
      color={EMBER}
      lineWidth={2.2}
      transparent
    />
  )
}

function IdleEdge({
  from,
  to,
}: {
  from: [number, number, number]
  to: [number, number, number]
}) {
  return (
    <Line points={[from, to]} color={EDGE_IDLE} lineWidth={1} transparent opacity={0.5} />
  )
}

export default function Hero3DScene({ reducedMotion }: { reducedMotion: boolean }) {
  const group = useRef<Group>(null)
  const graph = useMemo<Graph>(() => buildGraph(48, 17), [])
  const pulseRef = useRef(reducedMotion ? 1 : 0)

  useFrame((state, delta) => {
    if (!group.current) return
    if (!reducedMotion) {
      group.current.rotation.y += delta * 0.07
      group.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.1) * 0.08
      const t = state.clock.elapsedTime
      pulseRef.current = (Math.sin(t * 0.9) + 1) / 2
    }
  })

  return (
    <group ref={group}>
      {graph.edges.map(([a, b], i) => {
        const key = `${a}-${b}`
        const isChain = graph.chainEdgeKeys.has(key)
        const from = graph.nodes[a].pos
        const to = graph.nodes[b].pos
        return isChain ? (
          <ChainEdge key={i} from={from} to={to} pulseRef={pulseRef} />
        ) : (
          <IdleEdge key={i} from={from} to={to} />
        )
      })}

      {graph.nodes.map((n) => {
        const isChain = graph.chainNodeIds.has(n.id) && n.id !== 0
        return (
          <mesh key={n.id} position={n.pos}>
            <sphereGeometry args={[n.size, 16, 16]} />
            <meshBasicMaterial color={isChain ? EMBER : n.color} />
          </mesh>
        )
      })}
    </group>
  )
}
