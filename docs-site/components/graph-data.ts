export type GraphNode = {
  id: number
  pos: [number, number, number]
  color: string
  size: number
}

export type GraphEdge = [number, number]

export type Graph = {
  nodes: GraphNode[]
  edges: GraphEdge[]
  chainNodeIds: Set<number>
  chainEdgeKeys: Set<string>
}

function seededRandom(seed: number) {
  let s = seed | 0
  return () => {
    s = (s * 1103515245 + 12345) | 0
    return ((s >>> 0) % 1_000_000) / 1_000_000
  }
}

const COLOR_ROOT = '#0F1419'
const ECO_PALETTE = ['#2E6BD4', '#2F855A', '#7C4DCC', '#B04289']

export function buildGraph(nodeCount = 48, seed = 17): Graph {
  const rand = seededRandom(seed)
  const nodes: GraphNode[] = []

  nodes.push({ id: 0, pos: [0, 0.3, 0.4], color: COLOR_ROOT, size: 0.3 })

  for (let i = 1; i < nodeCount; i++) {
    const r = 1.8 + rand() * 2.2
    const theta = rand() * Math.PI * 2
    const phi = Math.acos(2 * rand() - 1)
    const x = r * Math.sin(phi) * Math.cos(theta)
    const y = r * Math.sin(phi) * Math.sin(theta) * 0.55
    const z = r * Math.cos(phi) * 0.8
    const color = ECO_PALETTE[Math.floor(rand() * ECO_PALETTE.length)]
    nodes.push({
      id: i,
      pos: [x, y, z],
      color,
      size: 0.08 + rand() * 0.07,
    })
  }

  const edges: GraphEdge[] = []
  for (let i = 1; i < nodes.length; i++) {
    let best = 0
    let bestDist = Infinity
    for (let j = 0; j < i; j++) {
      const dx = nodes[i].pos[0] - nodes[j].pos[0]
      const dy = nodes[i].pos[1] - nodes[j].pos[1]
      const dz = nodes[i].pos[2] - nodes[j].pos[2]
      const d = dx * dx + dy * dy + dz * dz
      if (d < bestDist) {
        bestDist = d
        best = j
      }
    }
    edges.push([best, i])
  }

  const chain: GraphEdge[] = []
  let cur = 0
  for (let step = 0; step < 5; step++) {
    const children = edges.filter(([a]) => a === cur).map(([, b]) => b)
    if (children.length === 0) break
    const next = children[Math.floor(rand() * children.length)]
    chain.push([cur, next])
    cur = next
  }

  const chainEdgeKeys = new Set(chain.map(([a, b]) => `${a}-${b}`))
  const chainNodeIds = new Set<number>()
  chain.forEach(([a, b]) => {
    chainNodeIds.add(a)
    chainNodeIds.add(b)
  })

  return { nodes, edges, chainNodeIds, chainEdgeKeys }
}
