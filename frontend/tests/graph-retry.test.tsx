import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { useState } from 'react'
import type { Core, CytoscapeOptions } from 'cytoscape'
import type { Graph } from '../src/api'

const runtime = vi.hoisted(() => ({ failNext: false, instances: [] as Core[] }))
vi.mock('cytoscape', async importOriginal => {
  const actual = await importOriginal<{ default: typeof import('cytoscape') }>()
  return { default: (options: CytoscapeOptions) => {
    if (runtime.failNext) { runtime.failNext = false; throw new Error('Synthetic initialization failure') }
    const instance = actual.default(options)
    runtime.instances.push(instance)
    return instance
  } }
})
import { GraphCanvas } from '../src/features/Map'

const graph: Graph = { nodes: [{ id: 'asset-1', label: 'Synthetic host', kind: 'host', track: 'network' }, { id: 'asset-2', label: 'Synthetic service', kind: 'service', track: 'network' }], edges: [{ id: 'edge-1', source: 'asset-1', target: 'asset-2', label: 'hosts', source_artifact: 'synthetic-source' }], total_nodes: 2, total_edges: 1 }
afterEach(() => { cleanup(); runtime.instances = []; runtime.failNext = false })

it('populates the recovered renderer and restores selection when the graph prop is unchanged', () => {
  runtime.failNext = true
  function RetryMap() {
    const [retry, setRetry] = useState(0)
    return <GraphCanvas graph={graph} selected="asset-2" onSelect={() => undefined} retryKey={retry} onRetry={() => setRetry(value => value + 1)} />
  }
  render(<RetryMap />)
  fireEvent.click(screen.getByRole('button', { name: 'Retry relationship map' }))
  expect(screen.queryByText('Relationship map could not initialize.')).not.toBeInTheDocument()
  const recovered = runtime.instances[0]
  expect(recovered.nodes().map(node => node.id())).toEqual(['asset-1', 'asset-2'])
  expect(recovered.edges().map(edge => edge.id())).toEqual(['edge-1'])
  expect(recovered.$(':selected').map(node => node.id())).toEqual(['asset-2'])
})

it('restores the same graph and selection after replacing an existing renderer', () => {
  const { rerender } = render(<GraphCanvas graph={graph} selected="asset-2" onSelect={() => undefined} retryKey={0} />)
  rerender(<GraphCanvas graph={graph} selected="asset-2" onSelect={() => undefined} retryKey={1} />)
  expect(runtime.instances[0].destroyed()).toBe(true)
  const replacement = runtime.instances[1]
  expect(replacement.elements()).toHaveLength(3)
  expect(replacement.$(':selected').map(node => node.id())).toEqual(['asset-2'])
})
