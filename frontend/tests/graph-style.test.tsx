import { cleanup, render } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
const create = vi.hoisted(() => vi.fn((_options?: unknown) => ({ on: vi.fn(), destroy: vi.fn(), nodes: () => ({ unselect: vi.fn() }) })))
vi.mock('cytoscape', () => ({ default: create }))
import { GraphCanvas } from '../src/main'
afterEach(cleanup)
it('uses legible dark labels on the pale plotting plane', () => {
  render(<GraphCanvas graph={null} selected={null} onSelect={() => undefined} />)
  const options = create.mock.calls[0][0] as unknown as { style: { selector: string; style: Record<string, unknown> }[] }
  expect(options.style.find(item => item.selector === 'node')?.style.color).toBe('#24333F')
})
