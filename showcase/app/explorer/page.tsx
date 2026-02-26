'use client'

import { useState, useEffect } from 'react'

interface Block {
  number: string
  hash: string
  timestamp: string
  transactions: string[]
  gasUsed: string
}

export default function Explorer() {
  const [blocks, setBlocks] = useState<Block[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchBlocks = async () => {
      try {
        const res = await fetch('http://localhost:8545', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'eth_blockNumber',
            params: [],
            id: 1,
          }),
        })
        const data = await res.json()
        const blockNumber = parseInt(data.result, 16)

        const blockPromises = []
        for (let i = blockNumber; i >= Math.max(0, blockNumber - 9); i--) {
          blockPromises.push(
            fetch('http://localhost:8545', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'eth_getBlockByNumber',
                params: ['0x' + i.toString(16), false],
                id: i + 1,
              }),
            }).then((r) => r.json())
          )
        }

        const results = await Promise.all(blockPromises)
        setBlocks(results.map((r) => r.result).filter(Boolean))
      } catch {
        setError('Cannot connect to devnet at localhost:8545')
      } finally {
        setLoading(false)
      }
    }

    fetchBlocks()
    const interval = setInterval(fetchBlocks, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold mb-2">Block Explorer</h1>
        <p className="text-gray-400">
          View blocks and frame transactions on the EIP-8141 devnet (Chain 8141).
        </p>
      </div>

      {loading && (
        <div className="text-gray-400 text-center py-12">Loading blocks...</div>
      )}

      {error && (
        <div className="bg-yellow-900/30 border border-yellow-800 rounded-xl p-4">
          <p className="text-yellow-400">{error}</p>
          <p className="text-sm text-gray-400 mt-1">
            Make sure the devnet is running: <code className="bg-gray-800 px-2 py-1 rounded">cd devnet && ./run-devnet.sh</code>
          </p>
        </div>
      )}

      {!loading && !error && (
        <div className="space-y-3">
          {blocks.map((block) => (
            <div
              key={block.hash}
              className="bg-gray-900 border border-gray-800 rounded-xl p-4 hover:border-gray-700 transition"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-blue-400 font-mono text-sm">
                  Block #{parseInt(block.number, 16)}
                </span>
                <span className="text-gray-500 text-xs">
                  {new Date(parseInt(block.timestamp, 16) * 1000).toLocaleString()}
                </span>
              </div>
              <div className="text-xs text-gray-500 font-mono truncate mb-2">
                {block.hash}
              </div>
              <div className="flex gap-4 text-xs text-gray-400">
                <span>{block.transactions.length} txs</span>
                <span>Gas: {parseInt(block.gasUsed, 16).toLocaleString()}</span>
              </div>
            </div>
          ))}
          {blocks.length === 0 && (
            <div className="text-gray-500 text-center py-8">
              No blocks found. The devnet may still be starting up.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
