'use client'

import { useState } from 'react'

type SignatureScheme = 'ecdsa' | 'multisig' | 'webauthn'

export default function Playground() {
  const [scheme, setScheme] = useState<SignatureScheme>('ecdsa')
  const [sender, setSender] = useState('')
  const [target, setTarget] = useState('')
  const [calldata, setCalldata] = useState('')
  const [txHash, setTxHash] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setTxHash(null)
    setLoading(true)

    try {
      // TODO: Build and send frame transaction using lib/eip8141.ts
      setError('Transaction sending not yet implemented. Connect to the devnet first.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold mb-2">Transaction Playground</h1>
        <p className="text-gray-400">
          Compose and send EIP-8141 frame transactions to the devnet.
        </p>
      </div>

      {/* Scheme Selection */}
      <div className="flex gap-3">
        {(['ecdsa', 'multisig', 'webauthn'] as const).map((s) => (
          <button
            key={s}
            onClick={() => setScheme(s)}
            className={`px-4 py-2 rounded-lg font-medium transition ${
              scheme === s
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:text-white'
            }`}
          >
            {s === 'ecdsa' ? 'ECDSA' : s === 'multisig' ? 'Multisig' : 'WebAuthn'}
          </button>
        ))}
      </div>

      {/* Transaction Form */}
      <form onSubmit={handleSubmit} className="space-y-4 bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Sender Address</label>
          <input
            type="text"
            value={sender}
            onChange={(e) => setSender(e.target.value)}
            placeholder="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Target Contract</label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="0x..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Calldata (hex)</label>
          <textarea
            value={calldata}
            onChange={(e) => setCalldata(e.target.value)}
            placeholder="0x..."
            rows={3}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
          />
        </div>

        {scheme === 'ecdsa' && (
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Private Key (demo only - never use real keys!)
            </label>
            <input
              type="password"
              placeholder="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
            />
          </div>
        )}

        {scheme === 'multisig' && (
          <div className="text-gray-400 text-sm p-4 bg-gray-800 rounded-lg">
            Multisig mode: Enter multiple private keys (comma-separated) for N-of-M signing.
            <input
              type="text"
              placeholder="0xkey1, 0xkey2, 0xkey3"
              className="w-full mt-2 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
            />
          </div>
        )}

        {scheme === 'webauthn' && (
          <div className="text-gray-400 text-sm p-4 bg-gray-800 rounded-lg">
            WebAuthn mode: Uses your browser&apos;s built-in passkey/biometric authentication.
            <button
              type="button"
              className="mt-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white text-sm transition"
            >
              Register Passkey
            </button>
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 text-white rounded-lg font-medium transition"
        >
          {loading ? 'Sending...' : 'Send Frame Transaction'}
        </button>
      </form>

      {/* Results */}
      {txHash && (
        <div className="bg-green-900/30 border border-green-800 rounded-xl p-4">
          <p className="text-green-400 font-medium">Transaction sent!</p>
          <p className="text-sm text-gray-400 mt-1 font-mono break-all">{txHash}</p>
        </div>
      )}

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-xl p-4">
          <p className="text-red-400 font-medium">Error</p>
          <p className="text-sm text-gray-400 mt-1">{error}</p>
        </div>
      )}

      {/* Frame Transaction Preview */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-3">Transaction Preview</h3>
        <pre className="text-sm text-gray-400 font-mono overflow-x-auto">
{`{
  "type": "0x06",
  "chainId": 8141,
  "nonce": 0,
  "sender": "${sender || '0x...'}",
  "frames": [
    {
      "mode": 1,
      "target": "<verifier-contract>",
      "gasLimit": 100000,
      "data": "<signature-data>"
    },
    {
      "mode": 2,
      "target": "${target || '0x...'}",
      "gasLimit": 200000,
      "data": "${calldata || '0x...'}"
    }
  ],
  "maxFeePerGas": "30000000000",
  "maxPriorityFeePerGas": "1000000000"
}`}
        </pre>
      </div>
    </div>
  )
}
