export default function Home() {
  return (
    <div className="space-y-12">
      <section className="text-center py-16">
        <h1 className="text-5xl font-bold mb-4">
          EIP-8141: <span className="text-blue-400">Frame Transactions</span>
        </h1>
        <p className="text-xl text-gray-400 max-w-2xl mx-auto">
          A new Ethereum transaction type that replaces ECDSA signatures with
          composable smart contract verification. Build custom authentication
          schemes for your transactions.
        </p>
        <div className="flex gap-4 justify-center mt-8">
          <a
            href="/playground"
            className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition"
          >
            Try the Playground
          </a>
          <a
            href="https://eips.ethereum.org/EIPS/eip-8141"
            target="_blank"
            rel="noopener noreferrer"
            className="px-6 py-3 border border-gray-700 hover:border-gray-500 text-gray-300 rounded-lg font-medium transition"
          >
            Read the EIP
          </a>
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="text-3xl mb-3">🔑</div>
          <h3 className="text-lg font-semibold mb-2">ECDSA Verifier</h3>
          <p className="text-gray-400 text-sm">
            Classic single-owner signature verification. The baseline - works
            just like regular Ethereum transactions but through frame verification.
          </p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="text-3xl mb-3">👥</div>
          <h3 className="text-lg font-semibold mb-2">Multisig Verifier</h3>
          <p className="text-gray-400 text-sm">
            N-of-M threshold signatures. Multiple parties must approve before
            the transaction executes. No separate multisig wallet needed.
          </p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="text-3xl mb-3">🔐</div>
          <h3 className="text-lg font-semibold mb-2">WebAuthn / Passkey</h3>
          <p className="text-gray-400 text-sm">
            Biometric authentication via P-256 signatures. Use your fingerprint
            or Face ID to authorize Ethereum transactions.
          </p>
        </div>
      </section>

      <section className="bg-gray-900 border border-gray-800 rounded-xl p-8">
        <h2 className="text-2xl font-bold mb-4">How Frame Transactions Work</h2>
        <div className="space-y-4 text-gray-400">
          <p>
            A frame transaction (type 0x06) replaces the traditional signature
            with an ordered list of <strong className="text-white">frames</strong> -
            each a mini-execution context with its own gas limit and target contract.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-blue-400 font-mono text-sm mb-1">VERIFY (mode=1)</div>
              <p className="text-sm">
                Runs as STATICCALL. Must call the APPROVE opcode to validate
                the transaction. This replaces ECDSA signature verification.
              </p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-green-400 font-mono text-sm mb-1">SENDER (mode=2)</div>
              <p className="text-sm">
                Executes with tx.sender as the caller. Requires prior sender
                approval from a VERIFY frame.
              </p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-yellow-400 font-mono text-sm mb-1">DEFAULT (mode=0)</div>
              <p className="text-sm">
                Standard call with ENTRY_POINT (0xaa) as caller. Used for
                auxiliary operations.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="text-center py-8">
        <p className="text-gray-500 text-sm">
          Running on Chain ID 8141 | Powered by{' '}
          <a href="https://github.com/paradigmxyz/reth" className="text-blue-400 hover:underline">
            Reth
          </a>
        </p>
      </section>
    </div>
  )
}
