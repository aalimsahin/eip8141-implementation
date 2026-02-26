import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'EIP-8141 Showcase',
  description: 'Frame Transaction Playground - Custom Signature Schemes for Ethereum',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-gray-950 text-gray-100 min-h-screen">
        <nav className="border-b border-gray-800 px-6 py-4">
          <div className="max-w-6xl mx-auto flex items-center justify-between">
            <a href="/" className="text-xl font-bold text-white">
              EIP-8141 <span className="text-blue-400">Showcase</span>
            </a>
            <div className="flex gap-6 text-sm">
              <a href="/" className="text-gray-400 hover:text-white transition">Home</a>
              <a href="/playground" className="text-gray-400 hover:text-white transition">Playground</a>
              <a href="/explorer" className="text-gray-400 hover:text-white transition">Explorer</a>
            </div>
          </div>
        </nav>
        <main className="max-w-6xl mx-auto px-6 py-8">
          {children}
        </main>
      </body>
    </html>
  )
}
