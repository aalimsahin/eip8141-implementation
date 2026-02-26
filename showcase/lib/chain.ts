/**
 * viem chain definition for the EIP-8141 devnet.
 */

import { defineChain } from "viem";

export const eip8141Devnet = defineChain({
  id: 8141,
  name: "EIP-8141 Devnet",
  nativeCurrency: {
    name: "Ether",
    symbol: "ETH",
    decimals: 18,
  },
  rpcUrls: {
    default: {
      http: [
        process.env.NEXT_PUBLIC_RPC_URL || "http://localhost:8545",
      ],
      webSocket: [
        process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8546",
      ],
    },
  },
  blockExplorers: {
    default: {
      name: "Frame Explorer",
      url: "http://localhost:3000/explorer",
    },
  },
  testnet: true,
});
