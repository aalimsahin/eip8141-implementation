/**
 * EIP-8141 Frame Transaction TypeScript encoder/decoder.
 *
 * Since no existing library (viem, ethers) supports tx type 0x06,
 * this module provides raw RLP encoding for frame transactions.
 */

import { encodeRlp, keccak256, toHex, toBytes, concatBytes } from "viem";
import type { Address, Hex } from "viem";

// ─── Constants ──────────────────────────────────────────────────────────────

export const TX_TYPE_EIP8141 = 0x06;
export const FRAME_TX_INTRINSIC_COST = 15_000n;
export const MAX_FRAMES = 1000;
export const ENTRY_POINT: Address =
  "0x00000000000000000000000000000000000000aa";

// ─── Types ──────────────────────────────────────────────────────────────────

export enum FrameMode {
  DEFAULT = 0,
  VERIFY = 1,
  SENDER = 2,
}

export interface Frame {
  mode: FrameMode;
  target: Address;
  gasLimit: bigint;
  data: Hex;
}

export interface FrameTransaction {
  chainId: bigint;
  nonce: bigint;
  sender: Address;
  frames: Frame[];
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  maxFeePerBlobGas: bigint;
  blobVersionedHashes: Hex[];
}

export interface FrameReceipt {
  success: boolean;
  gasUsed: bigint;
  logs: unknown[];
}

export interface FrameTxReceipt {
  cumulativeGasUsed: bigint;
  payer: Address;
  frameReceipts: FrameReceipt[];
}

// ─── Encoding ───────────────────────────────────────────────────────────────

function bigintToHex(value: bigint): Hex {
  if (value === 0n) return "0x";
  const hex = value.toString(16);
  return `0x${hex.length % 2 ? "0" + hex : hex}` as Hex;
}

function encodeFrame(frame: Frame): readonly [Hex, Hex, Hex, Hex] {
  return [
    bigintToHex(BigInt(frame.mode)),
    frame.target,
    bigintToHex(frame.gasLimit),
    frame.data,
  ] as const;
}

/**
 * Encode a frame transaction to its EIP-2718 serialized form.
 * Result: 0x06 || rlp([chain_id, nonce, sender, frames, ...])
 */
export function encodeFrameTransaction(tx: FrameTransaction): Hex {
  validateFrameTransaction(tx);

  const rlpPayload = encodeRlp([
    bigintToHex(tx.chainId),
    bigintToHex(tx.nonce),
    tx.sender,
    tx.frames.map(encodeFrame),
    bigintToHex(tx.maxPriorityFeePerGas),
    bigintToHex(tx.maxFeePerGas),
    bigintToHex(tx.maxFeePerBlobGas),
    tx.blobVersionedHashes,
  ]);

  // Prepend tx type byte
  const typePrefix = new Uint8Array([TX_TYPE_EIP8141]);
  const rlpBytes = toBytes(rlpPayload);
  const combined = concatBytes([typePrefix, rlpBytes]);
  return toHex(combined);
}

/**
 * Compute the EIP-8141 signature hash.
 *
 * The signature hash is keccak256 of the encoded transaction with all
 * VERIFY frame data fields zeroed out (replaced with empty bytes).
 * This allows the signature to commit to frame targets but not frame data.
 */
export function computeSignatureHash(tx: FrameTransaction): Hex {
  const txForHash: FrameTransaction = {
    ...tx,
    frames: tx.frames.map((f) =>
      f.mode === FrameMode.VERIFY ? { ...f, data: "0x" as Hex } : f
    ),
  };
  const encoded = encodeFrameTransaction(txForHash);
  return keccak256(encoded);
}

/**
 * Compute the total gas limit for a frame transaction.
 */
export function computeTotalGasLimit(tx: FrameTransaction): bigint {
  const frameGas = tx.frames.reduce((sum, f) => sum + f.gasLimit, 0n);
  // Note: calldata cost is computed from RLP-encoded frames, not included here
  return FRAME_TX_INTRINSIC_COST + frameGas;
}

// ─── Validation ─────────────────────────────────────────────────────────────

export function validateFrameTransaction(tx: FrameTransaction): void {
  if (tx.frames.length === 0) {
    throw new Error("Frame transaction must have at least one frame");
  }
  if (tx.frames.length > MAX_FRAMES) {
    throw new Error(`Frame transaction exceeds MAX_FRAMES (${MAX_FRAMES})`);
  }
  for (const frame of tx.frames) {
    if (![0, 1, 2].includes(frame.mode)) {
      throw new Error(`Invalid frame mode: ${frame.mode}`);
    }
    if (frame.gasLimit <= 0n) {
      throw new Error("Frame gas limit must be > 0");
    }
  }
}

// ─── Helpers for building common frame patterns ─────────────────────────────

/**
 * Build a simple ECDSA-verified transaction.
 * Frame 0: VERIFY — calls the verifier contract with the signature
 * Frame 1: SENDER — executes the actual call
 */
export function buildEcdsaFrameTx(params: {
  chainId: bigint;
  nonce: bigint;
  sender: Address;
  verifierAddress: Address;
  signature: Hex;
  target: Address;
  calldata: Hex;
  gasLimitVerify?: bigint;
  gasLimitCall?: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}): FrameTransaction {
  return {
    chainId: params.chainId,
    nonce: params.nonce,
    sender: params.sender,
    frames: [
      {
        mode: FrameMode.VERIFY,
        target: params.verifierAddress,
        gasLimit: params.gasLimitVerify ?? 100_000n,
        data: params.signature,
      },
      {
        mode: FrameMode.SENDER,
        target: params.target,
        gasLimit: params.gasLimitCall ?? 200_000n,
        data: params.calldata,
      },
    ],
    maxPriorityFeePerGas: params.maxPriorityFeePerGas,
    maxFeePerGas: params.maxFeePerGas,
    maxFeePerBlobGas: 0n,
    blobVersionedHashes: [],
  };
}

/**
 * Build a sponsored transaction.
 * Frame 0: VERIFY — user signature verification (APPROVE scope 0x0)
 * Frame 1: VERIFY — sponsor validation + payment (APPROVE scope 0x1)
 * Frame 2: SENDER — user's actual call
 */
export function buildSponsoredFrameTx(params: {
  chainId: bigint;
  nonce: bigint;
  sender: Address;
  userVerifier: Address;
  userSignature: Hex;
  sponsorVerifier: Address;
  sponsorData: Hex;
  target: Address;
  calldata: Hex;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}): FrameTransaction {
  return {
    chainId: params.chainId,
    nonce: params.nonce,
    sender: params.sender,
    frames: [
      {
        mode: FrameMode.VERIFY,
        target: params.userVerifier,
        gasLimit: 100_000n,
        data: params.userSignature,
      },
      {
        mode: FrameMode.VERIFY,
        target: params.sponsorVerifier,
        gasLimit: 100_000n,
        data: params.sponsorData,
      },
      {
        mode: FrameMode.SENDER,
        target: params.target,
        gasLimit: 200_000n,
        data: params.calldata,
      },
    ],
    maxPriorityFeePerGas: params.maxPriorityFeePerGas,
    maxFeePerGas: params.maxFeePerGas,
    maxFeePerBlobGas: 0n,
    blobVersionedHashes: [],
  };
}

/**
 * Send a raw frame transaction to an RPC endpoint.
 */
export async function sendFrameTransaction(
  rpcUrl: string,
  tx: FrameTransaction
): Promise<Hex> {
  const rawTx = encodeFrameTransaction(tx);

  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "eth_sendRawTransaction",
      params: [rawTx],
      id: 1,
    }),
  });

  const { result, error } = await response.json();
  if (error) throw new Error(`RPC error: ${error.message}`);
  return result as Hex;
}
