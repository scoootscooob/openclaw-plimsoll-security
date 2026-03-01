/**
 * Plimsoll Firewall — lightweight transaction guard engines.
 *
 * Three deterministic engines ported from the Plimsoll Protocol
 * (https://github.com/scoootscooob/plimsoll-protocol):
 *
 *   1. Trajectory Hash   — SHA-256 fingerprint of (tool, target, amount).
 *      Catches hallucination retry loops before the agent drains the wallet.
 *   2. Capital Velocity   — Sliding-window spend-rate limiter.
 *      Catches both rapid-drain AND slow-bleed attacks that stay under
 *      individual per-tx limits.
 *   3. Entropy Guard      — Shannon entropy + regex pattern matching.
 *      Blocks payloads that look like private keys, seed phrases, or
 *      encoded secrets being exfiltrated via tool calls.
 *
 * Zero external dependencies. Deterministic. Fail-closed.
 */

import { createHash } from "node:crypto";

// ─── Types ──────────────────────────────────────────────────────

export type PlimsollConfig = {
  maxVelocityCentsPerWindow: number;
  velocityWindowSeconds: number;
  loopThreshold: number;
  loopWindowSeconds: number;
};

export type Verdict = {
  allowed: boolean;
  blocked: boolean;
  friction: boolean;
  reason: string;
  engine: string;
  code: string;
};

type WindowEntry<T> = T & { ts: number };

const ALLOW: Verdict = {
  allowed: true,
  blocked: false,
  friction: false,
  reason: "",
  engine: "",
  code: "ALLOW",
};

// ─── Per-Session State ──────────────────────────────────────────

type SessionState = {
  trajectoryWindow: WindowEntry<{ hash: string }>[];
  velocityWindow: WindowEntry<{ amount: number }>[];
};

/**
 * State is keyed by sessionKey so that one agent's DeFi activity
 * does not affect another session running in the same gateway process.
 */
const sessions = new Map<string, SessionState>();

/** Max sessions to track before pruning oldest entries. */
const MAX_SESSIONS = 1000;

function getSession(sessionKey: string): SessionState {
  let state = sessions.get(sessionKey);
  if (!state) {
    // Evict oldest session if we've hit the cap
    if (sessions.size >= MAX_SESSIONS) {
      const oldest = sessions.keys().next().value;
      if (oldest !== undefined) sessions.delete(oldest);
    }
    state = { trajectoryWindow: [], velocityWindow: [] };
    sessions.set(sessionKey, state);
  }
  return state;
}

// ─── Engine 1: Trajectory Hash ──────────────────────────────────

function trajectoryHash(toolName: string, params: Record<string, unknown>): string {
  const target = String(params.to ?? params.address ?? params.recipient ?? params.target ?? "");
  const amount = String(params.amount ?? params.value ?? params.quantity ?? "0");
  const canonical = `${toolName}:${target}:${amount}`;
  return createHash("sha256").update(canonical).digest("hex").slice(0, 16);
}

function evaluateTrajectory(
  sessionKey: string,
  toolName: string,
  params: Record<string, unknown>,
  config: PlimsollConfig,
): Verdict {
  const now = Date.now();
  const windowMs = config.loopWindowSeconds * 1000;
  const hash = trajectoryHash(toolName, params);
  const state = getSession(sessionKey);

  // Prune expired entries
  while (state.trajectoryWindow.length > 0 && now - state.trajectoryWindow[0].ts > windowMs) {
    state.trajectoryWindow.shift();
  }

  const dupeCount = state.trajectoryWindow.filter((e) => e.hash === hash).length;
  state.trajectoryWindow.push({ hash, ts: now });

  if (dupeCount >= config.loopThreshold) {
    return {
      allowed: false,
      blocked: true,
      friction: false,
      reason:
        `${dupeCount + 1} identical ${toolName} calls in ${config.loopWindowSeconds}s. ` +
        `Likely hallucination retry loop. Pivot strategy instead of retrying.`,
      engine: "trajectory_hash",
      code: "BLOCK_LOOP_DETECTED",
    };
  }

  if (dupeCount === config.loopThreshold - 1) {
    return {
      allowed: true,
      blocked: false,
      friction: true,
      reason:
        `${dupeCount + 1} identical ${toolName} calls detected. ` +
        `One more will trigger a hard block. Consider a different approach.`,
      engine: "trajectory_hash",
      code: "FRICTION_LOOP_WARNING",
    };
  }

  return ALLOW;
}

// ─── Engine 2: Capital Velocity ─────────────────────────────────

function evaluateVelocity(
  sessionKey: string,
  params: Record<string, unknown>,
  config: PlimsollConfig,
): Verdict {
  const now = Date.now();
  const windowMs = config.velocityWindowSeconds * 1000;
  const amount = Number(params.amount ?? params.value ?? params.quantity ?? 0);
  if (amount <= 0) return ALLOW;

  const state = getSession(sessionKey);

  // Prune expired entries
  while (state.velocityWindow.length > 0 && now - state.velocityWindow[0].ts > windowMs) {
    state.velocityWindow.shift();
  }

  const windowSpend = state.velocityWindow.reduce((sum, e) => sum + e.amount, 0);

  if (windowSpend + amount > config.maxVelocityCentsPerWindow) {
    return {
      allowed: false,
      blocked: true,
      friction: false,
      reason:
        `Spend velocity exceeded: $${(windowSpend / 100).toFixed(2)} already spent in ` +
        `${config.velocityWindowSeconds}s window, adding $${(amount / 100).toFixed(2)} ` +
        `would breach the $${(config.maxVelocityCentsPerWindow / 100).toFixed(2)} cap.`,
      engine: "capital_velocity",
      code: "BLOCK_VELOCITY_BREACH",
    };
  }

  state.velocityWindow.push({ amount, ts: now });
  return ALLOW;
}

// ─── Engine 3: Entropy Guard ────────────────────────────────────

/**
 * Matches Ethereum private keys (64 hex chars after 0x).
 * Negative lookbehind/lookahead reduces false positives on
 * longer hex strings like tx hashes that contain a 64-char substring.
 */
const ETH_KEY_RE = /(?<![0-9a-fA-F])0x[0-9a-fA-F]{64}(?![0-9a-fA-F])/;

const MNEMONIC_RE = /\b([a-z]{3,8}\s+){11,}[a-z]{3,8}\b/;
const BASE64_RE = /[A-Za-z0-9+/]{40,}={0,2}/;

/** Fields that commonly carry transaction hashes, not private keys. */
const TX_HASH_FIELD_NAMES = new Set([
  "txHash",
  "transactionHash",
  "tx_hash",
  "transaction_hash",
  "hash",
  "txId",
  "tx_id",
  "blockHash",
  "block_hash",
  "parentHash",
  "parent_hash",
  "previousHash",
  "receipt",
]);

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of s) {
    freq.set(c, (freq.get(c) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function evaluateEntropy(params: Record<string, unknown>): Verdict {
  for (const [key, val] of Object.entries(params)) {
    if (typeof val !== "string" || val.length < 20) continue;

    // Skip fields that commonly carry tx hashes, not private keys
    if (TX_HASH_FIELD_NAMES.has(key)) continue;

    if (ETH_KEY_RE.test(val)) {
      return {
        allowed: false,
        blocked: true,
        friction: false,
        reason: `Field "${key}" contains an Ethereum private key pattern. Exfiltration blocked.`,
        engine: "entropy_guard",
        code: "BLOCK_KEY_EXFIL",
      };
    }

    if (MNEMONIC_RE.test(val)) {
      return {
        allowed: false,
        blocked: true,
        friction: false,
        reason: `Field "${key}" contains a BIP-39 mnemonic phrase. Exfiltration blocked.`,
        engine: "entropy_guard",
        code: "BLOCK_MNEMONIC_EXFIL",
      };
    }

    if (BASE64_RE.test(val) && shannonEntropy(val) > 5.0) {
      return {
        allowed: false,
        blocked: true,
        friction: false,
        reason:
          `Field "${key}" contains a high-entropy blob (${shannonEntropy(val).toFixed(1)} bits/char). ` +
          `Possible encoded secret.`,
        engine: "entropy_guard",
        code: "BLOCK_ENTROPY_ANOMALY",
      };
    }
  }

  return ALLOW;
}

// ─── Public API ─────────────────────────────────────────────────

/**
 * Run all three Plimsoll engines against a tool call.
 * First block wins. Returns the verdict.
 */
export function evaluate(
  sessionKey: string,
  toolName: string,
  params: Record<string, unknown>,
  config: PlimsollConfig,
): Verdict {
  // Engine 1: Loop detection
  const trajectoryVerdict = evaluateTrajectory(sessionKey, toolName, params, config);
  if (trajectoryVerdict.blocked) return trajectoryVerdict;

  // Engine 2: Spend rate
  const velocityVerdict = evaluateVelocity(sessionKey, params, config);
  if (velocityVerdict.blocked) return velocityVerdict;

  // Engine 3: Secret detection
  const entropyVerdict = evaluateEntropy(params);
  if (entropyVerdict.blocked) return entropyVerdict;

  // Return friction if any engine raised it
  if (trajectoryVerdict.friction) return trajectoryVerdict;

  return ALLOW;
}

export const DEFAULT_CONFIG: PlimsollConfig = {
  maxVelocityCentsPerWindow: 50_000,
  velocityWindowSeconds: 300,
  loopThreshold: 3,
  loopWindowSeconds: 60,
};

// ─── DeFi Tool Classification ───────────────────────────────────

/** Exact tool names that are always classified as DeFi. */
export const DEFI_TOOLS = new Set([
  "swap",
  "transfer",
  "approve",
  "bridge",
  "stake",
  "unstake",
  "deposit",
  "withdraw",
  "borrow",
  "repay",
  "lend",
  "supply",
  "send",
  "send_transaction",
]);

/**
 * Keyword fallback — matches "swap", "transfer", or "bridge" as
 * standalone segments separated by underscores, hyphens, or at
 * start/end of string. Avoids false positives on "swapfile", etc.
 */
const DEFI_KEYWORD_RE = /(?:^|[-_])(?:swap|transfer|bridge)(?:$|[-_])/i;

/**
 * Classify whether a tool name represents a DeFi operation.
 *
 * Two-tier: exact match against DEFI_TOOLS set, then keyword
 * fallback via DEFI_KEYWORD_RE for plugin-registered tools.
 */
export function isDefiTool(toolName: string): boolean {
  if (DEFI_TOOLS.has(toolName)) return true;
  return DEFI_KEYWORD_RE.test(toolName);
}
