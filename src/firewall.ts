/**
 * Plimsoll Financial Guard — five deterministic defense engines.
 *
 * Protects any agent that handles money: crypto, stocks, purchases,
 * bank transfers, credit cards. Ported from the Plimsoll Protocol
 * (https://github.com/scoootscooob/plimsoll-protocol).
 *
 *   1. Trajectory Hash      — blocks hallucination retry loops
 *   2. Capital Velocity     — sliding-window spend-rate limiter
 *   3. Entropy Guard        — blocks credential exfiltration (crypto keys,
 *                             credit cards, SSNs, API keys, mnemonics)
 *   4. Confirmation Gate    — hard block on high-value single transactions
 *   5. Amount Anomaly       — flags statistical outliers vs rolling average
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
  confirmationThresholdCents: number;
  anomalyMultiplier: number;
  anomalyMinSamples: number;
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
  amountHistory: number[];
};

const sessions = new Map<string, SessionState>();
const MAX_SESSIONS = 1000;

function getSession(sessionKey: string): SessionState {
  let state = sessions.get(sessionKey);
  if (!state) {
    if (sessions.size >= MAX_SESSIONS) {
      const oldest = sessions.keys().next().value;
      if (oldest !== undefined) sessions.delete(oldest);
    }
    state = { trajectoryWindow: [], velocityWindow: [], amountHistory: [] };
    sessions.set(sessionKey, state);
  }
  return state;
}

// ─── Engine 1: Trajectory Hash ──────────────────────────────────

function trajectoryHash(toolName: string, params: Record<string, unknown>): string {
  const target = String(
    params.to ?? params.address ?? params.recipient ?? params.target ??
    params.account ?? params.symbol ?? params.ticker ?? "",
  );
  const amount = String(params.amount ?? params.value ?? params.quantity ?? params.total ?? "0");
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
  const amount = Number(params.amount ?? params.value ?? params.quantity ?? params.total ?? 0);
  if (amount <= 0) return ALLOW;

  const state = getSession(sessionKey);

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

// Crypto credentials
const ETH_KEY_RE = /(?<![0-9a-fA-F])0x[0-9a-fA-F]{64}(?![0-9a-fA-F])/;
const MNEMONIC_RE = /\b([a-z]{3,8}\s+){11,}[a-z]{3,8}\b/;
const BASE64_RE = /[A-Za-z0-9+/]{40,}={0,2}/;

// Credit card numbers — 13-19 digits, optionally separated by spaces or dashes
const CREDIT_CARD_RE = /\b(\d[ -]*?){13,19}\b/;

// SSN pattern — XXX-XX-XXXX
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/;

// Bank routing numbers — 9 digits (ABA format)
const ROUTING_RE = /\b\d{9}\b/;

// Financial API keys — Stripe, Plaid, etc.
const STRIPE_KEY_RE = /\b[sr]k_(live|test)_[A-Za-z0-9]{20,}/;
const PLAID_TOKEN_RE = /\b(access-|link-)(sandbox|development|production)-[a-f0-9-]{30,}/;

/** Fields that commonly carry transaction hashes or IDs, not secrets. */
const SAFE_FIELD_NAMES = new Set([
  "txHash", "transactionHash", "tx_hash", "transaction_hash",
  "hash", "txId", "tx_id", "blockHash", "block_hash",
  "parentHash", "parent_hash", "previousHash", "receipt",
  "orderId", "order_id", "traceId", "trace_id", "requestId",
  "request_id", "confirmationNumber", "confirmation_number",
]);

/** Luhn algorithm — validates credit card check digit. */
export function luhnCheck(digits: string): boolean {
  const nums = digits.replace(/\D/g, "");
  if (nums.length < 13 || nums.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = nums.length - 1; i >= 0; i--) {
    let d = parseInt(nums[i], 10);
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

export function shannonEntropy(s: string): number {
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
    if (typeof val !== "string" || val.length < 9) continue;
    if (SAFE_FIELD_NAMES.has(key)) continue;

    // Ethereum private keys
    if (ETH_KEY_RE.test(val)) {
      return {
        allowed: false, blocked: true, friction: false,
        reason: `Field "${key}" contains an Ethereum private key pattern. Exfiltration blocked.`,
        engine: "entropy_guard", code: "BLOCK_KEY_EXFIL",
      };
    }

    // BIP-39 mnemonic phrases
    if (val.length >= 20 && MNEMONIC_RE.test(val)) {
      return {
        allowed: false, blocked: true, friction: false,
        reason: `Field "${key}" contains a BIP-39 mnemonic phrase. Exfiltration blocked.`,
        engine: "entropy_guard", code: "BLOCK_MNEMONIC_EXFIL",
      };
    }

    // Credit card numbers (Luhn-validated)
    const ccMatch = val.match(CREDIT_CARD_RE);
    if (ccMatch) {
      const digits = ccMatch[0].replace(/\D/g, "");
      if (luhnCheck(digits)) {
        return {
          allowed: false, blocked: true, friction: false,
          reason: `Field "${key}" contains a credit card number (Luhn-valid). Exfiltration blocked.`,
          engine: "entropy_guard", code: "BLOCK_CREDIT_CARD",
        };
      }
    }

    // SSN
    if (SSN_RE.test(val)) {
      return {
        allowed: false, blocked: true, friction: false,
        reason: `Field "${key}" contains an SSN pattern. Exfiltration blocked.`,
        engine: "entropy_guard", code: "BLOCK_SSN",
      };
    }

    // Financial API keys (Stripe)
    if (STRIPE_KEY_RE.test(val)) {
      return {
        allowed: false, blocked: true, friction: false,
        reason: `Field "${key}" contains a Stripe API key. Exfiltration blocked.`,
        engine: "entropy_guard", code: "BLOCK_API_KEY",
      };
    }

    // Financial API keys (Plaid)
    if (PLAID_TOKEN_RE.test(val)) {
      return {
        allowed: false, blocked: true, friction: false,
        reason: `Field "${key}" contains a Plaid access token. Exfiltration blocked.`,
        engine: "entropy_guard", code: "BLOCK_API_KEY",
      };
    }

    // High-entropy base64 blobs
    if (val.length >= 20 && BASE64_RE.test(val) && shannonEntropy(val) > 5.0) {
      return {
        allowed: false, blocked: true, friction: false,
        reason:
          `Field "${key}" contains a high-entropy blob (${shannonEntropy(val).toFixed(1)} bits/char). ` +
          `Possible encoded secret.`,
        engine: "entropy_guard", code: "BLOCK_ENTROPY_ANOMALY",
      };
    }
  }

  return ALLOW;
}

// ─── Engine 4: Confirmation Gate ────────────────────────────────

function evaluateConfirmation(
  params: Record<string, unknown>,
  config: PlimsollConfig,
): Verdict {
  if (config.confirmationThresholdCents <= 0) return ALLOW;

  const amount = Number(params.amount ?? params.value ?? params.quantity ?? params.total ?? 0);
  if (amount <= 0) return ALLOW;

  if (amount >= config.confirmationThresholdCents) {
    return {
      allowed: false,
      blocked: true,
      friction: false,
      reason:
        `Transaction of $${(amount / 100).toFixed(2)} exceeds the ` +
        `$${(config.confirmationThresholdCents / 100).toFixed(2)} confirmation threshold. ` +
        `Human approval required before proceeding.`,
      engine: "confirmation_gate",
      code: "BLOCK_CONFIRMATION_REQUIRED",
    };
  }

  return ALLOW;
}

// ─── Engine 5: Amount Anomaly Detection ─────────────────────────

const MAX_HISTORY = 50;

function evaluateAnomaly(
  sessionKey: string,
  params: Record<string, unknown>,
  config: PlimsollConfig,
): Verdict {
  const amount = Number(params.amount ?? params.value ?? params.quantity ?? params.total ?? 0);
  if (amount <= 0) return ALLOW;

  const state = getSession(sessionKey);

  if (state.amountHistory.length >= config.anomalyMinSamples) {
    const avg = state.amountHistory.reduce((a, b) => a + b, 0) / state.amountHistory.length;
    if (avg > 0 && amount >= avg * config.anomalyMultiplier) {
      return {
        allowed: true,
        blocked: false,
        friction: true,
        reason:
          `Transaction of $${(amount / 100).toFixed(2)} is ${(amount / avg).toFixed(1)}x ` +
          `the rolling average ($${(avg / 100).toFixed(2)}). Possible anomaly — verify intent.`,
        engine: "amount_anomaly",
        code: "FRICTION_AMOUNT_ANOMALY",
      };
    }
  }

  // Record after evaluation so current tx doesn't bias its own check
  state.amountHistory.push(amount);
  if (state.amountHistory.length > MAX_HISTORY) {
    state.amountHistory.shift();
  }

  return ALLOW;
}

// ─── Public API ─────────────────────────────────────────────────

/**
 * Run all five Plimsoll engines against a tool call.
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

  // Engine 3: Credential exfiltration
  const entropyVerdict = evaluateEntropy(params);
  if (entropyVerdict.blocked) return entropyVerdict;

  // Engine 4: High-value confirmation
  const confirmVerdict = evaluateConfirmation(params, config);
  if (confirmVerdict.blocked) return confirmVerdict;

  // Engine 5: Amount anomaly (friction only, after blocks)
  const anomalyVerdict = evaluateAnomaly(sessionKey, params, config);
  if (anomalyVerdict.friction) return anomalyVerdict;

  // Return friction from trajectory if raised
  if (trajectoryVerdict.friction) return trajectoryVerdict;

  return ALLOW;
}

export const DEFAULT_CONFIG: PlimsollConfig = {
  maxVelocityCentsPerWindow: 50_000,
  velocityWindowSeconds: 300,
  loopThreshold: 3,
  loopWindowSeconds: 60,
  confirmationThresholdCents: 100_00,
  anomalyMultiplier: 10,
  anomalyMinSamples: 5,
};

// ─── Financial Tool Classification ──────────────────────────────

/** Exact tool names classified as financial operations. */
export const FINANCIAL_TOOLS = new Set([
  // DeFi
  "swap", "transfer", "approve", "bridge", "stake", "unstake",
  "deposit", "withdraw", "borrow", "repay", "lend", "supply",
  "send", "send_transaction",
  // Trading
  "buy", "sell", "place_order", "market_order", "limit_order",
  "cancel_order",
  // Payments
  "pay", "purchase", "checkout", "charge", "subscribe", "refund",
  // Banking
  "wire_transfer", "ach_transfer", "send_money", "bank_transfer",
  // General
  "payment", "transaction", "invoice",
]);

/** @deprecated Use FINANCIAL_TOOLS instead. */
export const DEFI_TOOLS = FINANCIAL_TOOLS;

/**
 * Keyword fallback — matches financial keywords as standalone
 * segments separated by underscores, hyphens, or at start/end.
 */
const FINANCIAL_KEYWORD_RE =
  /(?:^|[-_])(?:swap|transfer|bridge|buy|sell|pay|purchase|charge|order|wire|send)(?:$|[-_])/i;

/**
 * Classify whether a tool name represents a financial operation.
 *
 * Two-tier: exact match against FINANCIAL_TOOLS, then keyword
 * fallback via FINANCIAL_KEYWORD_RE for plugin-registered tools.
 */
export function isFinancialTool(toolName: string): boolean {
  if (FINANCIAL_TOOLS.has(toolName)) return true;
  return FINANCIAL_KEYWORD_RE.test(toolName);
}

/** @deprecated Use isFinancialTool instead. */
export function isDefiTool(toolName: string): boolean {
  return isFinancialTool(toolName);
}
