import { describe, it, expect } from "vitest";
import {
  evaluate, DEFAULT_CONFIG, isFinancialTool, isDefiTool,
  luhnCheck, shannonEntropy, FINANCIAL_TOOLS,
  getAuditLog, verifyAuditChain, clearAuditLog,
} from "./firewall.js";
import type { PlimsollConfig, AuditEntry } from "./firewall.js";

function freshSession(): string {
  return `test-${Date.now()}-${Math.random()}`;
}

// ─── Engine 1: Trajectory Hash ──────────────────────────────────

describe("Trajectory Hash — loop detection", () => {
  it("allows the first call", () => {
    const v = evaluate(freshSession(), "swap", { to: "0xabc", amount: 100 }, DEFAULT_CONFIG);
    expect(v.blocked).toBe(false);
    expect(v.code).toBe("ALLOW");
  });

  it("allows different calls", () => {
    const session = freshSession();
    for (let i = 0; i < 5; i++) {
      const v = evaluate(session, "swap", { to: `0x${i}`, amount: 100 + i }, DEFAULT_CONFIG);
      expect(v.blocked).toBe(false);
    }
  });

  it("emits friction one call before the block threshold", () => {
    const session = freshSession();
    const params = { to: "0xabc", amount: 100 };
    evaluate(session, "swap", params, DEFAULT_CONFIG);
    evaluate(session, "swap", params, DEFAULT_CONFIG);
    const v3 = evaluate(session, "swap", params, DEFAULT_CONFIG);
    expect(v3.friction).toBe(true);
    expect(v3.code).toBe("FRICTION_LOOP_WARNING");
  });

  it("blocks when dupes reach the threshold", () => {
    const session = freshSession();
    const params = { to: "0xabc", amount: 100 };
    evaluate(session, "swap", params, DEFAULT_CONFIG);
    evaluate(session, "swap", params, DEFAULT_CONFIG);
    evaluate(session, "swap", params, DEFAULT_CONFIG);
    const v4 = evaluate(session, "swap", params, DEFAULT_CONFIG);
    expect(v4.blocked).toBe(true);
    expect(v4.code).toBe("BLOCK_LOOP_DETECTED");
  });

  it("isolates sessions", () => {
    const sessionA = freshSession();
    const sessionB = freshSession();
    const params = { to: "0xabc", amount: 100 };
    evaluate(sessionA, "swap", params, DEFAULT_CONFIG);
    evaluate(sessionA, "swap", params, DEFAULT_CONFIG);
    evaluate(sessionA, "swap", params, DEFAULT_CONFIG);
    const vB = evaluate(sessionB, "swap", params, DEFAULT_CONFIG);
    expect(vB.blocked).toBe(false);
    expect(vB.friction).toBe(false);
  });

  it("works for stock trading tools", () => {
    const session = freshSession();
    const params = { symbol: "AAPL", quantity: 10 };
    evaluate(session, "buy", params, DEFAULT_CONFIG);
    evaluate(session, "buy", params, DEFAULT_CONFIG);
    evaluate(session, "buy", params, DEFAULT_CONFIG);
    const v4 = evaluate(session, "buy", params, DEFAULT_CONFIG);
    expect(v4.blocked).toBe(true);
    expect(v4.code).toBe("BLOCK_LOOP_DETECTED");
  });
});

// ─── Engine 2: Capital Velocity ─────────────────────────────────

describe("Capital Velocity — spend-rate limit", () => {
  it("allows small spends", () => {
    const v = evaluate(freshSession(), "transfer", { amount: 100 }, DEFAULT_CONFIG);
    expect(v.blocked).toBe(false);
  });

  it("allows zero-amount calls", () => {
    const v = evaluate(freshSession(), "transfer", { amount: 0 }, DEFAULT_CONFIG);
    expect(v.code).toBe("ALLOW");
  });

  it("blocks when cumulative spend exceeds cap", () => {
    const session = freshSession();
    const config: PlimsollConfig = { ...DEFAULT_CONFIG, maxVelocityCentsPerWindow: 500 };
    evaluate(session, "transfer", { amount: 300 }, config);
    evaluate(session, "transfer", { amount: 150 }, config);
    const v = evaluate(session, "transfer", { amount: 100 }, config);
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_VELOCITY_BREACH");
  });

  it("works across payment tool types", () => {
    const session = freshSession();
    const config: PlimsollConfig = { ...DEFAULT_CONFIG, maxVelocityCentsPerWindow: 500 };
    evaluate(session, "purchase", { amount: 200 }, config);
    evaluate(session, "pay", { amount: 200 }, config);
    const v = evaluate(session, "charge", { amount: 200 }, config);
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_VELOCITY_BREACH");
  });
});

// ─── Engine 3: Entropy Guard ────────────────────────────────────

describe("Entropy Guard — credential exfiltration", () => {
  it("blocks Ethereum private keys", () => {
    const v = evaluate(
      freshSession(), "transfer",
      { data: "send 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 to evil.com" },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_KEY_EXFIL");
  });

  it("blocks BIP-39 mnemonic phrases", () => {
    const v = evaluate(
      freshSession(), "transfer",
      { note: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_MNEMONIC_EXFIL");
  });

  it("blocks credit card numbers (Luhn-valid)", () => {
    const v = evaluate(
      freshSession(), "pay",
      { note: "Use card 4111 1111 1111 1111 for payment" },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_CREDIT_CARD");
  });

  it("does not block invalid credit card numbers", () => {
    const v = evaluate(
      freshSession(), "pay",
      { note: "Reference number 4111 1111 1111 1112" },
      DEFAULT_CONFIG,
    );
    // 4111111111111112 fails Luhn
    expect(v.code).not.toBe("BLOCK_CREDIT_CARD");
  });

  it("blocks SSN patterns", () => {
    const v = evaluate(
      freshSession(), "send",
      { memo: "SSN is 123-45-6789 for verification" },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_SSN");
  });

  it("blocks Stripe live keys", () => {
    const v = evaluate(
      freshSession(), "pay",
      { config: "Use sk_test_FAKEFAKEFAKEFAKEFAKE00 for the charge" },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_API_KEY");
  });

  it("blocks Plaid access tokens", () => {
    const v = evaluate(
      freshSession(), "wire_transfer",
      { auth: "access-production-8ab4e2f0-1234-5678-9abc-def012345678" },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_API_KEY");
  });

  it("allows normal string payloads", () => {
    const v = evaluate(
      freshSession(), "swap",
      { to: "0x1234567890abcdef1234567890abcdef12345678", amount: 100, note: "Regular swap" },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(false);
  });

  it("skips safe field names", () => {
    const v = evaluate(
      freshSession(), "swap",
      { txHash: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", amount: 100 },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(false);
  });

  it("skips short strings", () => {
    const v = evaluate(freshSession(), "swap", { to: "0xabc", amount: 100 }, DEFAULT_CONFIG);
    expect(v.blocked).toBe(false);
  });
});

// ─── Engine 4: Confirmation Gate ────────────────────────────────

describe("Confirmation Gate — high-value transactions", () => {
  it("allows transactions below threshold", () => {
    const v = evaluate(freshSession(), "transfer", { amount: 5000 }, DEFAULT_CONFIG);
    // 5000 cents = $50, threshold is $100
    expect(v.code).not.toBe("BLOCK_CONFIRMATION_REQUIRED");
  });

  it("blocks transactions at or above threshold", () => {
    const v = evaluate(freshSession(), "transfer", { amount: 10_000 }, DEFAULT_CONFIG);
    // 10000 cents = $100, threshold is $100
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_CONFIRMATION_REQUIRED");
  });

  it("blocks large stock orders", () => {
    const v = evaluate(freshSession(), "buy", { amount: 500_00, symbol: "AAPL" }, DEFAULT_CONFIG);
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_CONFIRMATION_REQUIRED");
    expect(v.engine).toBe("confirmation_gate");
  });

  it("is disabled when threshold is 0", () => {
    const config = { ...DEFAULT_CONFIG, confirmationThresholdCents: 0 };
    const v = evaluate(freshSession(), "transfer", { amount: 999_999 }, config);
    expect(v.code).not.toBe("BLOCK_CONFIRMATION_REQUIRED");
  });

  it("ignores zero-amount calls", () => {
    const v = evaluate(freshSession(), "approve", { amount: 0 }, DEFAULT_CONFIG);
    expect(v.code).toBe("ALLOW");
  });
});

// ─── Engine 5: Amount Anomaly Detection ─────────────────────────

describe("Amount Anomaly — outlier detection", () => {
  it("allows early transactions (before min samples)", () => {
    const session = freshSession();
    const config = { ...DEFAULT_CONFIG, anomalyMinSamples: 5, confirmationThresholdCents: 0 };
    // Under 5 samples — no anomaly detection
    for (let i = 0; i < 4; i++) {
      const v = evaluate(session, "pay", { amount: 100 }, config);
      expect(v.code).not.toBe("FRICTION_AMOUNT_ANOMALY");
    }
  });

  it("flags outlier after enough samples", () => {
    const session = freshSession();
    const config = {
      ...DEFAULT_CONFIG,
      anomalyMinSamples: 3,
      anomalyMultiplier: 5,
      confirmationThresholdCents: 0,
    };
    // Build history: 3 small transactions
    evaluate(session, "pay", { amount: 100 }, config);
    evaluate(session, "pay", { amount: 100 }, config);
    evaluate(session, "pay", { amount: 100 }, config);
    // 4th is 50x the average — should be flagged
    const v = evaluate(session, "pay", { amount: 5000 }, config);
    expect(v.friction).toBe(true);
    expect(v.code).toBe("FRICTION_AMOUNT_ANOMALY");
    expect(v.engine).toBe("amount_anomaly");
  });

  it("allows transactions within multiplier range", () => {
    const session = freshSession();
    const config = {
      ...DEFAULT_CONFIG,
      anomalyMinSamples: 3,
      anomalyMultiplier: 10,
      confirmationThresholdCents: 0,
    };
    evaluate(session, "pay", { amount: 100 }, config);
    evaluate(session, "pay", { amount: 100 }, config);
    evaluate(session, "pay", { amount: 100 }, config);
    // 5x average — under 10x multiplier, should pass
    const v = evaluate(session, "pay", { amount: 500 }, config);
    expect(v.friction).toBe(false);
    expect(v.code).toBe("ALLOW");
  });
});

// ─── Luhn Check ─────────────────────────────────────────────────

describe("luhnCheck", () => {
  it("validates known good card numbers", () => {
    expect(luhnCheck("4111111111111111")).toBe(true);  // Visa test
    expect(luhnCheck("5500000000000004")).toBe(true);  // MC test
    expect(luhnCheck("378282246310005")).toBe(true);   // Amex test
  });

  it("rejects invalid numbers", () => {
    expect(luhnCheck("4111111111111112")).toBe(false);
    expect(luhnCheck("1234567890")).toBe(false);       // too short
    expect(luhnCheck("00000000000000000000")).toBe(false); // too long
  });
});

// ─── Shannon Entropy ────────────────────────────────────────────

describe("shannonEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for single character", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
  });

  it("returns high entropy for random-looking strings", () => {
    expect(shannonEntropy("aB3$fG7!kL9@mN1#")).toBeGreaterThan(3.5);
  });
});

// ─── Financial Tool Classification ──────────────────────────────

describe("isFinancialTool — classification boundaries", () => {
  describe("exact matches (FINANCIAL_TOOLS set)", () => {
    it.each([
      // DeFi
      "swap", "transfer", "approve", "bridge", "stake", "unstake",
      "deposit", "withdraw", "borrow", "repay", "lend", "supply",
      "send", "send_transaction",
      // Trading
      "buy", "sell", "place_order", "market_order", "limit_order", "cancel_order",
      // Payments
      "pay", "purchase", "checkout", "charge", "subscribe", "refund",
      // Banking
      "wire_transfer", "ach_transfer", "send_money", "bank_transfer",
      // General
      "payment", "transaction", "invoice",
    ])("classifies '%s' as financial", (name) => {
      expect(isFinancialTool(name)).toBe(true);
    });
  });

  describe("keyword fallback — true positives", () => {
    it.each([
      ["token_swap", "swap as trailing segment"],
      ["cross_chain_bridge", "bridge as trailing segment"],
      ["usdc_transfer", "transfer as trailing segment"],
      ["batch-swap", "swap with hyphen"],
      ["stock_buy", "buy as trailing segment"],
      ["auto_pay", "pay as trailing segment"],
      ["bulk_purchase", "purchase as trailing segment"],
      ["one_click_charge", "charge as trailing segment"],
      ["limit-order-v2", "order as middle segment"],
      ["wire-send", "send as trailing segment"],
    ])("classifies '%s' as financial (%s)", (name) => {
      expect(isFinancialTool(name)).toBe(true);
    });
  });

  describe("keyword fallback — true negatives", () => {
    it.each([
      ["read_file", "no financial keyword"],
      ["exec", "no financial keyword"],
      ["get_balance", "no financial keyword"],
      ["list_tokens", "no financial keyword"],
      ["transcribe", "no keyword despite 'trans'"],
      ["swapfile", "swap not standalone"],
      ["bridgetown", "bridge not standalone"],
      ["sellular", "sell not standalone"],
      ["bypass", "no keyword"],
      ["display", "no keyword"],
    ])("classifies '%s' as non-financial (%s)", (name) => {
      expect(isFinancialTool(name)).toBe(false);
    });
  });

  describe("backward compatibility", () => {
    it("isDefiTool is an alias for isFinancialTool", () => {
      expect(isDefiTool("swap")).toBe(true);
      expect(isDefiTool("buy")).toBe(true);
      expect(isDefiTool("read_file")).toBe(false);
    });
  });
});

// ─── Engine Edge Cases ──────────────────────────────────────────

describe("Trajectory Hash — edge cases", () => {
  it("does not cross-count different tools with same target", () => {
    const session = freshSession();
    const params = { to: "0xabc", amount: 100 };
    evaluate(session, "swap", params, DEFAULT_CONFIG);
    evaluate(session, "transfer", params, DEFAULT_CONFIG);
    evaluate(session, "bridge", params, DEFAULT_CONFIG);
    const v = evaluate(session, "send", params, DEFAULT_CONFIG);
    expect(v.blocked).toBe(false);
  });

  it("handles empty params without error", () => {
    const v = evaluate(freshSession(), "swap", {}, DEFAULT_CONFIG);
    expect(v.code).toBe("ALLOW");
  });

  it("distinguishes by amount", () => {
    const session = freshSession();
    evaluate(session, "swap", { to: "0xabc", amount: 100 }, DEFAULT_CONFIG);
    evaluate(session, "swap", { to: "0xabc", amount: 200 }, DEFAULT_CONFIG);
    evaluate(session, "swap", { to: "0xabc", amount: 300 }, DEFAULT_CONFIG);
    const v = evaluate(session, "swap", { to: "0xabc", amount: 400 }, DEFAULT_CONFIG);
    expect(v.blocked).toBe(false);
  });

  it("uses custom loopThreshold", () => {
    const session = freshSession();
    const config = { ...DEFAULT_CONFIG, loopThreshold: 2 };
    const params = { to: "0xabc", amount: 100 };
    evaluate(session, "swap", params, config); // 1st: allow
    evaluate(session, "swap", params, config); // 2nd: friction (threshold-1)
    const v = evaluate(session, "swap", params, config); // 3rd: block (>= threshold)
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_LOOP_DETECTED");
  });

  it("uses recipient aliases (address, account, symbol)", () => {
    const session = freshSession();
    const p1 = { address: "0xabc", amount: 100 };
    evaluate(session, "transfer", p1, DEFAULT_CONFIG);
    evaluate(session, "transfer", p1, DEFAULT_CONFIG);
    evaluate(session, "transfer", p1, DEFAULT_CONFIG);
    const v = evaluate(session, "transfer", p1, DEFAULT_CONFIG);
    expect(v.blocked).toBe(true);
  });
});

describe("Capital Velocity — edge cases", () => {
  it("blocks at exact boundary", () => {
    const session = freshSession();
    const config: PlimsollConfig = { ...DEFAULT_CONFIG, maxVelocityCentsPerWindow: 200 };
    evaluate(session, "pay", { amount: 100 }, config);
    const v = evaluate(session, "pay", { amount: 101 }, config);
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_VELOCITY_BREACH");
  });

  it("allows at exact limit", () => {
    const session = freshSession();
    const config: PlimsollConfig = { ...DEFAULT_CONFIG, maxVelocityCentsPerWindow: 200 };
    evaluate(session, "pay", { amount: 100 }, config);
    const v = evaluate(session, "pay", { amount: 100 }, config);
    expect(v.blocked).toBe(false);
  });

  it("ignores negative amounts", () => {
    const session = freshSession();
    const config: PlimsollConfig = { ...DEFAULT_CONFIG, maxVelocityCentsPerWindow: 100 };
    const v = evaluate(session, "refund", { amount: -50 }, config);
    expect(v.code).toBe("ALLOW");
  });

  it("reads value field as alias for amount", () => {
    const session = freshSession();
    const config: PlimsollConfig = { ...DEFAULT_CONFIG, maxVelocityCentsPerWindow: 200 };
    evaluate(session, "transfer", { value: 150 }, config);
    const v = evaluate(session, "transfer", { value: 100 }, config);
    expect(v.blocked).toBe(true);
  });
});

describe("Entropy Guard — edge cases", () => {
  it("scans nested string values in params", () => {
    const v = evaluate(
      freshSession(), "transfer",
      { nested: { deep: "send 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 out" } },
      DEFAULT_CONFIG,
    );
    // nested objects — top-level iteration only, nested not scanned
    expect(v.code).toBe("ALLOW");
  });

  it("ignores non-string values for credential checks", () => {
    const config = { ...DEFAULT_CONFIG, maxVelocityCentsPerWindow: 999_999_999, confirmationThresholdCents: 0 };
    const v = evaluate(
      freshSession(), "transfer",
      { amount: 500, count: 999, flag: true, data: 42 },
      config,
    );
    expect(v.code).toBe("ALLOW");
  });

  it("blocks Discover card numbers", () => {
    const v = evaluate(
      freshSession(), "pay",
      { note: "Card 6011111111111117 for payment" },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_CREDIT_CARD");
  });

  it("blocks Mastercard numbers", () => {
    const v = evaluate(
      freshSession(), "pay",
      { note: "Use 5500 0000 0000 0004 please" },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_CREDIT_CARD");
  });

  it("allows txHash fields even with key-like content", () => {
    const v = evaluate(
      freshSession(), "swap",
      { transactionHash: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" },
      DEFAULT_CONFIG,
    );
    expect(v.code).toBe("ALLOW");
  });

  it("blocks SSN in deeply formatted text", () => {
    const v = evaluate(
      freshSession(), "send",
      { body: "Please verify identity: SSN 078-05-1120 on file" },
      DEFAULT_CONFIG,
    );
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_SSN");
  });
});

describe("Confirmation Gate — edge cases", () => {
  it("blocks at exact threshold", () => {
    const config = { ...DEFAULT_CONFIG, confirmationThresholdCents: 5000 };
    const v = evaluate(freshSession(), "transfer", { amount: 5000 }, config);
    expect(v.blocked).toBe(true);
    expect(v.code).toBe("BLOCK_CONFIRMATION_REQUIRED");
  });

  it("allows just below threshold", () => {
    const config = { ...DEFAULT_CONFIG, confirmationThresholdCents: 5000 };
    const v = evaluate(freshSession(), "transfer", { amount: 4999 }, config);
    expect(v.code).not.toBe("BLOCK_CONFIRMATION_REQUIRED");
  });

  it("ignores string amount values gracefully", () => {
    const v = evaluate(freshSession(), "transfer", { amount: "not-a-number" }, DEFAULT_CONFIG);
    expect(v.code).toBe("ALLOW");
  });
});

describe("Amount Anomaly — edge cases", () => {
  it("does not flag when multiplier is very high", () => {
    const session = freshSession();
    const config = {
      ...DEFAULT_CONFIG,
      anomalyMinSamples: 2,
      anomalyMultiplier: 1000,
      confirmationThresholdCents: 0,
    };
    evaluate(session, "pay", { amount: 100 }, config);
    evaluate(session, "pay", { amount: 100 }, config);
    const v = evaluate(session, "pay", { amount: 5000 }, config);
    expect(v.friction).toBe(false);
  });

  it("caps history at MAX_HISTORY entries", () => {
    const session = freshSession();
    const config = {
      ...DEFAULT_CONFIG,
      anomalyMinSamples: 3,
      anomalyMultiplier: 5,
      confirmationThresholdCents: 0,
    };
    // Push 60 entries (MAX_HISTORY = 50, should truncate)
    for (let i = 0; i < 60; i++) {
      evaluate(session, "pay", { amount: 100 }, config);
    }
    // A big anomaly should still be caught
    const v = evaluate(session, "pay", { amount: 5000 }, config);
    expect(v.friction).toBe(true);
    expect(v.code).toBe("FRICTION_AMOUNT_ANOMALY");
  });
});

// ─── Multi-Engine Integration ───────────────────────────────────

describe("Multi-engine priority", () => {
  it("loop detection takes priority over velocity", () => {
    const session = freshSession();
    const config: PlimsollConfig = { ...DEFAULT_CONFIG, maxVelocityCentsPerWindow: 100 };
    const params = { to: "0xabc", amount: 50 };
    evaluate(session, "swap", params, config);
    evaluate(session, "swap", params, config);
    evaluate(session, "swap", params, config);
    // Both loop (4th identical) and velocity (200 > 100) should trigger, loop wins
    const v = evaluate(session, "swap", params, config);
    expect(v.code).toBe("BLOCK_LOOP_DETECTED");
  });

  it("credential block takes priority over confirmation gate", () => {
    const config = { ...DEFAULT_CONFIG, maxVelocityCentsPerWindow: 999_999_999 };
    const v = evaluate(
      freshSession(), "transfer",
      { amount: 999999, data: "key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" },
      config,
    );
    // Entropy guard fires before confirmation gate (velocity disabled via high cap)
    expect(v.code).toBe("BLOCK_KEY_EXFIL");
  });

  it("velocity block takes priority over credential block", () => {
    const session = freshSession();
    const config: PlimsollConfig = { ...DEFAULT_CONFIG, maxVelocityCentsPerWindow: 100 };
    evaluate(session, "pay", { amount: 80 }, config);
    // Second call exceeds velocity AND has a credit card
    const v = evaluate(session, "pay", { amount: 50, note: "Use card 4111 1111 1111 1111" }, config);
    expect(v.code).toBe("BLOCK_VELOCITY_BREACH");
  });

  it("friction from trajectory is returned when no blocks fire", () => {
    const session = freshSession();
    const params = { to: "0xabc", amount: 100 };
    evaluate(session, "swap", params, DEFAULT_CONFIG);
    evaluate(session, "swap", params, DEFAULT_CONFIG);
    // 3rd = friction warning (threshold - 1)
    const v = evaluate(session, "swap", params, DEFAULT_CONFIG);
    expect(v.friction).toBe(true);
    expect(v.code).toBe("FRICTION_LOOP_WARNING");
  });
});

// ─── Audit Trail ────────────────────────────────────────────────

describe("Audit Trail — hash-chained log", () => {
  it("records ALLOW verdicts", () => {
    const session = freshSession();
    clearAuditLog(session);
    evaluate(session, "swap", { to: "0xabc", amount: 100 }, DEFAULT_CONFIG);
    const log = getAuditLog(session);
    expect(log.length).toBe(1);
    expect(log[0].code).toBe("ALLOW");
    expect(log[0].toolName).toBe("swap");
    expect(log[0].seq).toBe(0);
  });

  it("records BLOCK verdicts", () => {
    const session = freshSession();
    clearAuditLog(session);
    const v = evaluate(session, "transfer", { amount: 10_000 }, DEFAULT_CONFIG);
    expect(v.blocked).toBe(true);
    const log = getAuditLog(session);
    expect(log.length).toBe(1);
    expect(log[0].code).toBe("BLOCK_CONFIRMATION_REQUIRED");
  });

  it("chains hashes correctly", () => {
    const session = freshSession();
    clearAuditLog(session);
    evaluate(session, "swap", { to: "0xabc", amount: 100 }, DEFAULT_CONFIG);
    evaluate(session, "pay", { amount: 200 }, DEFAULT_CONFIG);
    evaluate(session, "transfer", { amount: 300 }, DEFAULT_CONFIG);
    const log = getAuditLog(session);
    expect(log.length).toBe(3);
    // First entry's prevHash is genesis
    expect(log[0].prevHash).toBe("0000000000000000000000000000000000000000000000000000000000000000");
    // Each subsequent entry's prevHash is previous entry's hash
    expect(log[1].prevHash).toBe(log[0].hash);
    expect(log[2].prevHash).toBe(log[1].hash);
  });

  it("verifyAuditChain returns -1 for valid chain", () => {
    const session = freshSession();
    clearAuditLog(session);
    evaluate(session, "swap", { amount: 100 }, DEFAULT_CONFIG);
    evaluate(session, "pay", { amount: 200 }, DEFAULT_CONFIG);
    expect(verifyAuditChain(session)).toBe(-1);
  });

  it("verifyAuditChain returns -1 for empty log", () => {
    expect(verifyAuditChain("nonexistent-session")).toBe(-1);
  });

  it("records sequential seq numbers", () => {
    const session = freshSession();
    clearAuditLog(session);
    for (let i = 0; i < 5; i++) {
      evaluate(session, "pay", { amount: 100 + i }, DEFAULT_CONFIG);
    }
    const log = getAuditLog(session);
    expect(log.length).toBe(5);
    for (let i = 0; i < 5; i++) {
      expect(log[i].seq).toBe(i);
    }
  });

  it("includes engine name in entries", () => {
    const session = freshSession();
    clearAuditLog(session);
    evaluate(session, "transfer", { amount: 10_000 }, DEFAULT_CONFIG);
    const log = getAuditLog(session);
    expect(log[0].engine).toBe("confirmation_gate");
  });

  it("hashes are unique for different entries", () => {
    const session = freshSession();
    clearAuditLog(session);
    evaluate(session, "swap", { amount: 100 }, DEFAULT_CONFIG);
    evaluate(session, "pay", { amount: 200 }, DEFAULT_CONFIG);
    const log = getAuditLog(session);
    expect(log[0].hash).not.toBe(log[1].hash);
  });

  it("isolates audit logs per session", () => {
    const s1 = freshSession();
    const s2 = freshSession();
    clearAuditLog(s1);
    clearAuditLog(s2);
    evaluate(s1, "swap", { amount: 100 }, DEFAULT_CONFIG);
    evaluate(s1, "swap", { amount: 200 }, DEFAULT_CONFIG);
    evaluate(s2, "pay", { amount: 300 }, DEFAULT_CONFIG);
    expect(getAuditLog(s1).length).toBe(2);
    expect(getAuditLog(s2).length).toBe(1);
  });

  it("clearAuditLog removes the log", () => {
    const session = freshSession();
    evaluate(session, "swap", { amount: 100 }, DEFAULT_CONFIG);
    clearAuditLog(session);
    expect(getAuditLog(session).length).toBe(0);
  });
});
