import { describe, it, expect } from "vitest";
import {
  evaluate, DEFAULT_CONFIG, isFinancialTool, isDefiTool,
  luhnCheck, shannonEntropy, FINANCIAL_TOOLS,
} from "./firewall.js";
import type { PlimsollConfig } from "./firewall.js";

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
