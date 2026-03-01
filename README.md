# openclaw-plimsoll-security

Financial security guard for OpenClaw agents. Protects any agent that handles money — crypto, stocks, purchases, bank transfers, credit cards. Five deterministic defense engines, zero dependencies, fail-closed.

## Install

```bash
openclaw plugins install openclaw-plimsoll-security
```

## Engines

| Engine | Catches | How |
|--------|---------|-----|
| **Trajectory Hash** | Hallucination retry loops | SHA-256 fingerprint of (tool, target, amount). 3+ identical calls in 60s = hard block. |
| **Capital Velocity** | Spend-rate abuse | Sliding-window cap. Cumulative spend > $500 in 5 min = hard block. |
| **Entropy Guard** | Credential exfiltration | Blocks ETH private keys, BIP-39 mnemonics, credit card numbers (Luhn-validated), SSNs, Stripe/Plaid API keys, high-entropy blobs. |
| **Confirmation Gate** | Unauthorized large transactions | Per-transaction threshold. Single tx > $100 = hard block requiring human approval. |
| **Amount Anomaly** | Unusual spending patterns | Flags transactions 10x+ above rolling average. Catches prompt injection that inflates amounts. |

All engines are **deterministic** (no LLM calls), **zero-dependency** (only `node:crypto`), and **fail-closed**.

Non-financial tools pass through untouched.

## What it protects

- **Crypto/DeFi** — swap, transfer, bridge, stake, approve, etc.
- **Stock trading** — buy, sell, place_order, market_order, limit_order
- **Payments** — pay, purchase, checkout, charge, subscribe
- **Banking** — wire_transfer, ach_transfer, send_money, bank_transfer

Plus keyword fallback: any tool with `swap`, `transfer`, `bridge`, `buy`, `sell`, `pay`, `purchase`, `charge`, `order`, `wire`, or `send` as a standalone segment (e.g., `token_swap` matches, `swapfile` does not).

## Configuration

All settings are optional — defaults are conservative:

```json
{
  "plugins": {
    "entries": {
      "plimsoll-security": {
        "enabled": true,
        "config": {
          "maxVelocityCentsPerWindow": 50000,
          "velocityWindowSeconds": 300,
          "loopThreshold": 3,
          "loopWindowSeconds": 60,
          "confirmationThresholdCents": 10000,
          "anomalyMultiplier": 10,
          "anomalyMinSamples": 5
        }
      }
    }
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `maxVelocityCentsPerWindow` | `50000` ($500) | Max cumulative spend in a sliding window |
| `velocityWindowSeconds` | `300` (5 min) | Sliding window duration |
| `loopThreshold` | `3` | Identical calls before hard block |
| `loopWindowSeconds` | `60` (1 min) | Loop detection window |
| `confirmationThresholdCents` | `10000` ($100) | Per-tx amount requiring human approval. Set to `0` to disable. |
| `anomalyMultiplier` | `10` | Flag txs this many times above rolling avg |
| `anomalyMinSamples` | `5` | Min transactions before anomaly detection activates |

## Verdicts

Each tool call gets one of three verdicts:

- **ALLOW** — pass through, no action
- **FRICTION** — inject `_plimsoll_warning` into params, let agent decide
- **BLOCK** — hard stop with reason, agent told to pivot strategy

## Commands

- `/plimsoll` — Show guard status and current configuration

## Development

```bash
npm install
npm test
npm run build
```

## License

MIT

---

Powered by [Plimsoll Protocol](https://github.com/scoootscooob/plimsoll-protocol) — deterministic execution substrate for autonomous AI agents.
