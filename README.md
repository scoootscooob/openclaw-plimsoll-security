# openclaw-plimsoll-security

Transaction firewall for OpenClaw agents that handle DeFi operations. Intercepts tool calls (`swap`, `transfer`, `bridge`, etc.) and runs them through three deterministic defense engines before execution.

## Install

```bash
openclaw plugins install openclaw-plimsoll-security
```

## What it does

| Engine | Catches | How |
|--------|---------|-----|
| **Trajectory Hash** | Hallucination retry loops | SHA-256 fingerprint of (tool, target, amount). 3+ identical calls in 60s = hard block. |
| **Capital Velocity** | Spend-rate abuse | Sliding-window cap. Cumulative spend > $500 in 5 min = hard block. |
| **Entropy Guard** | Private key exfiltration | Regex + Shannon entropy. Blocks ETH keys, BIP-39 mnemonics, high-entropy blobs in tool params. |

All engines are **deterministic** (no LLM calls), **zero-dependency** (only `node:crypto`), and **fail-closed** (blocks if uncertain).

Non-DeFi tools pass through untouched.

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
          "loopWindowSeconds": 60
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

## Commands

- `/plimsoll` — Show firewall status and current configuration

## How it works

The plugin registers a `before_tool_call` hook. When a DeFi tool is called:

1. **Tool classification** — Two-tier: exact match against known DeFi tools, then segment-aware keyword regex for plugin-registered tools (e.g., `token_swap`, `cross_chain_bridge`).

2. **Three engines evaluate in order** — first block wins:
   - Trajectory Hash checks for repeated identical calls
   - Capital Velocity checks cumulative spend rate
   - Entropy Guard scans string parameters for secrets

3. **Verdict** — `ALLOW` (pass through), `FRICTION` (inject warning, let agent decide), or `BLOCK` (hard stop with reason).

State is per-session (keyed by `sessionKey`) with LRU eviction at 1000 sessions. One agent's activity never affects another.

## Guarded tools

Exact matches: `swap`, `transfer`, `approve`, `bridge`, `stake`, `unstake`, `deposit`, `withdraw`, `borrow`, `repay`, `lend`, `supply`, `send`, `send_transaction`

Keyword fallback matches tools with `swap`, `transfer`, or `bridge` as standalone segments (e.g., `token_swap` matches, `swapfile` does not).

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
