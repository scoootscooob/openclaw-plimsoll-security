/**
 * Plimsoll Financial Guard — Third-Party OpenClaw Plugin
 *
 * Protects any agent that handles money: crypto, stocks, purchases,
 * bank transfers, credit cards. Five deterministic defense engines:
 *
 *   1. Trajectory Hash      — blocks hallucination retry loops
 *   2. Capital Velocity     — enforces spend-rate limits
 *   3. Entropy Guard        — blocks credential exfiltration
 *   4. Confirmation Gate    — requires approval for high-value txs
 *   5. Amount Anomaly       — flags statistical outliers
 *
 * Install: openclaw plugins install openclaw-plimsoll-security
 * Docs:    https://github.com/scoootscooob/openclaw-plimsoll-security
 */

import { evaluate, DEFAULT_CONFIG, isFinancialTool, FINANCIAL_TOOLS, getAuditLog, verifyAuditChain } from "./firewall.js";
import type { PlimsollConfig } from "./firewall.js";

// ── Minimal type stubs matching OpenClaw's plugin API ────────────
// These mirror the shapes from src/plugins/types.ts without importing
// OpenClaw internals, so the plugin stays zero-dependency.

interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

interface ToolContext {
  agentId?: string;
  sessionKey?: string;
  toolName: string;
}

interface BeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
}

interface AfterToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  result?: unknown;
  error?: string;
  durationMs?: number;
}

interface PluginApi {
  pluginConfig?: Record<string, unknown>;
  logger: {
    info?: (...args: unknown[]) => void;
    warn?: (...args: unknown[]) => void;
    debug?: (...args: unknown[]) => void;
  };
  /** Typed lifecycle hook registration — used for before_tool_call, after_tool_call, etc. */
  on: (
    hookName: string,
    handler: (...args: any[]) => any,
    opts?: { priority?: number },
  ) => void;
  registerCommand: (cmd: {
    name: string;
    description: string;
    requireAuth?: boolean;
    handler: (ctx: Record<string, unknown>) => { text: string } | Promise<{ text: string }>;
  }) => void;
}

export default function register(api: PluginApi) {
  const pluginCfg = (api.pluginConfig ?? {}) as Partial<PlimsollConfig & { enabled: boolean }>;

  if (pluginCfg.enabled === false) {
    api.logger.info?.("Plimsoll Financial Guard: disabled via config");
    return;
  }

  const config: PlimsollConfig = {
    maxVelocityCentsPerWindow:
      pluginCfg.maxVelocityCentsPerWindow ?? DEFAULT_CONFIG.maxVelocityCentsPerWindow,
    velocityWindowSeconds:
      pluginCfg.velocityWindowSeconds ?? DEFAULT_CONFIG.velocityWindowSeconds,
    loopThreshold: pluginCfg.loopThreshold ?? DEFAULT_CONFIG.loopThreshold,
    loopWindowSeconds: pluginCfg.loopWindowSeconds ?? DEFAULT_CONFIG.loopWindowSeconds,
    confirmationThresholdCents:
      pluginCfg.confirmationThresholdCents ?? DEFAULT_CONFIG.confirmationThresholdCents,
    anomalyMultiplier: pluginCfg.anomalyMultiplier ?? DEFAULT_CONFIG.anomalyMultiplier,
    anomalyMinSamples: pluginCfg.anomalyMinSamples ?? DEFAULT_CONFIG.anomalyMinSamples,
  };

  api.logger.info?.("Plimsoll Financial Guard: active");

  // ── Hook: before_tool_call ───────────────────────────────────
  // Uses api.on() for typed plugin hooks (NOT api.registerHook which
  // is for internal event hooks like command:new / message:received).
  api.on(
    "before_tool_call",
    (event: BeforeToolCallEvent, ctx: ToolContext): BeforeToolCallResult | void => {
      if (!isFinancialTool(event.toolName)) return;

      const sessionKey = ctx.sessionKey ?? ctx.agentId ?? "default";
      const verdict = evaluate(sessionKey, event.toolName, event.params, config);

      if (verdict.blocked) {
        api.logger.warn?.(`PLIMSOLL BLOCK [${verdict.engine}]: ${verdict.reason}`);
        return {
          block: true,
          blockReason:
            `[PLIMSOLL] ${verdict.code}: ${verdict.reason} ` +
            `Do not retry. Pivot strategy.`,
        };
      }

      if (verdict.friction) {
        api.logger.info?.(`PLIMSOLL FRICTION [${verdict.engine}]: ${verdict.reason}`);
        return {
          params: {
            ...event.params,
            _plimsoll_warning: verdict.reason,
          },
        };
      }
    },
  );

  // ── Hook: after_tool_call (audit log) ─────────────────────────
  api.on(
    "after_tool_call",
    (event: AfterToolCallEvent, _ctx: ToolContext): void => {
      if (isFinancialTool(event.toolName)) {
        api.logger.debug?.(
          `PLIMSOLL AUDIT: ${event.toolName} completed` +
          (event.durationMs != null ? ` (${event.durationMs}ms)` : "") +
          (event.error ? ` [error: ${event.error}]` : ""),
        );
      }
    },
  );

  // ── Command: /plimsoll ──────────────────────────────────────
  api.registerCommand({
    name: "plimsoll",
    description: "Show Plimsoll financial guard status",
    requireAuth: true,
    handler: (ctx) => {
      const sessionKey = String((ctx as Record<string, unknown>).sessionKey ?? "default");
      const log = getAuditLog(sessionKey);
      const chainStatus = verifyAuditChain(sessionKey);
      const blocks = log.filter((e) => e.code.startsWith("BLOCK_")).length;
      const frictions = log.filter((e) => e.code.startsWith("FRICTION_")).length;

      return {
        text:
          `**Plimsoll Financial Guard** — active\n\n` +
          `**Engines:**\n` +
          `- Loop detection: ${config.loopThreshold} identical calls / ${config.loopWindowSeconds}s\n` +
          `- Velocity cap: $${(config.maxVelocityCentsPerWindow / 100).toFixed(2)} / ${config.velocityWindowSeconds}s\n` +
          `- Credential guard: ETH keys, mnemonics, credit cards, SSNs, Stripe/Plaid keys\n` +
          `- Confirmation gate: $${(config.confirmationThresholdCents / 100).toFixed(2)} per-tx threshold\n` +
          `- Anomaly detection: ${config.anomalyMultiplier}x rolling average (after ${config.anomalyMinSamples} samples)\n\n` +
          `**Audit trail:** ${log.length} entries | ${blocks} blocks | ${frictions} frictions | chain ${chainStatus === -1 ? "valid" : `BROKEN at #${chainStatus}`}\n\n` +
          `**Guarded tools:** ${Array.from(FINANCIAL_TOOLS).join(", ")}\n\n` +
          `_Powered by [Plimsoll Protocol](https://github.com/scoootscooob/plimsoll-protocol)_`,
      };
    },
  });
}
