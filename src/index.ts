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

import { evaluate, DEFAULT_CONFIG, isFinancialTool, FINANCIAL_TOOLS } from "./firewall.js";
import type { PlimsollConfig } from "./firewall.js";

interface PluginApi {
  pluginConfig?: Record<string, unknown>;
  logger: {
    info?: (...args: unknown[]) => void;
    warn?: (...args: unknown[]) => void;
    debug?: (...args: unknown[]) => void;
  };
  registerHook: (
    event: string,
    handler: (context: Record<string, unknown>) => Promise<unknown>,
    opts: { name: string; description: string },
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
  api.registerHook(
    "before_tool_call",
    async (context) => {
      const toolName = (context.toolName ?? context.tool ?? "") as string;
      if (!isFinancialTool(toolName)) return;

      const params = (context.params ?? context.args ?? {}) as Record<string, unknown>;
      const sessionKey = String(context.sessionKey ?? context.agentId ?? "default");
      const verdict = evaluate(sessionKey, toolName, params, config);

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
            ...params,
            _plimsoll_warning: verdict.reason,
          },
        };
      }
    },
    {
      name: "plimsoll-security.before-tool-call",
      description: "Financial security guard — loop detection, velocity limits, credential defense, confirmation gates",
    },
  );

  // ── Hook: after_tool_call (audit log) ─────────────────────────
  api.registerHook(
    "after_tool_call",
    async (context) => {
      const toolName = (context.toolName ?? context.tool ?? "") as string;
      if (isFinancialTool(toolName)) {
        api.logger.debug?.(`PLIMSOLL AUDIT: ${toolName} completed`);
      }
    },
    {
      name: "plimsoll-security.after-tool-call",
      description: "Audit log for completed financial tool calls",
    },
  );

  // ── Command: /plimsoll ──────────────────────────────────────
  api.registerCommand({
    name: "plimsoll",
    description: "Show Plimsoll financial guard status",
    requireAuth: true,
    handler: () => ({
      text:
        `**Plimsoll Financial Guard** — active\n\n` +
        `**Engines:**\n` +
        `- Loop detection: ${config.loopThreshold} identical calls / ${config.loopWindowSeconds}s\n` +
        `- Velocity cap: $${(config.maxVelocityCentsPerWindow / 100).toFixed(2)} / ${config.velocityWindowSeconds}s\n` +
        `- Credential guard: ETH keys, mnemonics, credit cards, SSNs, Stripe/Plaid keys\n` +
        `- Confirmation gate: $${(config.confirmationThresholdCents / 100).toFixed(2)} per-tx threshold\n` +
        `- Anomaly detection: ${config.anomalyMultiplier}x rolling average (after ${config.anomalyMinSamples} samples)\n\n` +
        `**Guarded tools:** ${Array.from(FINANCIAL_TOOLS).join(", ")}\n\n` +
        `_Powered by [Plimsoll Protocol](https://github.com/scoootscooob/plimsoll-protocol)_`,
    }),
  });
}
