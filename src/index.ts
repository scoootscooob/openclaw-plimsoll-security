/**
 * Plimsoll DeFi Security — Third-Party OpenClaw Plugin
 *
 * Transaction firewall for agents that handle financial operations.
 * Intercepts DeFi tool calls via before_tool_call and runs them
 * through three defense engines from the Plimsoll Protocol:
 *
 *   1. Trajectory Hash  — blocks hallucination retry loops
 *   2. Capital Velocity — enforces spend-rate limits
 *   3. Entropy Guard    — blocks private key exfiltration
 *
 * All engines are deterministic, zero-dependency, and fail-closed.
 *
 * Install: openclaw plugins install openclaw-plimsoll-security
 * Docs:    https://github.com/scoootscooob/openclaw-plimsoll-security
 */

import { evaluate, DEFAULT_CONFIG, isDefiTool, DEFI_TOOLS } from "./firewall.js";
import type { PlimsollConfig } from "./firewall.js";

// Minimal type for the plugin API — avoids hard dependency on OpenClaw internals
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
    api.logger.info?.("Plimsoll Security: disabled via config");
    return;
  }

  const config: PlimsollConfig = {
    maxVelocityCentsPerWindow:
      pluginCfg.maxVelocityCentsPerWindow ?? DEFAULT_CONFIG.maxVelocityCentsPerWindow,
    velocityWindowSeconds:
      pluginCfg.velocityWindowSeconds ?? DEFAULT_CONFIG.velocityWindowSeconds,
    loopThreshold: pluginCfg.loopThreshold ?? DEFAULT_CONFIG.loopThreshold,
    loopWindowSeconds: pluginCfg.loopWindowSeconds ?? DEFAULT_CONFIG.loopWindowSeconds,
  };

  api.logger.info?.("Plimsoll Security: active");

  // ── Hook: before_tool_call ───────────────────────────────────
  api.registerHook(
    "before_tool_call",
    async (context) => {
      const toolName = (context.toolName ?? context.tool ?? "") as string;
      if (!isDefiTool(toolName)) return;

      const params = (context.params ?? context.args ?? {}) as Record<string, unknown>;
      const sessionKey = String(context.sessionKey ?? context.agentId ?? "default");
      const verdict = evaluate(sessionKey, toolName, params, config);

      if (verdict.blocked) {
        api.logger.warn?.(`PLIMSOLL BLOCK [${verdict.engine}]: ${verdict.reason}`);
        return {
          block: true,
          blockReason:
            `[PLIMSOLL OVERRIDE] ${verdict.code}: ${verdict.reason} ` +
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
      description: "DeFi transaction firewall — loop detection, velocity limits, exfiltration defense",
    },
  );

  // ── Hook: after_tool_call (audit log) ─────────────────────────
  api.registerHook(
    "after_tool_call",
    async (context) => {
      const toolName = (context.toolName ?? context.tool ?? "") as string;
      if (isDefiTool(toolName)) {
        api.logger.debug?.(`PLIMSOLL AUDIT: ${toolName} completed`);
      }
    },
    {
      name: "plimsoll-security.after-tool-call",
      description: "Audit log for completed DeFi tool calls",
    },
  );

  // ── Command: /plimsoll ──────────────────────────────────────
  api.registerCommand({
    name: "plimsoll",
    description: "Show Plimsoll firewall status and configuration",
    requireAuth: true,
    handler: () => ({
      text:
        `**Plimsoll DeFi Security** — active\n\n` +
        `- Velocity cap: $${(config.maxVelocityCentsPerWindow / 100).toFixed(2)} / ${config.velocityWindowSeconds}s\n` +
        `- Loop threshold: ${config.loopThreshold} identical calls / ${config.loopWindowSeconds}s\n` +
        `- Entropy guard: enabled\n` +
        `- Guarded tools: ${Array.from(DEFI_TOOLS).join(", ")}\n\n` +
        `_Powered by [Plimsoll Protocol](https://github.com/scoootscooob/plimsoll-protocol)_`,
    }),
  });
}
