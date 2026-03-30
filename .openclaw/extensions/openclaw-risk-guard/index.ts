import http from "node:http";
import https from "node:https";
import fs from "node:fs";

type ApprovalDecision = "allow-once" | "allow-always" | "deny" | "timeout" | "cancelled";

type ExtensionConfig = {
  baseUrl?: string;
  riskGuardBaseUrl?: string;
  requestTimeoutMs?: number;
  approvalTimeoutMs?: number;
  approvalTimeoutBehavior?: "deny" | "cancel";
  failOpen?: boolean;
};

type EvaluateResponse = {
  decision: "allow" | "confirm" | "block";
  severity: "info" | "warning" | "critical";
  summary: string;
  user_message: string;
  confirmation_id?: string;
  confirmation_ttl_seconds?: number;
  policy_version?: string;
};

type ToolCallPayload = {
  tool_name: string;
  params: Record<string, unknown>;
  source: string;
  namespace?: string;
  user_prompt: string;
  session_id?: string;
  actor_id?: string;
  raw_event?: Record<string, unknown>;
};

const DEFAULT_BASE_URL = "http://127.0.0.1:8099";
const DEFAULT_REQUEST_TIMEOUT_MS = 3000;
const DEFAULT_APPROVAL_TIMEOUT_MS = 120000;
const DEBUG_EVENT_LOG = "/tmp/openclaw-risk-guard-event.jsonl";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeText(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function firstText(...values: unknown[]): string {
  for (const value of values) {
    const text = safeText(value);
    if (text) {
      return text;
    }
  }
  return "";
}

function extractMessageText(message: unknown): string {
  if (typeof message === "string") {
    return message;
  }
  if (!isRecord(message)) {
    return "";
  }
  return firstText(
    message.content,
    message.text,
    message.prompt,
    message.message,
    message.body,
  );
}

function lastMessageText(messages: unknown): string {
  if (!Array.isArray(messages)) {
    return "";
  }
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const text = extractMessageText(messages[index]);
    if (text) {
      return text;
    }
  }
  return "";
}

function pickRecord(...values: unknown[]): Record<string, unknown> | undefined {
  for (const value of values) {
    if (isRecord(value)) {
      return value as Record<string, unknown>;
    }
  }
  return undefined;
}

function getEnv(name: string): string | undefined {
  const proc = (globalThis as any).process;
  return proc?.env?.[name];
}

function safeSerialize(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return JSON.stringify({ error: "serialization_failed" });
  }
}

function appendDebugEvent(stage: string, event: unknown, payload?: unknown): void {
  const record = {
    ts: new Date().toISOString(),
    stage,
    event,
    payload,
  };
  try {
    fs.appendFileSync(DEBUG_EVENT_LOG, `${safeSerialize(record)}\n`, "utf8");
  } catch {
    return;
  }
}

function resolveConfig(api: any): Required<Pick<ExtensionConfig, "baseUrl" | "requestTimeoutMs" | "approvalTimeoutMs" | "approvalTimeoutBehavior" | "failOpen">> {
  const rawConfig = api?.getConfig?.();
  const config = isRecord(rawConfig) ? (rawConfig as ExtensionConfig) : {};
  return {
    baseUrl: config.baseUrl || config.riskGuardBaseUrl || getEnv("RISK_GUARD_BASE_URL") || DEFAULT_BASE_URL,
    requestTimeoutMs: config.requestTimeoutMs || Number(getEnv("RISK_GUARD_REQUEST_TIMEOUT_MS") || DEFAULT_REQUEST_TIMEOUT_MS),
    approvalTimeoutMs: config.approvalTimeoutMs || Number(getEnv("RISK_GUARD_APPROVAL_TIMEOUT_MS") || DEFAULT_APPROVAL_TIMEOUT_MS),
    approvalTimeoutBehavior: config.approvalTimeoutBehavior || "deny",
    failOpen: config.failOpen || false,
  };
}

async function postJson(url: string, payload: unknown, timeoutMs: number): Promise<any> {
  const target = new URL(url);
  const transport = target.protocol === "https:" ? https : http;
  const body = JSON.stringify(payload);
  const contentLength = Buffer.byteLength(body);

  return new Promise((resolve, reject) => {
    const req = transport.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port ? Number(target.port) : undefined,
        path: `${target.pathname}${target.search}`,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": String(contentLength),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          if ((res.statusCode || 500) >= 400) {
            reject(new Error(`risk guard request failed: ${res.statusCode || 500}`));
            return;
          }
          try {
            resolve(body ? JSON.parse(body) : {});
          } catch (error) {
            reject(error);
          }
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("risk guard request timed out"));
    });

    req.on("error", (error) => {
      reject(error);
    });

    req.write(body);
    req.end();
  });
}

function candidateBaseUrls(baseUrl: string): string[] {
  const candidates = [baseUrl];
  if (baseUrl.includes("127.0.0.1")) {
    candidates.push(baseUrl.replace("127.0.0.1", "localhost"));
  } else if (baseUrl.includes("localhost")) {
    candidates.push(baseUrl.replace("localhost", "127.0.0.1"));
  }
  return Array.from(new Set(candidates));
}

async function postJsonWithFallback(baseUrl: string, path: string, payload: unknown, timeoutMs: number): Promise<any> {
  let lastError: unknown;
  for (const candidate of candidateBaseUrls(baseUrl)) {
    try {
      return await postJson(`${candidate}${path}`, payload, timeoutMs);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("risk guard request failed");
}

function extractToolName(event: any): string {
  return firstText(
    event?.tool?.name,
    event?.tool?.toolName,
    event?.toolName,
    event?.tool?.id,
    event?.tool?.slug,
    event?.call?.tool?.name,
    event?.request?.tool?.name,
    event?.name,
    event?.call?.tool_name,
    event?.call?.name,
    event?.request?.tool_name,
    event?.request?.name,
  ) || "unknown_tool";
}

function extractParams(event: any): Record<string, unknown> {
  return (
    pickRecord(
      event?.params,
      event?.arguments,
      event?.args,
      event?.toolInput,
      event?.input?.params,
      event?.input?.arguments,
      event?.tool?.input,
      event?.call?.arguments,
      event?.call?.params,
      event?.call?.input,
      event?.request?.params,
      event?.request?.arguments,
      event?.request?.input,
    ) || {}
  );
}

function normalizeSource(event: any): string {
  const source = String(
    firstText(
      event?.tool?.source,
      event?.tool?.kind,
      event?.source,
      event?.call?.source,
      event?.request?.source,
      event?.provider,
    ),
  ).toLowerCase();
  if (source.includes("mcp")) {
    return "mcp";
  }
  if (source.includes("skill")) {
    return "skill";
  }
  return "tool";
}

function extractPrompt(event: any): string {
  return firstText(
    event?.context?.prompt,
    event?.context?.userPrompt,
    event?.context?.message,
    lastMessageText(event?.context?.messages),
    event?.input?.prompt,
    event?.input?.message,
    lastMessageText(event?.input?.messages),
    event?.request?.prompt,
    event?.request?.message,
    lastMessageText(event?.request?.messages),
    event?.call?.prompt,
    event?.call?.message,
    lastMessageText(event?.call?.messages),
    event?.userPrompt,
    event?.message,
    lastMessageText(event?.messages),
  );
}

function extractSessionId(event: any): string | undefined {
  return firstText(
    event?.context?.sessionId,
    event?.sessionId,
    event?.request?.sessionId,
    event?.session?.id,
  ) || undefined;
}

function extractActorId(event: any): string | undefined {
  return firstText(
    event?.context?.actorId,
    event?.actorId,
    event?.request?.actorId,
    event?.actor?.id,
  ) || undefined;
}

function summarizeEvent(event: any): Record<string, unknown> {
  const summary: Record<string, unknown> = {
    trace: {
      runId: safeText(event?.runId),
      toolCallId: safeText(event?.toolCallId),
      sessionId: extractSessionId(event) || "",
      actorId: extractActorId(event) || "",
    },
    tool_name_candidates: {
      tool_name: safeText(event?.tool?.name),
      tool_toolName: safeText(event?.tool?.toolName),
      toolName: safeText(event?.toolName),
      tool_id: safeText(event?.tool?.id),
      call_tool_name_nested: safeText(event?.call?.tool?.name),
      request_tool_name_nested: safeText(event?.request?.tool?.name),
      name: safeText(event?.name),
      call_tool_name: safeText(event?.call?.tool_name),
      request_tool_name: safeText(event?.request?.tool_name),
    },
    prompt_candidates: {
      context_prompt: safeText(event?.context?.prompt),
      context_userPrompt: safeText(event?.context?.userPrompt),
      context_message: safeText(event?.context?.message),
      input_prompt: safeText(event?.input?.prompt),
      input_message: safeText(event?.input?.message),
      request_prompt: safeText(event?.request?.prompt),
      request_message: safeText(event?.request?.message),
      message: safeText(event?.message),
      context_messages_last: lastMessageText(event?.context?.messages),
      input_messages_last: lastMessageText(event?.input?.messages),
      request_messages_last: lastMessageText(event?.request?.messages),
      messages_last: lastMessageText(event?.messages),
    },
    params_candidates: {
      params: isRecord(event?.params),
      arguments: isRecord(event?.arguments),
      args: isRecord(event?.args),
      toolInput: isRecord(event?.toolInput),
      input_params: isRecord(event?.input?.params),
      input_arguments: isRecord(event?.input?.arguments),
      tool_input: isRecord(event?.tool?.input),
      call_arguments: isRecord(event?.call?.arguments),
      call_params: isRecord(event?.call?.params),
      call_input: isRecord(event?.call?.input),
      request_params: isRecord(event?.request?.params),
      request_arguments: isRecord(event?.request?.arguments),
      request_input: isRecord(event?.request?.input),
    },
    source_candidates: {
      tool_source: safeText(event?.tool?.source),
      tool_kind: safeText(event?.tool?.kind),
      source: safeText(event?.source),
      request_source: safeText(event?.request?.source),
    },
  };
  return summary;
}

function approvalTitle(toolName: string): string {
  if (toolName === "web_search") {
    return "外部搜索待确认";
  }
  if (toolName === "sessions_send") {
    return "消息发送待确认";
  }
  return "高风险工具调用待确认";
}

export default function register(api: any) {
  const config = resolveConfig(api);

  api.on("before_tool_call", async (event: any) => {
    const payload: ToolCallPayload = {
      tool_name: extractToolName(event),
      params: extractParams(event),
      source: normalizeSource(event),
      namespace: event?.tool?.namespace || undefined,
      user_prompt: extractPrompt(event),
      session_id: extractSessionId(event),
      actor_id: extractActorId(event),
      raw_event: summarizeEvent(event),
    };
    appendDebugEvent("before_tool_call", event, payload);

    let result: EvaluateResponse;
    try {
      result = (await postJsonWithFallback(config.baseUrl, "/v1/evaluate", payload, config.requestTimeoutMs)) as EvaluateResponse;
    } catch (error) {
      if (config.failOpen) {
        return undefined;
      }
      const message = error instanceof Error ? error.message : "risk guard unavailable";
      return {
        block: true,
        blockReason: `风险判定服务不可用，已按安全默认阻断。${message}`,
      };
    }

    if (result.decision === "block") {
      return {
        block: true,
        blockReason: result.user_message,
      };
    }

    if (result.decision === "confirm") {
      return {
        requireApproval: {
          title: approvalTitle(payload.tool_name),
          description: result.user_message,
          severity: result.severity,
          timeoutMs: config.approvalTimeoutMs,
          timeoutBehavior: config.approvalTimeoutBehavior,
          onResolution: async (decision: ApprovalDecision) => {
            if (!result.confirmation_id) {
              return;
            }
            await postJsonWithFallback(
              config.baseUrl,
              "/v1/confirm",
              {
                confirmation_id: result.confirmation_id,
                decision,
              },
              config.requestTimeoutMs,
            );
          },
        },
      };
    }

    return undefined;
  });
}
