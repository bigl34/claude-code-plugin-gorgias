import { readFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  LlmEmptyResponseError,
  LlmError,
  LlmHttpError,
  LlmMalformedResponseError,
  LlmRateLimitError,
  LlmTimeoutError,
  LlmTruncatedError,
  redactSecrets,
  scrubErrorBody,
} from "./errors.js";
import { loadOpenRouterKey } from "./load-secrets.js";

export const OPENROUTER_CHAT_ENDPOINT =
  "https://openrouter.ai/api/v1/chat/completions";

const DEFAULT_BASE_BACKOFF_MS = 1_000;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_PER_REQUEST_TIMEOUT_MS = 300_000;
const RETRYABLE_STATUSES = new Set([429, 500, 502, 503, 504]);

export interface LoadOpenRouterIgnoreListDeps {
  configPath?: string;
  readFile?: (path: string) => string;
}

export interface BizProviderPolicy extends Record<string, unknown> {
  data_collection: "deny";
  zdr: true;
  ignore: string[];
}

export type OpenRouterProviderPolicy = Record<string, unknown>;

export type OpenRouterUserPart =
  | {
      type: "text";
      text: string;
    }
  | {
      type: "image";
      mimeType: string;
      base64: string;
    };

interface GenerateOpenRouterTextBaseOptions {
  model: string;
  system?: string;
  temperature?: number;
  maxOutputTokens: number;
  timeoutMs: number;
  jsonSchema?: {
    name: string;
    schema: object;
    strict?: boolean;
  };
  jsonMode?: boolean;
  reasoningEffort?: "minimal" | "low" | "medium" | "high" | "xhigh";
  title: string;
  provider?: OpenRouterProviderPolicy;
}

interface GenerateOpenRouterTextStringOptions {
  user: string;
  userParts?: never;
}

interface GenerateOpenRouterTextPartsOptions {
  user?: never;
  userParts: OpenRouterUserPart[];
}

export type GenerateOpenRouterTextOptions = GenerateOpenRouterTextBaseOptions &
  (GenerateOpenRouterTextStringOptions | GenerateOpenRouterTextPartsOptions);

export interface OpenRouterUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  reasoningTokens?: number;
  cost?: number;
  isByok?: boolean;
}

export interface GenerateOpenRouterTextResult {
  text: string;
  json?: unknown;
  usage: OpenRouterUsage;
  finishReason: string;
  servedModel: string;
  servedProvider: string;
  generationId: string;
}

export interface OpenRouterUsageLogEntry {
  model: string;
  servedModel: string;
  servedProvider: string;
  usage: OpenRouterUsage;
  title: string;
  generationId: string;
}

export interface GenerateOpenRouterTextDeps {
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  baseBackoffMs?: number;
  maxAttempts?: number;
  jitter?: (base: number) => number;
  loadKey?: () => string;
  perRequestTimeoutMs?: number;
  usageLogger?: (entry: OpenRouterUsageLogEntry) => void;
}

interface OpenRouterTextPart {
  type: "text";
  text: string;
}

interface OpenRouterImagePart {
  type: "image_url";
  image_url: {
    url: string;
  };
}

type OpenRouterContentPart = OpenRouterTextPart | OpenRouterImagePart;

interface OpenRouterMessage {
  role: "system" | "user";
  content: string | OpenRouterContentPart[];
}

interface OpenRouterChoice {
  finish_reason?: string;
  message?: {
    content?: string | null;
  };
}

interface OpenRouterResponseBody {
  id?: string;
  model?: string;
  provider?: string;
  choices?: OpenRouterChoice[];
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
    completion_tokens_details?: {
      reasoning_tokens?: number;
    };
    cost?: number;
    is_byok?: boolean;
  };
}

export function loadOpenRouterIgnoreList(
  deps?: LoadOpenRouterIgnoreListDeps,
): string[] {
  const configPath = deps?.configPath ?? defaultOpenRouterModelsPath();
  const readFile = deps?.readFile ?? defaultReadFile;
  let parsed: unknown;

  try {
    const source = readFile(configPath);
    parsed = JSON.parse(source);
  } catch (err) {
    throw new LlmError("OpenRouter provider ignore list could not be loaded", {
      cause: err,
    });
  }

  if (!isRecord(parsed)) {
    throw new LlmError("OpenRouter provider ignore list is missing or empty");
  }

  const providerPreferences = parsed.provider_preferences;

  if (!isRecord(providerPreferences)) {
    throw new LlmError("OpenRouter provider ignore list is missing or empty");
  }

  const ignore = providerPreferences.ignore;

  if (!isStringArray(ignore)) {
    throw new LlmError("OpenRouter provider ignore list is missing or empty");
  }

  const normalizedIgnore = ignore.map((provider) => provider.trim());
  const hasEmptyProvider = normalizedIgnore.some((provider) => provider === "");

  if (normalizedIgnore.length === 0 || hasEmptyProvider) {
    throw new LlmError("OpenRouter provider ignore list is missing or empty");
  }

  return normalizedIgnore;
}

export function bizProviderPolicy(
  _model: string,
  opts?: {
    ignore?: string[];
  },
): BizProviderPolicy {
  const ignore = opts?.ignore ?? loadOpenRouterIgnoreList();

  return {
    data_collection: "deny",
    zdr: true,
    ignore,
  };
}

export async function generateOpenRouterText(
  opts: GenerateOpenRouterTextOptions,
  deps?: GenerateOpenRouterTextDeps,
): Promise<GenerateOpenRouterTextResult> {
  const now = deps?.now ?? Date.now;
  const startedAt = now();
  const deadline = startedAt + opts.timeoutMs;
  const loadKey = deps?.loadKey ?? loadOpenRouterKey;
  const apiKey = loadKey();
  const fetchImpl = deps?.fetchImpl ?? globalThis.fetch;
  const sleep = deps?.sleep ?? defaultSleep;
  const baseBackoffMs = deps?.baseBackoffMs ?? DEFAULT_BASE_BACKOFF_MS;
  const maxAttempts = deps?.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const jitter = deps?.jitter ?? defaultJitter;
  const perRequestTimeoutMs =
    deps?.perRequestTimeoutMs ?? DEFAULT_PER_REQUEST_TIMEOUT_MS;
  const requestBody = buildRequestBody(opts);

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    assertTimeRemaining(deadline, now);
    const signal = createAttemptSignal(deadline, now, perRequestTimeoutMs);
    let responseReceived = false;

    try {
      const response = await fetchOpenRouter(
        fetchImpl,
        apiKey,
        opts.title,
        requestBody,
        signal,
      );
      responseReceived = true;

      if (response.ok) {
        const result = await parseSuccessResponse(response, opts);
        logUsage(result, opts, deps?.usageLogger);
        return result;
      }

      const shouldRetry = shouldRetryResponse(
        response.status,
        attempt,
        maxAttempts,
      );

      if (!shouldRetry) {
        await throwHttpError(response);
      }

      const backoffMs = computeResponseBackoff(
        response,
        attempt,
        baseBackoffMs,
        jitter,
        now,
      );
      const retryTime = now() + backoffMs;

      if (retryTime > deadline) {
        await throwHttpError(response);
      }

      await sleep(backoffMs);
    } catch (err) {
      await handleAttemptFailure(
        err,
        responseReceived,
        attempt,
        maxAttempts,
        deadline,
        now,
        sleep,
        baseBackoffMs,
        jitter,
      );
    }
  }

  throw new LlmError("OpenRouter request failed before any attempt completed");
}

function defaultOpenRouterModelsPath(): string {
  const modulePath = fileURLToPath(import.meta.url);
  const moduleDirectory = dirname(modulePath);
  const isBuiltModule = basename(moduleDirectory) === "dist";
  const packageDirectory = isBuiltModule
    ? dirname(moduleDirectory)
    : moduleDirectory;
  const configPath = resolve(
    packageDirectory,
    "../../../config/pal-mcp/openrouter_models.json",
  );
  return configPath;
}

function defaultReadFile(path: string): string {
  const source = readFileSync(path, "utf8");
  return source;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null) {
    return false;
  }

  if (typeof value !== "object") {
    return false;
  }

  return true;
}

function isStringArray(value: unknown): value is string[] {
  if (!Array.isArray(value)) {
    return false;
  }

  const allStrings = value.every((item) => typeof item === "string");
  return allStrings;
}

function buildRequestBody(
  opts: GenerateOpenRouterTextOptions,
): Record<string, unknown> {
  const messages = buildMessages(opts);
  const provider = opts.provider ?? bizProviderPolicy(opts.model);
  const responseFormat = buildResponseFormat(opts);
  const reasoning = buildReasoning(opts);
  const body: Record<string, unknown> = {
    model: opts.model,
    messages,
    max_tokens: opts.maxOutputTokens,
    provider,
    usage: {
      include: true,
    },
  };

  return {
    ...body,
    ...(opts.temperature === undefined
      ? {}
      : { temperature: opts.temperature }),
    ...(responseFormat === undefined
      ? {}
      : { response_format: responseFormat }),
    ...(reasoning === undefined ? {} : { reasoning }),
  };
}

function buildMessages(opts: GenerateOpenRouterTextOptions): OpenRouterMessage[] {
  const hasUser = opts.user !== undefined;
  const hasUserParts = opts.userParts !== undefined;

  if (hasUser === hasUserParts) {
    throw new LlmError("OpenRouter request requires exactly one user input");
  }

  const userContent = hasUser
    ? opts.user
    : buildUserParts(opts.userParts ?? []);
  const userMessage: OpenRouterMessage = {
    role: "user",
    content: userContent,
  };

  if (opts.system === undefined) {
    return [userMessage];
  }

  const systemMessage: OpenRouterMessage = {
    role: "system",
    content: opts.system,
  };
  return [systemMessage, userMessage];
}

function buildUserParts(parts: OpenRouterUserPart[]): OpenRouterContentPart[] {
  return parts.map((part) => {
    if (part.type === "text") {
      return {
        type: "text",
        text: part.text,
      };
    }

    if (!part.mimeType.startsWith("image/")) {
      throw new LlmError(
        `OpenRouter image part has unsupported MIME type: ${part.mimeType}`,
      );
    }

    const url = `data:${part.mimeType};base64,${part.base64}`;
    return {
      type: "image_url",
      image_url: {
        url,
      },
    };
  });
}

function buildResponseFormat(
  opts: GenerateOpenRouterTextOptions,
): Record<string, unknown> | undefined {
  if (opts.jsonSchema !== undefined) {
    return {
      type: "json_schema",
      json_schema: {
        name: opts.jsonSchema.name,
        strict: opts.jsonSchema.strict,
        schema: opts.jsonSchema.schema,
      },
    };
  }

  if (opts.jsonMode === true) {
    return {
      type: "json_object",
    };
  }

  return undefined;
}

function buildReasoning(
  opts: GenerateOpenRouterTextOptions,
): Record<string, unknown> | undefined {
  if (opts.reasoningEffort === undefined) {
    return undefined;
  }

  return {
    effort: opts.reasoningEffort,
  };
}

function assertTimeRemaining(deadline: number, now: () => number): void {
  const remainingMs = deadline - now();

  if (remainingMs <= 0) {
    throw new LlmTimeoutError(
      "OpenRouter request timed out before attempt started",
    );
  }
}

function createAttemptSignal(
  deadline: number,
  now: () => number,
  perRequestTimeoutMs: number,
): AbortSignal {
  const remainingMs = deadline - now();

  if (remainingMs <= 0) {
    throw new LlmTimeoutError(
      "OpenRouter request timed out before fetch started",
    );
  }

  const attemptTimeoutMs = Math.min(remainingMs, perRequestTimeoutMs);
  const integerTimeoutMs = Math.max(1, Math.floor(attemptTimeoutMs));
  const signal = AbortSignal.timeout(integerTimeoutMs);
  return signal;
}

async function fetchOpenRouter(
  fetchImpl: typeof fetch,
  apiKey: string,
  title: string,
  requestBody: Record<string, unknown>,
  signal: AbortSignal,
): Promise<Response> {
  const headers = {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
    "X-Title": `biz/${title}`,
  };
  const body = JSON.stringify(requestBody);
  const response = await fetchImpl(OPENROUTER_CHAT_ENDPOINT, {
    method: "POST",
    headers,
    body,
    signal,
  });
  return response;
}

async function parseSuccessResponse(
  response: Response,
  opts: GenerateOpenRouterTextOptions,
): Promise<GenerateOpenRouterTextResult> {
  const body = (await response.json()) as OpenRouterResponseBody;
  const choice = body.choices?.[0];
  const finishReason = choice?.finish_reason ?? "";
  const content = choice?.message?.content ?? "";
  const usage = parseUsage(body);
  const errorUsage = buildUsageEntry(body, opts, usage);

  if (finishReason === "length") {
    const error = new LlmTruncatedError(
      "OpenRouter response was truncated",
      finishReason,
    );
    throw attachErrorUsage(error, errorUsage);
  }

  if (content.trim() === "") {
    const error = new LlmEmptyResponseError("OpenRouter returned an empty response");
    throw attachErrorUsage(error, errorUsage);
  }

  let json: unknown;
  try {
    json = parseStructuredContent(content, opts);
  } catch (err) {
    if (err instanceof LlmError) {
      throw attachErrorUsage(err, errorUsage);
    }
    throw err;
  }

  return {
    text: content,
    ...(json === undefined ? {} : { json }),
    usage,
    finishReason,
    servedModel: body.model ?? "",
    servedProvider: body.provider ?? "",
    generationId: body.id ?? "",
  };
}

function parseUsage(body: OpenRouterResponseBody): OpenRouterUsage {
  const promptTokens = body.usage?.prompt_tokens ?? 0;
  const completionTokens = body.usage?.completion_tokens ?? 0;
  const totalTokens = body.usage?.total_tokens ?? 0;
  const reasoningTokens =
    body.usage?.completion_tokens_details?.reasoning_tokens;
  const cost = body.usage?.cost;
  const isByok = body.usage?.is_byok;
  const usage: OpenRouterUsage = {
    promptTokens,
    completionTokens,
    totalTokens,
    ...(reasoningTokens === undefined ? {} : { reasoningTokens }),
    ...(cost === undefined ? {} : { cost }),
    ...(isByok === undefined ? {} : { isByok }),
  };
  return usage;
}

function buildUsageEntry(
  body: OpenRouterResponseBody,
  opts: GenerateOpenRouterTextOptions,
  usage: OpenRouterUsage,
): OpenRouterUsageLogEntry {
  return {
    model: opts.model,
    servedModel: body.model ?? "",
    servedProvider: body.provider ?? "",
    usage,
    title: opts.title,
    generationId: body.id ?? "",
  };
}

function attachErrorUsage<T extends LlmError>(
  error: T,
  usage: OpenRouterUsageLogEntry,
): T & { openRouterUsage: OpenRouterUsageLogEntry } {
  const enrichedError = Object.assign(error, {
    openRouterUsage: usage,
  });
  return enrichedError;
}

function parseStructuredContent(
  content: string,
  opts: GenerateOpenRouterTextOptions,
): unknown {
  const expectsJson = opts.jsonSchema !== undefined || opts.jsonMode === true;

  if (!expectsJson) {
    return undefined;
  }

  try {
    const value: unknown = JSON.parse(content);
    return value;
  } catch (err) {
    throw new LlmMalformedResponseError(
      "OpenRouter returned malformed JSON",
      {
        cause: err,
      },
    );
  }
}

function logUsage(
  result: GenerateOpenRouterTextResult,
  opts: GenerateOpenRouterTextOptions,
  usageLogger?: (entry: OpenRouterUsageLogEntry) => void,
): void {
  if (usageLogger === undefined) {
    return;
  }

  const entry: OpenRouterUsageLogEntry = {
    model: opts.model,
    servedModel: result.servedModel,
    servedProvider: result.servedProvider,
    usage: result.usage,
    title: opts.title,
    generationId: result.generationId,
  };
  usageLogger(entry);
}

function shouldRetryResponse(
  status: number,
  attempt: number,
  maxAttempts: number,
): boolean {
  const isRetryable = RETRYABLE_STATUSES.has(status);
  const hasAttemptsRemaining = attempt < maxAttempts;
  const shouldRetry = isRetryable && hasAttemptsRemaining;
  return shouldRetry;
}

function computeResponseBackoff(
  response: Response,
  attempt: number,
  baseBackoffMs: number,
  jitter: (base: number) => number,
  now: () => number,
): number {
  const retryAfter = response.headers.get("retry-after");
  const retryAfterMs = parseRetryAfterMs(retryAfter, now);

  if (retryAfterMs !== null) {
    return retryAfterMs;
  }

  const exponentialBackoff = computeExponentialBackoff(
    attempt,
    baseBackoffMs,
  );
  const jitteredBackoff = jitter(exponentialBackoff);
  return jitteredBackoff;
}

function parseRetryAfterMs(
  value: string | null,
  now: () => number,
): number | null {
  if (value === null) {
    return null;
  }

  const numericSeconds = Number(value);
  const isNumeric = Number.isFinite(numericSeconds);

  if (isNumeric) {
    const numericMs = numericSeconds * 1_000;
    const flooredMs = Math.max(0, numericMs);
    return flooredMs;
  }

  const dateMs = Date.parse(value);
  const isValidDate = Number.isFinite(dateMs);

  if (!isValidDate) {
    return null;
  }

  const delayMs = dateMs - now();
  const flooredMs = Math.max(0, delayMs);
  return flooredMs;
}

function computeExponentialBackoff(
  attempt: number,
  baseBackoffMs: number,
): number {
  const exponent = attempt - 1;
  const multiplier = 2 ** exponent;
  const backoff = baseBackoffMs * multiplier;
  return backoff;
}

async function handleAttemptFailure(
  err: unknown,
  responseReceived: boolean,
  attempt: number,
  maxAttempts: number,
  deadline: number,
  now: () => number,
  sleep: (ms: number) => Promise<void>,
  baseBackoffMs: number,
  jitter: (base: number) => number,
): Promise<void> {
  if (err instanceof LlmError) {
    throw err;
  }

  const deadlinePassed = now() >= deadline;
  const timedOut = isTimeoutError(err) || deadlinePassed;

  if (timedOut) {
    throw new LlmTimeoutError("OpenRouter request timed out", {
      cause: err,
    });
  }

  if (responseReceived) {
    throw err;
  }

  const hasAttemptsRemaining = attempt < maxAttempts;

  if (!hasAttemptsRemaining) {
    throwNetworkError(err);
  }

  const exponentialBackoff = computeExponentialBackoff(
    attempt,
    baseBackoffMs,
  );
  const backoffMs = jitter(exponentialBackoff);
  const retryTime = now() + backoffMs;

  if (retryTime > deadline) {
    throwNetworkError(err);
  }

  await sleep(backoffMs);
}

function isTimeoutError(err: unknown): boolean {
  if (!isObjectWithName(err)) {
    return false;
  }

  if (err.name === "AbortError") {
    return true;
  }

  if (err.name === "TimeoutError") {
    return true;
  }

  return false;
}

function isObjectWithName(value: unknown): value is { name: string } {
  if (value === null) {
    return false;
  }

  if (typeof value !== "object") {
    return false;
  }

  if (!("name" in value)) {
    return false;
  }

  const namedValue = value as { name: unknown };
  const isStringName = typeof namedValue.name === "string";
  return isStringName;
}

function throwNetworkError(err: unknown): never {
  const message = getErrorMessage(err);
  const redactedMessage = redactSecrets(message);
  throw new LlmError(`OpenRouter request failed: ${redactedMessage}`, {
    cause: err,
  });
}

function getErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }

  const text = String(err);
  return text;
}

async function throwHttpError(response: Response): Promise<never> {
  const bodyText = await formatErrorBody(response);
  const message = buildHttpErrorMessage(response.status, bodyText);

  if (response.status === 429) {
    throw new LlmRateLimitError(message, {
      status: response.status,
      url: OPENROUTER_CHAT_ENDPOINT,
    });
  }

  throw new LlmHttpError(message, response.status, {
    url: OPENROUTER_CHAT_ENDPOINT,
  });
}

async function formatErrorBody(response: Response): Promise<string> {
  const rawText = await response.text();
  const trimmedText = rawText.trim();

  if (trimmedText === "") {
    return "";
  }

  const parsed = parseJson(trimmedText);

  if (parsed.ok) {
    const scrubbed = scrubErrorBody(parsed.value);
    const serialized = JSON.stringify(scrubbed);
    const redacted = redactSecrets(serialized);
    return redacted;
  }

  const redacted = redactSecrets(trimmedText);
  return redacted;
}

interface JsonParseResult {
  ok: boolean;
  value?: unknown;
}

function parseJson(text: string): JsonParseResult {
  try {
    const value: unknown = JSON.parse(text);
    return {
      ok: true,
      value,
    };
  } catch {
    return {
      ok: false,
    };
  }
}

function buildHttpErrorMessage(status: number, bodyText: string): string {
  if (bodyText === "") {
    return `OpenRouter API ${status}`;
  }

  return `OpenRouter API ${status}: ${bodyText}`;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, ms);
  });
}

function defaultJitter(base: number): number {
  const multiplier = 0.8 + Math.random() * 0.4;
  const jittered = base * multiplier;
  return jittered;
}
