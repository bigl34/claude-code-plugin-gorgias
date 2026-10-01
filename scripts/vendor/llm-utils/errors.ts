const BEARER_SECRET_PATTERN = /\bBearer\s+[A-Za-z0-9._~+/\-]+={0,}(?=$|[^A-Za-z0-9._~+/=\-])/gi;
const OPENAI_KEY_PATTERN = /sk-[A-Za-z0-9_\-]{20,}/g;
const SECRET_KEY_PATTERN = /key|token|secret|auth/i;

export function redactSecrets(text: string): string {
  const bearerRedacted = text.replace(BEARER_SECRET_PATTERN, "Bearer ***REDACTED***");
  const keyRedacted = bearerRedacted.replace(OPENAI_KEY_PATTERN, "***REDACTED***");
  return keyRedacted;
}

export function scrubErrorBody(value: unknown): unknown {
  if (Array.isArray(value)) {
    const scrubbedItems = value.map((item) => scrubErrorBody(item));
    return scrubbedItems;
  }

  if (!isJsonObject(value)) {
    return value;
  }

  const scrubbed: Record<string, unknown> = {};
  const entries = Object.entries(value);

  for (const [key, nestedValue] of entries) {
    const isSecretKey = SECRET_KEY_PATTERN.test(key);

    if (isSecretKey) {
      continue;
    }

    const scrubbedValue = scrubErrorBody(nestedValue);
    scrubbed[key] = scrubbedValue;
  }

  return scrubbed;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  if (value === null) {
    return false;
  }

  if (typeof value !== "object") {
    return false;
  }

  return true;
}

interface LlmErrorOptions {
  status?: number;
  url?: string;
  cause?: unknown;
}

export class LlmError extends Error {
  status?: number;
  url?: string;

  constructor(message: string, opts?: LlmErrorOptions) {
    const redactedMessage = redactSecrets(message);
    super(redactedMessage);

    this.name = "LlmError";
    this.status = opts?.status;

    if (opts?.url !== undefined) {
      this.url = redactSecrets(opts.url);
    }

    if (opts?.cause !== undefined) {
      this.cause = sanitizeCause(opts.cause);
    }

    if (this.stack !== undefined) {
      this.stack = redactSecrets(this.stack);
    }
  }
}

function sanitizeCause(value: unknown): unknown {
  if (typeof value === "string") {
    return redactSecrets(value);
  }

  if (value instanceof Error) {
    return sanitizeErrorCause(value);
  }

  const scrubbed = scrubErrorBody(value);
  const redacted = redactStoredStrings(scrubbed);
  return redacted;
}

function sanitizeErrorCause(error: Error): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {
    name: redactSecrets(error.name),
    message: redactSecrets(error.message),
  };

  if (error.stack !== undefined) {
    sanitized.stack = redactSecrets(error.stack);
  }

  return sanitized;
}

function redactStoredStrings(value: unknown): unknown {
  if (typeof value === "string") {
    return redactSecrets(value);
  }

  if (Array.isArray(value)) {
    const redactedItems = value.map((item) => redactStoredStrings(item));
    return redactedItems;
  }

  if (!isJsonObject(value)) {
    return value;
  }

  const redacted: Record<string, unknown> = {};
  const entries = Object.entries(value);

  for (const [key, nestedValue] of entries) {
    const redactedValue = redactStoredStrings(nestedValue);
    redacted[key] = redactedValue;
  }

  return redacted;
}

export class LlmRateLimitError extends LlmError {
  constructor(message: string, opts?: LlmErrorOptions) {
    super(message, opts);
    this.name = "LlmRateLimitError";
  }
}

export class LlmTimeoutError extends LlmError {
  constructor(message: string, opts?: LlmErrorOptions) {
    super(message, opts);
    this.name = "LlmTimeoutError";
  }
}

export class LlmTruncatedError extends LlmError {
  finishReason: string;

  constructor(message: string, finishReason: string, opts?: LlmErrorOptions) {
    super(message, opts);
    this.name = "LlmTruncatedError";
    this.finishReason = finishReason;
  }
}

export class LlmHttpError extends LlmError {
  status: number;

  constructor(message: string, status: number, opts?: Omit<LlmErrorOptions, "status">) {
    const mergedOptions = {
      ...opts,
      status,
    };
    super(message, mergedOptions);
    this.name = "LlmHttpError";
    this.status = status;
  }
}

export class LlmMissingKeyError extends LlmError {
  constructor(message: string, opts?: LlmErrorOptions) {
    super(message, opts);
    this.name = "LlmMissingKeyError";
  }
}

export class LlmEmptyResponseError extends LlmError {
  constructor(message: string, opts?: LlmErrorOptions) {
    super(message, opts);
    this.name = "LlmEmptyResponseError";
  }
}

export class LlmMalformedResponseError extends LlmError {
  constructor(message: string, opts?: LlmErrorOptions) {
    super(message, opts);
    this.name = "LlmMalformedResponseError";
  }
}

