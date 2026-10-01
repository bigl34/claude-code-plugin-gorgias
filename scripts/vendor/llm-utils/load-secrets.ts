import { execSync } from "node:child_process";

import { loadServiceConfig } from "@local/cli-utils";

import { LlmMissingKeyError } from "./errors.js";

const OPENROUTER_SERVICE_NAME = "openrouter-inference";
const OPENROUTER_PASS_PATH = "your-secret-store/openrouter/api-key";
const OPENROUTER_PASS_COMMAND = `pass ${OPENROUTER_PASS_PATH} 2>/dev/null`;
const MISSING_OPENROUTER_KEY_MESSAGE =
  `OpenRouter API key not found in ${OPENROUTER_SERVICE_NAME} config ` +
  `(openrouter.apiKey) or pass store (${OPENROUTER_PASS_PATH})`;

let cachedOpenRouterKey: string | null = null;

interface LoadOpenRouterKeyDeps {
  exec?: (cmd: string) => string;
  isTTY?: boolean;
  loadConfig?: (serviceName: string) => unknown;
}

export function loadOpenRouterKey(deps?: LoadOpenRouterKeyDeps): string {
  if (cachedOpenRouterKey !== null) {
    return cachedOpenRouterKey;
  }

  const loadConfig = deps?.loadConfig ?? defaultLoadConfig;
  const configKey = readOpenRouterConfigKey(loadConfig);

  if (configKey !== null) {
    cachedOpenRouterKey = configKey;
    return cachedOpenRouterKey;
  }

  const isTTY = deps?.isTTY ?? process.stdin.isTTY === true;

  if (!isTTY) {
    throw new LlmMissingKeyError(MISSING_OPENROUTER_KEY_MESSAGE);
  }

  const exec = deps?.exec ?? defaultExec;
  const passKey = readOpenRouterPassKey(exec);

  if (passKey === null) {
    throw new LlmMissingKeyError(MISSING_OPENROUTER_KEY_MESSAGE);
  }

  cachedOpenRouterKey = passKey;
  return cachedOpenRouterKey;
}

function defaultLoadConfig(serviceName: string): unknown {
  const config = loadServiceConfig<unknown>(serviceName);
  return config;
}

function readOpenRouterConfigKey(loadConfig: (serviceName: string) => unknown): string | null {
  let config: unknown;

  try {
    config = loadConfig(OPENROUTER_SERVICE_NAME);
  } catch {
    return null;
  }

  if (!isRecord(config)) {
    return null;
  }

  const openrouter = config.openrouter;

  if (!isRecord(openrouter)) {
    return null;
  }

  const apiKey = openrouter.apiKey;

  if (typeof apiKey !== "string") {
    return null;
  }

  const trimmedKey = apiKey.trim();

  if (trimmedKey === "") {
    return null;
  }

  return trimmedKey;
}

function readOpenRouterPassKey(exec: (cmd: string) => string): string | null {
  let output: string;

  try {
    output = exec(OPENROUTER_PASS_COMMAND);
  } catch {
    return null;
  }

  const trimmedKey = output.trim();

  if (trimmedKey === "") {
    return null;
  }

  return trimmedKey;
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

function defaultExec(cmd: string): string {
  const output = execSync(cmd, {
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 5_000,
  });
  const text = output.toString();
  return text;
}

export function __resetOpenRouterKeyCacheForTests(): void {
  cachedOpenRouterKey = null;
}
