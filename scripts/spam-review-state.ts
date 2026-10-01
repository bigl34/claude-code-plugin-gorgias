import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { hostname } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  ClassifierDecision,
  EventBoundary,
  PostUpdateEvidence,
  TicketFingerprint,
  TrashAttribution,
} from "./spam-review-core.js";
import { previousSourceDate, shiftSourceDate, sourceDatesBetween } from "./spam-review-core.js";

export type DayStatus = "running" | "complete" | "complete_capped" | "failed";

export interface DayState {
  schema: "gorgias-spam-review-day.v1";
  sourceDate: string;
  status: DayStatus;
  attempts: number;
  lastRunId: string;
  lastAttemptAt: string;
  completedAt?: string;
  errorCategory?: string;
  errorHash?: string;
  notificationPending?: boolean;
  lastAlertHash?: string;
  lastAlertedAt?: string;
}

export interface JournalIntent {
  type: "intent";
  intentId: string;
  runId: string;
  sourceDate: string;
  ticketId: number;
  at: string;
  pre: TicketFingerprint;
  eventBoundary?: EventBoundary;
  originalTrashedDatetime?: string | null;
  target: { spam: false; trashed: false };
}

export interface JournalOutcome {
  type: "outcome";
  intentId: string;
  runId: string;
  sourceDate: string;
  ticketId: number;
  at: string;
  status: "applied" | "not_applied" | "recovered_applied" | "recovered_not_applied" | "ambiguous" | "rolled_back";
  httpStatus?: number;
  post?: TicketFingerprint;
  postUpdateEvidence?: PostUpdateEvidence;
  errorCategory?: string;
}

export interface JournalRollbackIntent {
  type: "rollback_intent";
  rollbackIntentId: string;
  originalIntentId: string;
  rollbackRunId: string;
  sourceDate: string;
  ticketId: number;
  at: string;
  current: TicketFingerprint;
  target: { spam: true; trashed: boolean; trashedDatetime?: string | null };
}

export interface JournalRollbackOutcome {
  type: "rollback_outcome";
  rollbackIntentId: string;
  originalIntentId: string;
  rollbackRunId: string;
  sourceDate: string;
  ticketId: number;
  at: string;
  status: "rolled_back" | "not_applied" | "ambiguous";
  post?: TicketFingerprint;
  errorCategory?: string;
}

export type JournalEvent = JournalIntent | JournalOutcome | JournalRollbackIntent | JournalRollbackOutcome;

export interface RunTicketSummary {
  ticketId: number;
  decision: Omit<ClassifierDecision, "reason"> & { reason: string };
  trashAttribution: TrashAttribution;
  providerSpamLikely?: boolean;
  providerSpamEvidenceCodes?: string[];
  eligible: boolean;
  action: "none" | "dry_run" | "capped" | "stale" | "applied" | "manual_trash";
  intentId?: string;
}

export interface RunSummary {
  schema: "gorgias-spam-review-run.v1";
  runId: string;
  sourceDate: string;
  startedAt: string;
  completedAt: string;
  mode: "dry-run" | "live";
  status: DayStatus;
  model: string;
  promptVersion: string;
  schemaVersion: string;
  window: { start: string; end: string; timeZone: string };
  pagesFetched: number;
  rowsFetched: number;
  candidates: number;
  eligible: number;
  applied: number;
  capped: number;
  uncertain: number;
  tickets: RunTicketSummary[];
  notificationPending: boolean;
  errorCategory?: string;
  errorHash?: string;
}

interface DebouncedAlertState {
  schema: "gorgias-spam-review-alert.v1";
  key: string;
  problem: string;
  alertedAt: string;
}

function discoverBizRoot(): string {
  let candidate = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 6; depth += 1) {
    if (existsSync(join(candidate, "config")) && existsSync(join(candidate, "scripts"))) return candidate;
    const parent = dirname(candidate);
    if (parent === candidate) break;
    candidate = parent;
  }
  throw new Error("could not locate biz workspace root");
}

export const BIZ_ROOT = discoverBizRoot();
export const DEFAULT_STATE_ROOT = process.env.YOUR_COMPANY_RUNTIME_STATE_ROOT
  ? join(process.env.YOUR_COMPANY_RUNTIME_STATE_ROOT, "tasks/gorgias-spam-review")
  : join(BIZ_ROOT, "var/gorgias-spam-review");

export function acquireLiveLock(stateRoot: string): () => void {
  const root = resolve(stateRoot);
  ensurePrivateDirectory(root);
  const path = join(root, "live.lock");
  const token = randomUUID();
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, "wx", 0o600);
    writeSync(descriptor, `${JSON.stringify({ token, pid: process.pid, host: hostname(), startedAt: new Date().toISOString() })}\n`);
    fsyncSync(descriptor);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(`another live Gorgias spam review owns ${path}; prove that process is stopped before removing the lock`);
    }
    if (descriptor !== undefined && existsSync(path)) {
      try { unlinkSync(path); } catch {   }
    }
    throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  chmodSync(path, 0o600);
  return () => {
    try {
      const current = JSON.parse(readFileSync(path, "utf8")) as { token?: string };
      if (current.token === token) unlinkSync(path);
    } catch {
    }
  };
}

export function liveLockAgeMs(stateRoot: string, now = new Date()): number | null {
  const path = join(resolve(stateRoot), "live.lock");
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as { startedAt?: string };
    const startedAt = Date.parse(parsed.startedAt ?? "");
    return Number.isFinite(startedAt) ? Math.max(0, now.getTime() - startedAt) : Number.POSITIVE_INFINITY;
  } catch {
    const modified = statSync(path).mtimeMs;
    return Number.isFinite(modified) ? Math.max(0, now.getTime() - modified) : Number.POSITIVE_INFINITY;
  }
}

function ensurePrivateDirectory(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

function writePrivateJson(path: string, value: unknown): void {
  ensurePrivateDirectory(dirname(path));
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
  chmodSync(path, 0o600);
}

function dayDir(stateRoot: string, sourceDate: string): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(sourceDate)) throw new Error("invalid source date for state path");
  return join(resolve(stateRoot), "dates", sourceDate);
}

export function readDayState(stateRoot: string, sourceDate: string): DayState | null {
  const path = join(dayDir(stateRoot, sourceDate), "state.json");
  if (!existsSync(path)) return null;
  const parsed = JSON.parse(readFileSync(path, "utf8")) as DayState;
  if (parsed.schema !== "gorgias-spam-review-day.v1" || parsed.sourceDate !== sourceDate) {
    throw new Error(`invalid day state for ${sourceDate}`);
  }
  return parsed;
}

export function writeDayState(stateRoot: string, state: DayState): void {
  writePrivateJson(join(dayDir(stateRoot, state.sourceDate), "state.json"), state);
}

export function listPendingNotificationStates(stateRoot: string): DayState[] {
  const datesPath = join(resolve(stateRoot), "dates");
  if (!existsSync(datesPath)) return [];
  return readdirSync(datesPath)
    .filter((entry) => /^\d{4}-\d{2}-\d{2}$/.test(entry))
    .sort()
    .map((sourceDate) => readDayState(stateRoot, sourceDate))
    .filter((state): state is DayState => state?.notificationPending === true);
}

export function listDayStates(stateRoot: string): DayState[] {
  const datesPath = join(resolve(stateRoot), "dates");
  if (!existsSync(datesPath)) return [];
  return readdirSync(datesPath)
    .filter((entry) => /^\d{4}-\d{2}-\d{2}$/.test(entry))
    .sort()
    .map((sourceDate) => readDayState(stateRoot, sourceDate))
    .filter((state): state is DayState => state !== null);
}

export function listJournalSourceDates(stateRoot: string): string[] {
  const datesPath = join(resolve(stateRoot), "dates");
  if (!existsSync(datesPath)) return [];
  return readdirSync(datesPath)
    .filter((entry) => /^\d{4}-\d{2}-\d{2}$/.test(entry))
    .filter((sourceDate) => existsSync(join(dayDir(stateRoot, sourceDate), "journal.jsonl")))
    .sort();
}

export function appendJournal(stateRoot: string, sourceDate: string, event: JournalEvent): void {
  const path = join(dayDir(stateRoot, sourceDate), "journal.jsonl");
  ensurePrivateDirectory(dirname(path));
  const descriptor = openSync(path, "a", 0o600);
  try {
    writeSync(descriptor, `${JSON.stringify(event)}\n`);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  chmodSync(path, 0o600);
}

export function readJournal(stateRoot: string, sourceDate: string): JournalEvent[] {
  const path = join(dayDir(stateRoot, sourceDate), "journal.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line) as JournalEvent;
      } catch {
        throw new Error(`invalid journal JSON at line ${index + 1} for ${sourceDate}`);
      }
    });
}

export function pendingIntents(events: JournalEvent[]): JournalIntent[] {
  const intents = new Map<string, JournalIntent>();
  const outcomes = new Set<string>();
  for (const event of events) {
    if (event.type === "intent") intents.set(event.intentId, event);
    else if (event.type === "outcome") outcomes.add(event.intentId);
  }
  return [...intents.values()].filter((intent) => !outcomes.has(intent.intentId));
}

export function pendingRollbackIntents(events: JournalEvent[]): JournalRollbackIntent[] {
  const intents = new Map<string, JournalRollbackIntent>();
  const outcomes = new Set<string>();
  for (const event of events) {
    if (event.type === "rollback_intent") intents.set(event.rollbackIntentId, event);
    else if (event.type === "rollback_outcome") outcomes.add(event.rollbackIntentId);
  }
  return [...intents.values()].filter((intent) => !outcomes.has(intent.rollbackIntentId));
}

export function verifiedWriteCount(events: JournalEvent[]): number {
  const appliedIntents = new Set<string>();
  for (const event of events) {
    if (event.type !== "outcome") continue;
    if (
      event.status === "applied"
      || event.status === "recovered_applied"
      || (event.status === "ambiguous" && event.post?.spam === false && event.post.trashed === false)
    ) {
      appliedIntents.add(event.intentId);
    }
  }
  return appliedIntents.size;
}

export function unresolvedAmbiguousOutcomes(events: JournalEvent[]): JournalOutcome[] {
  const latest = new Map<string, JournalOutcome>();
  for (const event of events) {
    if (event.type === "outcome") latest.set(event.intentId, event);
  }
  return [...latest.values()].filter((event) => event.status === "ambiguous");
}

export function unresolvedAmbiguousRollbackOutcomes(events: JournalEvent[]): JournalRollbackOutcome[] {
  const latest = new Map<string, JournalRollbackOutcome>();
  for (const event of events) {
    if (event.type === "rollback_outcome") latest.set(event.rollbackIntentId, event);
  }
  return [...latest.values()].filter((event) => event.status === "ambiguous");
}

export function saveRunSummary(stateRoot: string, summary: RunSummary): void {
  if (!/^[A-Za-z0-9_.:-]+$/.test(summary.runId)) throw new Error("invalid run ID");
  writePrivateJson(join(resolve(stateRoot), "runs", `${summary.runId}.json`), summary);
}

export function readRunSummary(stateRoot: string, runId: string): RunSummary {
  if (!/^[A-Za-z0-9_.:-]+$/.test(runId)) throw new Error("invalid run ID");
  const path = join(resolve(stateRoot), "runs", `${runId}.json`);
  const parsed = JSON.parse(readFileSync(path, "utf8")) as RunSummary;
  if (parsed.schema !== "gorgias-spam-review-run.v1" || parsed.runId !== runId) {
    throw new Error("invalid spam-review run summary");
  }
  return parsed;
}

function alertPath(stateRoot: string, key: string): string {
  if (!/^[a-z0-9-]+$/.test(key)) throw new Error("invalid spam-review alert key");
  return join(resolve(stateRoot), "alerts", `${key}.json`);
}

export function clearDebouncedAlert(stateRoot: string, key: string): void {
  rmSync(alertPath(stateRoot, key), { force: true });
}

export function shouldSendDebouncedAlert(
  stateRoot: string,
  key: string,
  problem: string,
  now = new Date(),
  debounceHours = 12,
): boolean {
  const path = alertPath(stateRoot, key);
  if (!existsSync(path)) return true;
  try {
    const prior = JSON.parse(readFileSync(path, "utf8")) as DebouncedAlertState;
    const alertedAt = Date.parse(prior.alertedAt);
    return prior.schema !== "gorgias-spam-review-alert.v1"
      || prior.key !== key
      || prior.problem !== problem
      || !Number.isFinite(alertedAt)
      || now.getTime() - alertedAt >= debounceHours * 3_600_000;
  } catch {
    return true;
  }
}

export function recordDebouncedAlert(
  stateRoot: string,
  key: string,
  problem: string,
  now = new Date(),
): void {
  writePrivateJson(alertPath(stateRoot, key), {
    schema: "gorgias-spam-review-alert.v1",
    key,
    problem,
    alertedAt: now.toISOString(),
  } satisfies DebouncedAlertState);
}

export function selectDueSourceDate(
  stateRoot: string,
  now = new Date(),
  lookbackDays = 7,
): { sourceDate: string | null; overdueBefore: string | null } {
  const newest = previousSourceDate(now);
  const oldest = shiftSourceDate(newest, -(lookbackDays - 1));
  const datesPath = join(resolve(stateRoot), "dates");
  const existingDates = existsSync(datesPath)
    ? readdirSync(datesPath).filter((entry) => /^\d{4}-\d{2}-\d{2}$/.test(entry)).sort()
    : [];
  if (existingDates.length === 0) {
    return { sourceDate: newest, overdueBefore: null };
  }
  const earliestKnown = existingDates[0];
  let overdueBefore: string | null = null;
  if (earliestKnown < oldest) {
    const overdueEnd = shiftSourceDate(oldest, -1);
    for (const sourceDate of sourceDatesBetween(earliestKnown, overdueEnd)) {
      const state = readDayState(stateRoot, sourceDate);
      if (!state || (state.status !== "complete" && state.status !== "complete_capped")) {
        overdueBefore = sourceDate;
        break;
      }
    }
  }
  const scanStart = earliestKnown > oldest ? earliestKnown : oldest;
  for (const sourceDate of sourceDatesBetween(scanStart, newest)) {
    const state = readDayState(stateRoot, sourceDate);
    if (!state || (state.status !== "complete" && state.status !== "complete_capped")) {
      return { sourceDate, overdueBefore };
    }
  }
  return { sourceDate: null, overdueBefore };
}
