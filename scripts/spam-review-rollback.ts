#!/usr/bin/env npx tsx
import { randomUUID } from "node:crypto";
import { hostname } from "node:os";
import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { GorgiasClient, type Ticket, type TicketUpdateResult } from "./gorgias-client.js";
import { fingerprintTicket, fingerprintsEqual, type TicketFingerprint } from "./spam-review-core.js";
import { loadSpamReviewSettings, resolveLiveHost } from "./spam-review.js";
import {
  DEFAULT_STATE_ROOT,
  acquireLiveLock,
  appendJournal,
  pendingRollbackIntents,
  readJournal,
  readRunSummary,
  unresolvedAmbiguousRollbackOutcomes,
  type JournalIntent,
  type JournalOutcome,
  type JournalRollbackIntent,
  type JournalRollbackOutcome,
} from "./spam-review-state.js";

export interface RollbackClient {
  disableCache(): void;
  getTicket(ticketId: number, options: { fresh: boolean }): Promise<Ticket>;
  updateTicketSpamState(
    ticketId: number,
    update: { spam: boolean; trashedDatetime?: string | null },
  ): Promise<TicketUpdateResult>;
}

export interface RollbackResult {
  run_id: string;
  mode: "live" | "dry-run";
  results: Array<{ ticketId: number; status: string; reason?: string }>;
}

function sameTimestamp(actual: string | null | undefined, expected: string | null): boolean {
  if (actual == null || expected == null) return actual == null && expected == null;
  const actualMs = Date.parse(actual);
  const expectedMs = Date.parse(expected);
  return Number.isFinite(actualMs) && Number.isFinite(expectedMs) && actualMs === expectedMs;
}

function semanticRollbackApplied(
  ticket: Ticket,
  pre: TicketFingerprint,
  exactTrashedDatetime?: string | null,
): boolean {
  return ticket.spam === true
    && Boolean(ticket.trashed_datetime) === pre.trashed
    && (exactTrashedDatetime === undefined || sameTimestamp(ticket.trashed_datetime, exactTrashedDatetime));
}

function expectedRollbackFingerprint(current: TicketFingerprint, after: TicketFingerprint, trashed: boolean): TicketFingerprint {
  return {
    ...current,
    updatedDatetime: after.updatedDatetime,
    spam: true,
    trashed,
  };
}

function outcomeForIntent(events: ReturnType<typeof readJournal>, intentId: string): JournalOutcome | undefined {
  return events
    .filter((event): event is JournalOutcome => event.type === "outcome" && event.intentId === intentId)
    .at(-1);
}

function intentById(events: ReturnType<typeof readJournal>, intentId: string): JournalIntent | undefined {
  return events.find((event): event is JournalIntent => event.type === "intent" && event.intentId === intentId);
}

function rollbackOutcomeForOriginal(
  events: ReturnType<typeof readJournal>,
  originalIntentId: string,
): JournalRollbackOutcome | undefined {
  return events
    .filter((event): event is JournalRollbackOutcome =>
      event.type === "rollback_outcome" && event.originalIntentId === originalIntentId)
    .at(-1);
}

async function reconcilePendingRollbacks(
  client: RollbackClient,
  stateRoot: string,
  sourceDate: string,
): Promise<void> {
  const events = readJournal(stateRoot, sourceDate);
  const ambiguous = unresolvedAmbiguousRollbackOutcomes(events);
  const pendingById = new Map(
    pendingRollbackIntents(events).map((intent) => [intent.rollbackIntentId, intent]),
  );
  for (const outcome of ambiguous) {
    const intent = events.find(
      (event): event is JournalRollbackIntent =>
        event.type === "rollback_intent" && event.rollbackIntentId === outcome.rollbackIntentId,
    );
    if (!intent) throw new Error(`ambiguous rollback ${outcome.rollbackIntentId} has no matching intent`);
    pendingById.set(intent.rollbackIntentId, intent);
  }
  for (const intent of pendingById.values()) {
    const live = await client.getTicket(intent.ticketId, { fresh: true });
    const post = fingerprintTicket(live);
    let status: JournalRollbackOutcome["status"];
    if (
      semanticRollbackApplied(live, { ...intent.current, trashed: intent.target.trashed }, intent.target.trashedDatetime)
      && fingerprintsEqual(post, expectedRollbackFingerprint(intent.current, post, intent.target.trashed))
    ) {
      status = "rolled_back";
    } else if (fingerprintsEqual(post, intent.current)) {
      status = "not_applied";
    } else {
      status = "ambiguous";
    }
    appendJournal(stateRoot, sourceDate, {
      type: "rollback_outcome",
      rollbackIntentId: intent.rollbackIntentId,
      originalIntentId: intent.originalIntentId,
      rollbackRunId: intent.rollbackRunId,
      sourceDate,
      ticketId: intent.ticketId,
      at: new Date().toISOString(),
      status,
      post,
    });
    if (status === "ambiguous") {
      throw new Error(`pending rollback ${intent.rollbackIntentId} has ambiguous live state`);
    }
  }
}

export async function rollbackRun(
  options: {
    runId: string;
    confirm: boolean;
    stateRoot: string;
    stabilizationMs: number;
    sleep?: (ms: number) => Promise<void>;
    now?: () => Date;
  },
  client: RollbackClient,
): Promise<RollbackResult> {
  const now = options.now ?? (() => new Date());
  const sleep = options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const summary = readRunSummary(options.stateRoot, options.runId);
  client.disableCache();
  await reconcilePendingRollbacks(client, options.stateRoot, summary.sourceDate);
  const journal = readJournal(options.stateRoot, summary.sourceDate);

  const results: RollbackResult["results"] = [];
  for (const ticketSummary of summary.tickets.filter((ticket) => ticket.intentId)) {
    const intentId = ticketSummary.intentId as string;
    if (rollbackOutcomeForOriginal(journal, intentId)?.status === "rolled_back") {
      results.push({ ticketId: ticketSummary.ticketId, status: "skipped", reason: "already rolled back" });
      continue;
    }
    const intent = intentById(journal, intentId);
    const outcome = outcomeForIntent(journal, intentId);
    if (!intent || !outcome?.post || (outcome.status !== "applied" && outcome.status !== "recovered_applied")) {
      results.push({ ticketId: ticketSummary.ticketId, status: "skipped", reason: "missing verified apply evidence" });
      continue;
    }
    const currentTicket = await client.getTicket(ticketSummary.ticketId, { fresh: true });
    const current = fingerprintTicket(currentTicket);
    if (!fingerprintsEqual(current, outcome.post)) {
      results.push({ ticketId: ticketSummary.ticketId, status: "conflict", reason: "ticket changed after the spam review" });
      continue;
    }
    if (!options.confirm) {
      results.push({ ticketId: ticketSummary.ticketId, status: "would_rollback" });
      continue;
    }

    const rollbackIntentId = `rollback:${summary.runId}:${ticketSummary.ticketId}:${randomUUID().slice(0, 8)}`;
    const originalTrashedDatetime = Object.prototype.hasOwnProperty.call(intent, "originalTrashedDatetime")
      ? intent.originalTrashedDatetime ?? null
      : intent.pre.trashed ? now().toISOString() : null;
    const rollbackIntent: JournalRollbackIntent = {
      type: "rollback_intent",
      rollbackIntentId,
      originalIntentId: intentId,
      rollbackRunId: summary.runId,
      sourceDate: summary.sourceDate,
      ticketId: ticketSummary.ticketId,
      at: now().toISOString(),
      current,
      target: {
        spam: true,
        trashed: intent.pre.trashed,
        trashedDatetime: originalTrashedDatetime,
      },
    };
    appendJournal(options.stateRoot, summary.sourceDate, rollbackIntent);
    try {
      await client.updateTicketSpamState(ticketSummary.ticketId, {
        spam: true,
        trashedDatetime: originalTrashedDatetime,
      });
      const afterTicket = await client.getTicket(ticketSummary.ticketId, { fresh: true });
      const after = fingerprintTicket(afterTicket);
      if (!semanticRollbackApplied(afterTicket, intent.pre, originalTrashedDatetime)
        || !fingerprintsEqual(after, expectedRollbackFingerprint(current, after, intent.pre.trashed))) {
        throw new Error("rollback verification failed or unrelated fields changed");
      }
      await sleep(options.stabilizationMs);
      const stabilizedTicket = await client.getTicket(ticketSummary.ticketId, { fresh: true });
      const stabilized = fingerprintTicket(stabilizedTicket);
      if (!semanticRollbackApplied(stabilizedTicket, intent.pre, originalTrashedDatetime)
        || !fingerprintsEqual(stabilized, expectedRollbackFingerprint(current, stabilized, intent.pre.trashed))) {
        throw new Error("rollback stabilization verification failed or unrelated fields changed");
      }
      appendJournal(options.stateRoot, summary.sourceDate, {
        type: "rollback_outcome",
        rollbackIntentId,
        originalIntentId: intentId,
        rollbackRunId: summary.runId,
        sourceDate: summary.sourceDate,
        ticketId: ticketSummary.ticketId,
        at: now().toISOString(),
        status: "rolled_back",
        post: stabilized,
      });
      results.push({ ticketId: ticketSummary.ticketId, status: "rolled_back" });
    } catch (error) {
      let status: "not_applied" | "ambiguous" = "ambiguous";
      let post: TicketFingerprint | undefined;
      try {
        const live = await client.getTicket(ticketSummary.ticketId, { fresh: true });
        post = fingerprintTicket(live);
        if (fingerprintsEqual(post, current)) status = "not_applied";
      } catch {
      }
      appendJournal(options.stateRoot, summary.sourceDate, {
        type: "rollback_outcome",
        rollbackIntentId,
        originalIntentId: intentId,
        rollbackRunId: summary.runId,
        sourceDate: summary.sourceDate,
        ticketId: ticketSummary.ticketId,
        at: now().toISOString(),
        status,
        post,
        errorCategory: "rollback_failure",
      });
      throw error;
    }
  }

  return { run_id: summary.runId, mode: options.confirm ? "live" : "dry-run", results };
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      "run-id": { type: "string" },
      confirm: { type: "boolean", default: false },
      "state-root": { type: "string" },
    },
    strict: true,
  });
  if (!values["run-id"]) throw new Error("--run-id is required");
  const stateRoot = values["state-root"] ?? DEFAULT_STATE_ROOT;
  const settings = loadSpamReviewSettings();
  if (values.confirm) {
    const liveHost = resolveLiveHost(settings);
    if (hostname().toLowerCase() !== liveHost.toLowerCase()) {
      throw new Error(`live rollback is owned by ${liveHost}; current host is ${hostname()}`);
    }
  }
  if (values.confirm && resolve(stateRoot) !== resolve(DEFAULT_STATE_ROOT)) {
    throw new Error("live rollback must use the canonical state root");
  }

  const releaseLiveLock = values.confirm ? acquireLiveLock(stateRoot) : undefined;
  try {
  const client = new GorgiasClient({
    requestIntervalMs: settings.gorgiasRequestIntervalMs,
    readMaxRetries: settings.gorgiasReadMaxRetries,
  });
  const result = await rollbackRun({
    runId: values["run-id"],
    confirm: values.confirm,
    stateRoot,
    stabilizationMs: settings.verificationStabilizationMs,
  }, client);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    releaseLiveLock?.();
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    process.stderr.write(`gorgias-spam-review-rollback: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
