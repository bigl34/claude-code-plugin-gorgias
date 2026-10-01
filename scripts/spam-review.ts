#!/usr/bin/env npx tsx
import { createHash, randomUUID } from "node:crypto";
import { hostname } from "node:os";
import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadServiceConfig, z } from "@local/cli-utils";
import { GorgiasClient, type Event, type Ticket, type TicketUpdateResult } from "./gorgias-client.js";
import {
  applyClassifierInputRiskFlags,
  assessProviderSpamIngress,
  buildClassifierInput,
  dueWindowOpen,
  eligibleForAutomaticRestore,
  enumerateSpamCandidates,
  fingerprintTicket,
  fingerprintsEqual,
  trashAttribution,
  previousSourceDate,
  validatePostUpdateTransition,
  windowForSourceDate,
  type AllowedPostUpdateAutomation,
  type ClassifierDecision,
  type DayWindow,
  type EventBoundary,
  type PostUpdateEvidence,
  type TicketFingerprint,
} from "./spam-review-core.js";
import { GeminiSpamClassifier } from "./spam-review-model.js";
import {
  BIZ_ROOT,
  DEFAULT_STATE_ROOT,
  acquireLiveLock,
  appendJournal,
  listPendingNotificationStates,
  pendingIntents,
  pendingRollbackIntents,
  readDayState,
  readJournal,
  readRunSummary,
  recordDebouncedAlert,
  saveRunSummary,
  selectDueSourceDate,
  shouldSendDebouncedAlert,
  unresolvedAmbiguousOutcomes,
  unresolvedAmbiguousRollbackOutcomes,
  verifiedWriteCount,
  writeDayState,
  type DayState,
  type JournalIntent,
  type JournalOutcome,
  type RunSummary,
  type RunTicketSummary,
} from "./spam-review-state.js";

const settingsSchema = z.object({
  timeZone: z.string().min(1),
  model: z.string().min(1),
  minimumConfidence: z.number().min(0.5).max(1),
  maxCandidates: z.number().int().min(1).max(500),
  maxPages: z.number().int().min(1).max(100),
  maxWritesPerDate: z.number().int().min(1).max(100),
  catchupDays: z.number().int().min(1).max(31),
  classifierConcurrency: z.number().int().min(1).max(10),
  gorgiasRequestIntervalMs: z.number().int().min(100).max(5_000),
  gorgiasReadMaxRetries: z.number().int().min(0).max(10),
  verificationTimeoutMs: z.number().int().min(1_000).max(60_000),
  verificationStabilizationMs: z.number().int().min(500).max(10_000),
  slackChannel: z.string().min(1),
  liveHost: z.string().min(1),
  notBeforeHourLocal: z.number().int().min(0).max(23),
  mutationActorUserId: z.number().int().positive(),
  allowedPostUpdateAutomations: z.array(z.object({
    kind: z.literal("assignment"),
    ruleId: z.number().int().positive(),
    ruleName: z.string().min(1),
    actorUserId: z.number().int().positive(),
    fromAssigneeUserId: z.number().int().positive().nullable(),
    toAssigneeUserId: z.number().int().positive(),
    maxDelayMs: z.number().int().min(1_000).max(60_000),
  }).strict()).max(10),
}).strict();

export type SpamReviewSettings = z.infer<typeof settingsSchema>;

const SlackConfigSchema = z.object({
  slack: z.object({ botToken: z.string().min(1) }),
});

export interface ReviewClient {
  disableCache(): void;
  getSubdomain(): string;
  listTickets(options: {
    limit: number;
    orderBy: string;
    cursor?: string;
    fresh: boolean;
  }): Promise<{ data: Ticket[]; meta?: { cursor?: string; next_cursor?: string; has_more?: boolean } }>;
  getTicket(ticketId: number, options: { fresh: boolean }): Promise<Ticket>;
  listEvents(options: {
    objectId: number;
    objectType?: "Ticket";
    limit?: number;
    cursor?: string;
    orderBy?: "created_datetime:asc" | "created_datetime:desc";
  }): Promise<{ data: Event[]; meta?: { cursor?: string; next_cursor?: string; has_more?: boolean } }>;
  updateTicketSpamState(
    ticketId: number,
    update: { spam: boolean; trashedDatetime?: string | null },
  ): Promise<TicketUpdateResult>;
}

export interface ReviewClassifier {
  classify(input: ReturnType<typeof buildClassifierInput>): Promise<ClassifierDecision>;
  metadata(): { model: string; promptVersion: string; schemaVersion: string };
}

export interface RunReviewOptions {
  sourceDate: string;
  live: boolean;
  maxWrites: number;
  stateRoot: string;
  now?: Date;
  ticketId?: number;
}

export interface RunReviewDeps {
  client: ReviewClient;
  classifier: ReviewClassifier;
  settings: SpamReviewSettings;
  notify?: (message: string) => Promise<boolean>;
  sleep?: (ms: number) => Promise<void>;
}

export function loadSpamReviewSettings(
  path = join(BIZ_ROOT, "config/gorgias-spam-review.json"),
): SpamReviewSettings {
  const settings = settingsSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  const longestAutomationWindow = settings.allowedPostUpdateAutomations.reduce(
    (maximum, automation) => Math.max(maximum, automation.maxDelayMs),
    0,
  );
  if (settings.verificationTimeoutMs < longestAutomationWindow + settings.verificationStabilizationMs) {
    throw new Error("verificationTimeoutMs must cover the post-update automation window plus stabilization");
  }
  return settings;
}

export function resolveLiveHost(
  settings: Pick<SpamReviewSettings, "liveHost">,
  {
    env = process.env,
    platform = process.platform,
  }: {
    env?: NodeJS.ProcessEnv;
    platform?: NodeJS.Platform;
  } = {},
): string {
  const override = env.GORGIAS_SPAM_REVIEW_LIVE_HOST?.trim();
  if (!override) return settings.liveHost;
  if (
    platform !== "darwin"
    || env.YOUR_COMPANY_RUNTIME_MODE !== "live"
    || env.YOUR_COMPANY_RUNTIME_DEPLOYMENT_MODE !== "mutable_checkout"
    || env.YOUR_COMPANY_RUNTIME_LOCK_GROUP !== "gorgias-spam-review"
  ) {
    throw new Error("Gorgias spam review live-host override requires the managed Mac live runtime");
  }
  return override;
}

function errorHash(error: unknown): string {
  return createHash("sha256").update(error instanceof Error ? error.message : String(error)).digest("hex").slice(0, 16);
}

function errorCategory(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (/pagination|cursor|candidate overflow|ordering/i.test(message)) return "enumeration_incomplete";
  if (/Gemini|classification|schema|ticket ID|invalid JSON/i.test(message)) return "classifier_failure";
  if (/changed after classification|stale/i.test(message)) return "state_changed";
  if (/verification|update|Gorgias API/i.test(message)) return "mutation_failure";
  if (/journal|state/i.test(message)) return "state_failure";
  return "unexpected_failure";
}

export async function mapWithConcurrency<T, R>(
  values: T[],
  concurrency: number,
  worker: (value: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let next = 0;
  let failed = false;
  let firstError: unknown;
  const runners = Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (true) {
      if (failed) return;
      const index = next;
      next += 1;
      if (index >= values.length) return;
      try {
        results[index] = await worker(values[index], index);
      } catch (error) {
        if (!failed) {
          failed = true;
          firstError = error;
        }
        return;
      }
    }
  });
  await Promise.all(runners);
  if (failed) throw firstError;
  return results;
}

async function loadTicketEvents(client: ReviewClient, ticketId: number): Promise<Event[]> {
  const events: Event[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let page = 0; page < 5; page += 1) {
    if (cursor) {
      if (seen.has(cursor)) throw new Error(`event cursor loop for ticket ${ticketId}`);
      seen.add(cursor);
    }
    const result = await client.listEvents({
      objectId: ticketId,
      objectType: "Ticket",
      limit: 100,
      cursor,
      orderBy: "created_datetime:desc",
    });
    events.push(...(result.data ?? []));
    const nextCursor = result.meta?.next_cursor ?? result.meta?.cursor;
    if (!nextCursor) {
      if (result.meta?.has_more === true || result.data.length >= 100) {
        throw new Error(`event pagination ended without a cursor for ticket ${ticketId}`);
      }
      return events;
    }
    cursor = nextCursor;
  }
  throw new Error(`event pagination exceeded 5 pages for ticket ${ticketId}`);
}

async function captureEventSnapshot(
  client: ReviewClient,
  ticketId: number,
): Promise<{ events: Event[]; attribution: ReturnType<typeof trashAttribution>; boundary: EventBoundary }> {
  const captureStartedAt = new Date().toISOString();
  const events = await loadTicketEvents(client, ticketId);
  const newest = [...events].sort((a, b) => {
    const time = Date.parse(a.created_datetime) - Date.parse(b.created_datetime);
    return time || a.id - b.id;
  }).at(-1);
  return {
    events,
    attribution: trashAttribution(events),
    boundary: newest
      ? { eventId: newest.id, createdDatetime: newest.created_datetime }
      : { eventId: null, createdDatetime: captureStartedAt },
  };
}

function targetApplied(ticket: Ticket): boolean {
  return ticket.spam === false && ticket.trashed_datetime == null;
}

function ticketWithinWindow(ticket: Ticket, window: DayWindow): boolean {
  const created = Date.parse(ticket.created_datetime);
  return Number.isFinite(created) && created >= window.start.getTime() && created < window.end.getTime();
}

function unrelatedFieldsPreserved(before: TicketFingerprint, after: TicketFingerprint): boolean {
  return before.ticketId === after.ticketId
    && before.status === after.status
    && (before.priority === undefined || before.priority === after.priority)
    && before.assigneeUserId === after.assigneeUserId
    && before.assigneeTeamId === after.assigneeTeamId
    && before.unread === after.unread
    && JSON.stringify(before.tagIds) === JSON.stringify(after.tagIds)
    && before.latestMessageId === after.latestMessageId
    && before.latestMessageDatetime === after.latestMessageDatetime
    && before.contentHash === after.contentHash;
}

async function validateAppliedTransition(
  client: ReviewClient,
  before: TicketFingerprint,
  after: TicketFingerprint,
  intent: Pick<JournalIntent, "ticketId" | "at" | "eventBoundary">,
  settings: SpamReviewSettings,
  legacyBoundary?: EventBoundary,
): Promise<{ ok: true; evidence: PostUpdateEvidence } | { ok: false }> {
  const boundary = intent.eventBoundary ?? legacyBoundary;
  if (!boundary) return { ok: false };
  const events = await loadTicketEvents(client, intent.ticketId);
  return validatePostUpdateTransition(
    before,
    after,
    events,
    boundary,
    intent.at,
    settings.mutationActorUserId,
    settings.allowedPostUpdateAutomations as AllowedPostUpdateAutomation[],
  );
}

async function reconcilePending(
  client: ReviewClient,
  stateRoot: string,
  sourceDate: string,
  allowRecovery: boolean,
  settings: SpamReviewSettings,
): Promise<RunTicketSummary[]> {
  const events = readJournal(stateRoot, sourceDate);
  const unresolved = unresolvedAmbiguousOutcomes(events);
  if (!allowRecovery && unresolved.length > 0) {
    throw new Error(`source date ${sourceDate} has ${unresolved.length} ambiguous mutation outcome(s)`);
  }
  const pendingRollbacks = pendingRollbackIntents(events);
  const ambiguousRollbacks = unresolvedAmbiguousRollbackOutcomes(events);
  if (pendingRollbacks.length > 0 || ambiguousRollbacks.length > 0) {
    throw new Error(
      `source date ${sourceDate} has unresolved rollback state (${pendingRollbacks.length} pending, ${ambiguousRollbacks.length} ambiguous)`,
    );
  }
  const pendingById = new Map(pendingIntents(events).map((intent) => [intent.intentId, intent]));
  for (const outcome of unresolved) {
    const intent = events.find(
      (event): event is JournalIntent => event.type === "intent" && event.intentId === outcome.intentId,
    );
    if (!intent) throw new Error(`ambiguous outcome ${outcome.intentId} has no matching intent`);
    pendingById.set(intent.intentId, intent);
  }
  const pending = [...pendingById.values()];
  if (!allowRecovery && pending.length > 0) {
    throw new Error(`source date ${sourceDate} has ${pending.length} pending live mutation intent(s)`);
  }
  const recoveredSummaries: RunTicketSummary[] = [];
  for (const intent of pending) {
    const live = await client.getTicket(intent.ticketId, { fresh: true });
    const post = fingerprintTicket(live);
    let status: JournalOutcome["status"];
    let postUpdateEvidence: PostUpdateEvidence | undefined;
    const transition = targetApplied(live) && intent.eventBoundary
      ? await validateAppliedTransition(client, intent.pre, post, intent, settings)
      : null;
    if (targetApplied(live) && (transition?.ok === true || (!intent.eventBoundary && unrelatedFieldsPreserved(intent.pre, post)))) {
      status = "recovered_applied";
      if (transition?.ok === true) postUpdateEvidence = transition.evidence;
    } else if (fingerprintsEqual(intent.pre, post)) {
      status = "recovered_not_applied";
    } else {
      status = "ambiguous";
    }
    appendJournal(stateRoot, sourceDate, {
      type: "outcome",
      intentId: intent.intentId,
      runId: intent.runId,
      sourceDate,
      ticketId: intent.ticketId,
      at: new Date().toISOString(),
      status,
      post,
      postUpdateEvidence,
    });
    if (status === "ambiguous") {
      throw new Error(`pending intent ${intent.intentId} has ambiguous live state`);
    }
    if (status === "recovered_applied") {
      let recovered: RunTicketSummary = {
        ticketId: intent.ticketId,
        decision: {
          ticket_id: intent.ticketId,
          verdict: "uncertain",
          category: "unknown",
          confidence: 0,
          reason: "Recovered from a durable mutation intent.",
          evidence_codes: ["insufficient_context"],
          risk_flags: ["insufficient_context"],
        },
        trashAttribution: "unknown",
        eligible: false,
        action: "applied",
        intentId: intent.intentId,
      };
      try {
        const original = readRunSummary(stateRoot, intent.runId);
        const originalTicket = original.tickets.find((ticket) => ticket.ticketId === intent.ticketId);
        if (originalTicket) {
          originalTicket.action = "applied";
          originalTicket.intentId = intent.intentId;
          recovered = { ...originalTicket };
          original.applied = original.tickets.filter((ticket) => ticket.action === "applied").length;
          saveRunSummary(stateRoot, original);
        }
      } catch {
      }
      recoveredSummaries.push(recovered);
    }
  }
  return recoveredSummaries;
}

async function verifyApplied(
  client: ReviewClient,
  intent: JournalIntent,
  settings: SpamReviewSettings,
  timeoutMs: number,
  stabilizationMs: number,
  sleep: (ms: number) => Promise<void>,
): Promise<{ ticket: Ticket; fingerprint: TicketFingerprint; evidence: PostUpdateEvidence }> {
  const deadline = Date.now() + timeoutMs;
  const automationWindowMs = settings.allowedPostUpdateAutomations.reduce(
    (maximum, automation) => Math.max(maximum, automation.maxDelayMs),
    0,
  );
  const settleDelayMs = automationWindowMs + stabilizationMs;
  const maxAttempts = Math.max(1, Math.ceil(timeoutMs / 500));
  let last: Ticket | null = null;
  let invalidTargetTransition = false;
  let attempts = 0;
  do {
    attempts += 1;
    last = await client.getTicket(intent.ticketId, { fresh: true });
    const fingerprint = fingerprintTicket(last);
    if (targetApplied(last)) {
      const transition = await validateAppliedTransition(client, intent.pre, fingerprint, intent, settings);
      if (transition.ok) {
        await sleep(settleDelayMs);
        const stabilized = await client.getTicket(intent.ticketId, { fresh: true });
        const stabilizedFingerprint = fingerprintTicket(stabilized);
        const stabilizedTransition = targetApplied(stabilized)
          ? await validateAppliedTransition(client, intent.pre, stabilizedFingerprint, intent, settings)
          : { ok: false as const };
        if (stabilizedTransition.ok) {
          return {
            ticket: stabilized,
            fingerprint: stabilizedFingerprint,
            evidence: stabilizedTransition.evidence,
          };
        }
      }
      invalidTargetTransition = true;
    }
    await sleep(500);
  } while (Date.now() < deadline && attempts < maxAttempts);
  if (invalidTargetTransition) {
    throw new Error(`ticket ${intent.ticketId} changed unreviewed fields during spam update`);
  }
  throw new Error(`ticket ${intent.ticketId} spam update verification timed out`);
}

export function buildDigest(summary: RunSummary, subdomain: string): string {
  const link = (id: number) => `https://${subdomain}.gorgias.com/app/ticket/${id}`;
  const applied = summary.tickets.filter((ticket) => ticket.action === "applied").map((ticket) => `<${link(ticket.ticketId)}|#${ticket.ticketId}>`);
  const providerIngress = summary.tickets
    .filter((ticket) => ticket.providerSpamLikely === true)
    .map((ticket) => `<${link(ticket.ticketId)}|#${ticket.ticketId}>`);
  const manual = summary.tickets.filter((ticket) =>
    ticket.action === "capped"
      || ticket.action === "manual_trash"
      || ticket.decision.verdict === "uncertain"
      || (ticket.decision.verdict === "legitimate" && !ticket.eligible)
  ).map((ticket) => `<${link(ticket.ticketId)}|#${ticket.ticketId}>`);
  return [
    `*Gorgias spam review — ${summary.sourceDate}*`,
    `Reviewed ${summary.candidates}; legitimate ${summary.eligible}; restored ${summary.applied}; capped ${summary.capped}; uncertain/manual ${manual.length}.`,
    providerIngress.length ? `Provider-ingress spam watchdog: ${providerIngress.join(", ")}` : "",
    applied.length ? `Restored: ${applied.join(", ")}` : "",
    manual.length ? `Manual review: ${manual.join(", ")}` : "",
  ].filter(Boolean).join("\n").slice(0, 3_500);
}

export function buildFailureAlert(summary: RunSummary, subdomain: string): string {
  const applied = summary.tickets
    .filter((ticket) => ticket.action === "applied")
    .map((ticket) => `<https://${subdomain}.gorgias.com/app/ticket/${ticket.ticketId}|#${ticket.ticketId}>`);
  return [
    `:rotating_light: *Gorgias spam review failed — ${summary.sourceDate}*`,
    `Category: ${summary.errorCategory ?? "unknown"}`,
    `Error reference: ${summary.errorHash ?? "unknown"}`,
    `Verified changes before failure: ${summary.applied}${applied.length ? ` (${applied.join(", ")})` : ""}.`,
    "No later source date will run until this date succeeds.",
  ].join("\n").slice(0, 3_500);
}

export async function flushPendingNotifications(
  stateRoot: string,
  client: Pick<ReviewClient, "getSubdomain">,
  notify: (message: string) => Promise<boolean>,
): Promise<number> {
  let deliveredCount = 0;
  for (const state of listPendingNotificationStates(stateRoot)) {
    const summary = readRunSummary(stateRoot, state.lastRunId);
    const message = summary.errorCategory
      ? buildFailureAlert(summary, client.getSubdomain())
      : buildDigest(summary, client.getSubdomain());
    if (!await notify(message).catch(() => false)) continue;
    summary.notificationPending = false;
    saveRunSummary(stateRoot, summary);
    writeDayState(stateRoot, {
      ...state,
      notificationPending: false,
      ...(summary.errorHash ? { lastAlertHash: summary.errorHash, lastAlertedAt: new Date().toISOString() } : {}),
    });
    deliveredCount += 1;
  }
  return deliveredCount;
}

function decisionForAudit(decision: ClassifierDecision): RunTicketSummary["decision"] {
  const evidence = decision.evidence_codes.length > 0 ? decision.evidence_codes.join(", ") : "none";
  return { ...decision, reason: `Evidence codes: ${evidence}.` };
}

export async function adjudicateLegacyIntent(
  options: { sourceDate: string; intentId: string; stateRoot: string },
  client: ReviewClient,
  settings: SpamReviewSettings,
): Promise<{ intentId: string; ticketId: number; status: "recovered_applied"; evidence: PostUpdateEvidence }> {
  client.disableCache();
  const events = readJournal(options.stateRoot, options.sourceDate);
  const intent = events.find(
    (event): event is JournalIntent => event.type === "intent" && event.intentId === options.intentId,
  );
  if (!intent) throw new Error(`intent ${options.intentId} was not found`);
  if (intent.eventBoundary) throw new Error("only legacy intents without an event boundary require adjudication");
  const latestOutcome = events
    .filter((event): event is JournalOutcome => event.type === "outcome" && event.intentId === options.intentId)
    .at(-1);
  if (latestOutcome?.status !== "ambiguous") throw new Error("intent does not have a latest ambiguous outcome");

  const live = await client.getTicket(intent.ticketId, { fresh: true });
  if (!targetApplied(live)) throw new Error("legacy intent target state is not currently applied");
  const post = fingerprintTicket(live);
  const transition = await validateAppliedTransition(
    client,
    intent.pre,
    post,
    intent,
    settings,
    { eventId: null, createdDatetime: intent.at },
  );
  if (!transition.ok || transition.evidence.kind !== "allowed_assignment") {
    throw new Error("legacy intent does not match an exact reviewed post-update automation");
  }
  const original = readRunSummary(options.stateRoot, intent.runId);
  const originalTicket = original.tickets.find((ticket) => ticket.ticketId === intent.ticketId);
  if (!originalTicket) throw new Error("legacy intent run summary is missing its ticket");
  appendJournal(options.stateRoot, options.sourceDate, {
    type: "outcome",
    intentId: intent.intentId,
    runId: intent.runId,
    sourceDate: options.sourceDate,
    ticketId: intent.ticketId,
    at: new Date().toISOString(),
    status: "recovered_applied",
    post,
    postUpdateEvidence: transition.evidence,
  });
  originalTicket.action = "applied";
  originalTicket.intentId = intent.intentId;
  original.applied = original.tickets.filter((ticket) => ticket.action === "applied").length;
  saveRunSummary(options.stateRoot, original);
  return {
    intentId: intent.intentId,
    ticketId: intent.ticketId,
    status: "recovered_applied",
    evidence: transition.evidence,
  };
}

function buildRunSummary(
  input: Omit<RunSummary, "schema" | "eligible" | "applied" | "capped" | "uncertain">
    & Partial<Pick<RunSummary, "applied" | "capped" | "uncertain">>,
): RunSummary {
  return {
    schema: "gorgias-spam-review-run.v1",
    ...input,
    eligible: input.tickets.filter((item) => item.eligible).length,
    applied: input.applied ?? input.tickets.filter((item) => item.action === "applied").length,
    capped: input.capped ?? input.tickets.filter((item) => item.action === "capped").length,
    uncertain: input.uncertain ?? input.tickets.filter((item) => item.decision.verdict === "uncertain" || item.action === "manual_trash").length,
  };
}

export async function runSourceDateReview(
  options: RunReviewOptions,
  deps: RunReviewDeps,
): Promise<RunSummary> {
  const startedAt = options.now ?? new Date();
  const trackDayState = options.live && options.ticketId === undefined;
  const runId = `${options.sourceDate}:${startedAt.toISOString().replace(/[^0-9TZ]/g, "")}:${randomUUID().slice(0, 8)}`;
  const window = windowForSourceDate(options.sourceDate, deps.settings.timeZone);
  const mode: RunSummary["mode"] = options.live ? "live" : "dry-run";
  const summaryContext = {
    runId,
    sourceDate: options.sourceDate,
    startedAt: startedAt.toISOString(),
    mode,
    ...deps.classifier.metadata(),
    window: { start: window.start.toISOString(), end: window.end.toISOString(), timeZone: window.timeZone },
  };
  const priorState = readDayState(options.stateRoot, options.sourceDate);
  const runningState: DayState = {
    schema: "gorgias-spam-review-day.v1",
    sourceDate: options.sourceDate,
    status: "running",
    attempts: (priorState?.attempts ?? 0) + 1,
    lastRunId: runId,
    lastAttemptAt: startedAt.toISOString(),
    notificationPending: false,
    lastAlertHash: priorState?.lastAlertHash,
    lastAlertedAt: priorState?.lastAlertedAt,
  };
  if (trackDayState) writeDayState(options.stateRoot, runningState);
  deps.client.disableCache();

  let pagesFetched = 0;
  let rowsFetched = 0;
  let tickets: Ticket[] = [];
  let summaries: RunTicketSummary[] = [];
  let recoveredCount = 0;

  try {
    const recoveredSummaries = await reconcilePending(
      deps.client,
      options.stateRoot,
      options.sourceDate,
      options.live,
      deps.settings,
    );
    summaries = recoveredSummaries;
    recoveredCount = recoveredSummaries.length;
    if (trackDayState && recoveredCount > 0) {
      saveRunSummary(options.stateRoot, buildRunSummary({
        ...summaryContext,
        completedAt: new Date().toISOString(),
        mode: "live",
        status: "running",
        pagesFetched,
        rowsFetched,
        candidates: recoveredCount,
        applied: recoveredCount,
        capped: 0,
        uncertain: summaries.filter((item) => item.decision.verdict === "uncertain").length,
        tickets: summaries,
        notificationPending: true,
      }));
      writeDayState(options.stateRoot, { ...runningState, notificationPending: true });
    }
    const enumeration = await enumerateSpamCandidates(deps.client, window, {
      maxPages: deps.settings.maxPages,
      maxCandidates: deps.settings.maxCandidates,
    });
    pagesFetched = enumeration.pagesFetched;
    rowsFetched = enumeration.rowsFetched;
    tickets = options.ticketId === undefined
      ? enumeration.tickets
      : enumeration.tickets.filter((ticket) => ticket.id === options.ticketId);
    const recoveredCanary = options.ticketId !== undefined
      && recoveredSummaries.some((summary) => summary.ticketId === options.ticketId && summary.action === "applied");
    if (options.ticketId !== undefined && tickets.length !== 1 && !recoveredCanary) {
      throw new Error(`canary ticket ${options.ticketId} is not a current spam candidate in ${options.sourceDate}`);
    }

    const classified = await mapWithConcurrency(
      tickets,
      deps.settings.classifierConcurrency,
      async (ticket) => {
        const input = buildClassifierInput(ticket);
        const raw = await deps.classifier.classify(input);
        const decision = applyClassifierInputRiskFlags(input, raw);
        const events = await loadTicketEvents(deps.client, ticket.id);
        const attribution = trashAttribution(events);
        const providerSpam = assessProviderSpamIngress(ticket, events);
        const eligible = eligibleForAutomaticRestore(decision, {
          minimumConfidence: deps.settings.minimumConfidence,
          trashRestoreBlocked: attribution !== "none",
        });
        return { ticket, decision, attribution, providerSpam, eligible };
      },
    );

    summaries = [...summaries, ...classified.map<RunTicketSummary>(({ ticket, decision, attribution, providerSpam, eligible }) => ({
      ticketId: ticket.id,
      decision: decisionForAudit(decision),
      trashAttribution: attribution,
      providerSpamLikely: providerSpam.likelyProviderIngress,
      providerSpamEvidenceCodes: providerSpam.evidenceCodes,
      eligible,
      action: attribution !== "none" && decision.verdict === "legitimate" ? "manual_trash" : options.live ? "none" : eligible ? "dry_run" : "none",
    }))];

    if (options.live) {
      const eligibleEntries = classified
        .filter((entry) => entry.eligible)
        .sort((a, b) => Date.parse(a.ticket.created_datetime) - Date.parse(b.ticket.created_datetime));
      const preflight = new Map<number, { ticket: Ticket; fingerprint: TicketFingerprint }>();
      for (const entry of eligibleEntries) {
        const live = await deps.client.getTicket(entry.ticket.id, { fresh: true });
        if (live.spam !== true) continue;
        if (!ticketWithinWindow(live, window)) throw new Error(`ticket ${entry.ticket.id} moved outside source window`);
        const initial = fingerprintTicket(entry.ticket);
        const current = fingerprintTicket(live);
        if (!fingerprintsEqual(initial, current)) {
          const summary = summaries.find((item) => item.ticketId === entry.ticket.id);
          if (summary) summary.action = "stale";
          throw new Error(`ticket ${entry.ticket.id} changed after classification`);
        }
        preflight.set(entry.ticket.id, { ticket: live, fingerprint: current });
      }

      const journal = readJournal(options.stateRoot, options.sourceDate);
      const alreadyApplied = verifiedWriteCount(journal);
      const remainingBudget = Math.max(0, Math.min(options.maxWrites, deps.settings.maxWritesPerDate) - alreadyApplied);
      const writeCandidates = eligibleEntries.filter((entry) => preflight.has(entry.ticket.id));
      let appliedThisRun = 0;

      for (const entry of writeCandidates) {
        if (appliedThisRun >= remainingBudget) {
          const summary = summaries.find((item) => item.ticketId === entry.ticket.id);
          if (summary) summary.action = "capped";
          continue;
        }
        const pre = preflight.get(entry.ticket.id);
        if (!pre) continue;
        const immediatelyBefore = await deps.client.getTicket(entry.ticket.id, { fresh: true });
        if (immediatelyBefore.spam !== true || !ticketWithinWindow(immediatelyBefore, window)) {
          throw new Error(`ticket ${entry.ticket.id} is no longer an eligible source-window spam ticket`);
        }
        const immediateFingerprint = fingerprintTicket(immediatelyBefore);
        if (!fingerprintsEqual(pre.fingerprint, immediateFingerprint)) {
          const summary = summaries.find((item) => item.ticketId === entry.ticket.id);
          if (summary) summary.action = "stale";
          throw new Error(`ticket ${entry.ticket.id} changed immediately before update`);
        }

        const ticketSummary = summaries.find((item) => item.ticketId === entry.ticket.id);
        if (!ticketSummary) throw new Error(`missing run summary entry for ticket ${entry.ticket.id}`);
        const intentId = `${runId}:${entry.ticket.id}`;
        saveRunSummary(options.stateRoot, buildRunSummary({
          ...summaryContext,
          completedAt: new Date().toISOString(),
          mode: "live",
          status: "running",
          pagesFetched,
          rowsFetched,
          candidates: tickets.length + recoveredCount,
          tickets: summaries,
          notificationPending: false,
        }));
        const eventSnapshot = await captureEventSnapshot(deps.client, entry.ticket.id);
        if (eventSnapshot.attribution !== entry.attribution) {
          ticketSummary.trashAttribution = eventSnapshot.attribution;
          ticketSummary.eligible = false;
          ticketSummary.action = "manual_trash";
          continue;
        }

        ticketSummary.intentId = intentId;
        const intent: JournalIntent = {
          type: "intent",
          intentId,
          runId,
          sourceDate: options.sourceDate,
          ticketId: entry.ticket.id,
          at: new Date().toISOString(),
          pre: immediateFingerprint,
          eventBoundary: eventSnapshot.boundary,
          originalTrashedDatetime: immediatelyBefore.trashed_datetime ?? null,
          target: { spam: false, trashed: false },
        };
        appendJournal(options.stateRoot, options.sourceDate, intent);
        let updateResult: TicketUpdateResult | undefined;
        try {
          updateResult = await deps.client.updateTicketSpamState(entry.ticket.id, {
            spam: false,
            trashedDatetime: null,
          });
          const verified = await verifyApplied(
            deps.client,
            intent,
            deps.settings,
            deps.settings.verificationTimeoutMs,
            deps.settings.verificationStabilizationMs,
            deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms))),
          );
          appendJournal(options.stateRoot, options.sourceDate, {
            type: "outcome",
            intentId,
            runId,
            sourceDate: options.sourceDate,
            ticketId: entry.ticket.id,
            at: new Date().toISOString(),
            status: "applied",
            httpStatus: updateResult.httpStatus,
            post: verified.fingerprint,
            postUpdateEvidence: verified.evidence,
          });
          ticketSummary.action = "applied";
          appliedThisRun += 1;
        } catch (error) {
          let recoveryStatus: JournalOutcome["status"] = "ambiguous";
          let post: TicketFingerprint | undefined;
          let postUpdateEvidence: PostUpdateEvidence | undefined;
          try {
            const live = await deps.client.getTicket(entry.ticket.id, { fresh: true });
            post = fingerprintTicket(live);
            if (targetApplied(live)) {
              const transition = await validateAppliedTransition(
                deps.client,
                immediateFingerprint,
                post,
                intent,
                deps.settings,
              );
              if (transition.ok) {
                recoveryStatus = "recovered_applied";
                postUpdateEvidence = transition.evidence;
              }
            } else if (fingerprintsEqual(immediateFingerprint, post)) recoveryStatus = "not_applied";
          } catch {
          }
          appendJournal(options.stateRoot, options.sourceDate, {
            type: "outcome",
            intentId,
            runId,
            sourceDate: options.sourceDate,
            ticketId: entry.ticket.id,
            at: new Date().toISOString(),
            status: recoveryStatus,
            httpStatus: updateResult?.httpStatus,
            post,
            postUpdateEvidence,
            errorCategory: errorCategory(error),
          });
          if (recoveryStatus === "recovered_applied") ticketSummary.action = "applied";
          throw error;
        }
      }
    }

    const capped = summaries.filter((item) => item.action === "capped").length;
    const uncertain = summaries.filter((item) => item.decision.verdict === "uncertain" || item.action === "manual_trash").length;
    const status = capped > 0 ? "complete_capped" : "complete";
    const summary = buildRunSummary({
      ...summaryContext,
      completedAt: new Date().toISOString(),
      status,
      pagesFetched,
      rowsFetched,
      candidates: tickets.length + recoveredCount,
      capped,
      uncertain,
      tickets: summaries,
      notificationPending: trackDayState && (summaries.length > 0 || capped > 0 || uncertain > 0),
    });
    saveRunSummary(options.stateRoot, summary);

    if (trackDayState) {
      const completedState: DayState = {
        ...runningState,
        status,
        completedAt: summary.completedAt,
        notificationPending: summary.notificationPending,
      };
      writeDayState(options.stateRoot, completedState);
      if (summary.notificationPending && deps.notify) {
        const delivered = await deps.notify(buildDigest(summary, deps.client.getSubdomain())).catch(() => false);
        if (delivered) {
          summary.notificationPending = false;
          saveRunSummary(options.stateRoot, summary);
          writeDayState(options.stateRoot, { ...completedState, notificationPending: false });
        }
      }
    }
    return summary;
  } catch (error) {
    const category = errorCategory(error);
    const hash = errorHash(error);
    const priorAlertAt = priorState?.lastAlertedAt ? Date.parse(priorState.lastAlertedAt) : Number.NaN;
    const alertDebounced = priorState?.lastAlertHash === hash
      && Number.isFinite(priorAlertAt)
      && startedAt.getTime() - priorAlertAt < 12 * 3_600_000;
    const notificationPending = trackDayState && !alertDebounced;
    const summary = buildRunSummary({
      ...summaryContext,
      completedAt: new Date().toISOString(),
      status: "failed",
      pagesFetched,
      rowsFetched,
      candidates: tickets.length + recoveredCount,
      tickets: summaries,
      notificationPending,
      errorCategory: category,
      errorHash: hash,
    });
    saveRunSummary(options.stateRoot, summary);
    if (trackDayState) {
      writeDayState(options.stateRoot, {
        ...runningState,
        status: "failed",
        errorCategory: category,
        errorHash: hash,
        notificationPending,
        lastAlertHash: priorState?.lastAlertHash,
        lastAlertedAt: priorState?.lastAlertedAt,
      });
    }
    if (notificationPending && deps.notify) {
      const delivered = await deps.notify(buildFailureAlert(summary, deps.client.getSubdomain())).catch(() => false);
      if (delivered) {
        const lastAlertedAt = startedAt.toISOString();
        summary.notificationPending = false;
        saveRunSummary(options.stateRoot, summary);
        writeDayState(options.stateRoot, {
          ...runningState,
          status: "failed",
          errorCategory: category,
          errorHash: hash,
          notificationPending: false,
          lastAlertHash: hash,
          lastAlertedAt,
        });
      }
    }
    throw error;
  }
}

export async function postSlack(message: string, channel: string): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const config = loadServiceConfig("slack-manager", { schema: SlackConfigSchema });
    const controller = new AbortController();
    timer = setTimeout(() => controller.abort(), 10_000);
    const response = await fetch("https://slack.com/api/chat.postMessage", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.slack.botToken}`,
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify({ channel, text: message }),
      signal: controller.signal,
    });
    const payload = await response.json() as { ok?: boolean };
    return response.ok && payload.ok === true;
  } catch {
    return false;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      due: { type: "boolean", default: false },
      date: { type: "string" },
      live: { type: "boolean", default: false },
      "dry-run": { type: "boolean", default: false },
      "max-writes": { type: "string" },
      "state-root": { type: "string" },
      "ticket-id": { type: "string" },
      "adjudicate-intent": { type: "string" },
    },
    strict: true,
  });
  if (values.due && values.date) throw new Error("use either --due or --date, not both");
  if (values.live && values["dry-run"]) throw new Error("use either --live or --dry-run, not both");
  if (values["adjudicate-intent"] && (!values.live || !values.date || values.due || values["ticket-id"] || values["dry-run"])) {
    throw new Error("--adjudicate-intent requires --live and --date, without --due, --ticket-id, or --dry-run");
  }
  const settings = loadSpamReviewSettings();
  const stateRoot = values["state-root"] ?? DEFAULT_STATE_ROOT;
  if (values.live) {
    const liveHost = resolveLiveHost(settings);
    if (hostname().toLowerCase() !== liveHost.toLowerCase()) {
      throw new Error(`live Gorgias spam review is owned by ${liveHost}; current host is ${hostname()}`);
    }
  }
  if (values.live && resolve(stateRoot) !== resolve(DEFAULT_STATE_ROOT)) {
    throw new Error("live reviews must use the canonical state root so the per-date cap cannot be bypassed");
  }
  const releaseLiveLock = values.live ? acquireLiveLock(stateRoot) : undefined;
  try {
  const client = new GorgiasClient({
    requestIntervalMs: settings.gorgiasRequestIntervalMs,
    readMaxRetries: settings.gorgiasReadMaxRetries,
  });
  if (values["adjudicate-intent"]) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(values.date ?? "")) throw new Error("--date must be YYYY-MM-DD");
    const result = await adjudicateLegacyIntent({
      sourceDate: values.date as string,
      intentId: values["adjudicate-intent"],
      stateRoot,
    }, client, settings);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (values.live) {
    await flushPendingNotifications(
      stateRoot,
      client,
      (message) => postSlack(message, settings.slackChannel),
    );
  }
  let sourceDate = values.date;
  if (!sourceDate) {
    if (!dueWindowOpen(new Date(), settings.timeZone, settings.notBeforeHourLocal)) {
      process.stdout.write(`gorgias-spam-review: due window opens at ${settings.notBeforeHourLocal.toString().padStart(2, "0")}:00 ${settings.timeZone}\n`);
      return;
    }
    const due = selectDueSourceDate(stateRoot, new Date(), settings.catchupDays);
    if (due.overdueBefore && values.live) {
      const overdueProblem = `${settings.catchupDays}:${due.overdueBefore}`;
      if (shouldSendDebouncedAlert(stateRoot, "overdue-backfill", overdueProblem)) {
        const delivered = await postSlack(`:warning: Gorgias spam review has an unprocessed date older than the ${settings.catchupDays}-day automatic catch-up window (${due.overdueBefore}). Manual backfill is required.`, settings.slackChannel);
        if (delivered) recordDebouncedAlert(stateRoot, "overdue-backfill", overdueProblem);
      }
    }
    sourceDate = due.sourceDate ?? undefined;
  }
  if (!sourceDate) {
    process.stdout.write("gorgias-spam-review: no source date is due\n");
    return;
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(sourceDate)) throw new Error("--date must be YYYY-MM-DD");
  windowForSourceDate(sourceDate, settings.timeZone);
  if (values.live && sourceDate > previousSourceDate(new Date(), settings.timeZone)) {
    throw new Error("live reviews may only target completed UK calendar days");
  }
  const requestedMaxWrites = values["max-writes"] ? Number(values["max-writes"]) : settings.maxWritesPerDate;
  if (!Number.isInteger(requestedMaxWrites) || requestedMaxWrites < 1 || requestedMaxWrites > settings.maxWritesPerDate) {
    throw new Error(`--max-writes must be an integer from 1 to ${settings.maxWritesPerDate}`);
  }
  const ticketId = values["ticket-id"] === undefined ? undefined : Number(values["ticket-id"]);
  if (ticketId !== undefined && (!Number.isInteger(ticketId) || ticketId <= 0)) {
    throw new Error("--ticket-id must be a positive integer");
  }

  const classifier = new GeminiSpamClassifier({ model: settings.model });
  const summary = await runSourceDateReview(
    {
      sourceDate,
      live: values.live === true,
      maxWrites: requestedMaxWrites,
      stateRoot,
      ticketId,
    },
    {
      client,
      classifier,
      settings,
      notify: values.live ? (message) => postSlack(message, settings.slackChannel) : undefined,
    },
  );
  process.stdout.write(`${JSON.stringify({
    run_id: summary.runId,
    source_date: summary.sourceDate,
    mode: summary.mode,
    status: summary.status,
    candidates: summary.candidates,
    eligible: summary.eligible,
    applied: summary.applied,
    capped: summary.capped,
  })}\n`);
  } finally {
    releaseLiveLock?.();
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    process.stderr.write(`gorgias-spam-review: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
