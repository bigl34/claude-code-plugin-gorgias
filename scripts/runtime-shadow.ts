#!/usr/bin/env npx tsx

import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { z } from "@local/cli-utils";

import {
  applyClassifierInputRiskFlags,
  buildClassifierInput,
  classifierDecisionSchema,
  eligibleForAutomaticRestore,
  enumerateSpamCandidates,
  trashAttribution,
  windowForSourceDate,
  type TicketReadClient,
} from "./spam-review-core.js";
import { evaluateFreshness } from "./spam-review-freshness.js";
import type { Event, Ticket } from "./gorgias-client.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const BIZ_ROOT = resolve(HERE, "../..");
const RUNTIME_REGISTRY = resolve(BIZ_ROOT, "config/mac-mini-runtime.json");
const REVIEW_SETTINGS = resolve(BIZ_ROOT, "config/gorgias-spam-review.json");
const REVIEW_TASK = "gorgias-spam-review";
const FRESHNESS_TASK = "gorgias-spam-review-freshness";
const TASKS = new Set([REVIEW_TASK, FRESHNESS_TASK]);
const SHADOW_LOCK_GROUP = "gorgias-spam-review-shadow";

const scheduleSchema = z.object({
  kind: z.literal("calendar"),
  intervals: z.array(z.object({
    Hour: z.number().int().min(0).max(23).optional(),
    Minute: z.number().int().min(0).max(59).optional(),
  }).strict()).min(1),
}).strict();

const ticketSchema = z.object({
  id: z.number().int().positive(),
  subject: z.string().min(1),
  status: z.string().min(1),
  priority: z.string().min(1),
  channel: z.string().min(1),
  created_datetime: z.string().min(1),
  updated_datetime: z.string().min(1),
  spam: z.boolean(),
  trashed_datetime: z.string().nullable(),
  is_unread: z.boolean(),
  assignee_user: z.object({ id: z.number().int().positive() }).strict().nullable(),
  assignee_team: z.object({ id: z.number().int().positive() }).strict().nullable(),
  tags: z.array(z.object({
    id: z.number().int().positive(),
    name: z.string().min(1),
  }).strict()),
  messages: z.array(z.object({
    id: z.number().int().positive(),
    ticket_id: z.number().int().positive(),
    created_datetime: z.string().min(1),
    from_agent: z.boolean(),
    body_text: z.string(),
    sender: z.object({
      id: z.number().int().positive(),
      email: z.string().min(1),
    }).strict(),
  }).strict()).min(1),
}).strict();

const eventSchema = z.object({
  id: z.number().int().positive(),
  type: z.string().min(1),
  created_datetime: z.string().min(1),
  user_id: z.number().int().positive().nullable(),
}).strict();

const expectedActionSchema = z.object({
  ticket_id: z.number().int().positive(),
  eligible: z.boolean(),
  action: z.enum(["dry_run", "manual_trash", "none"]),
  trash_attribution: z.enum(["none", "human", "unknown"]),
  risk_flags: classifierDecisionSchema.shape.risk_flags,
}).strict();

const fixtureSchema = z.object({
  schema_version: z.literal(1),
  redacted: z.literal(true),
  schedules: z.object({
    [REVIEW_TASK]: scheduleSchema,
    [FRESHNESS_TASK]: scheduleSchema,
  }).strict(),
  review: z.object({
    source_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    now: z.string().min(1),
    tickets: z.array(ticketSchema).min(4),
    events: z.array(z.object({
      ticket_id: z.number().int().positive(),
      items: z.array(eventSchema),
    }).strict()),
    decisions: z.array(classifierDecisionSchema).min(1),
    expected: z.object({
      rows_fetched: z.number().int().positive(),
      candidates: z.number().int().positive(),
      eligible: z.number().int().nonnegative(),
      applied: z.literal(0),
      actions: z.array(expectedActionSchema).min(1),
    }).strict(),
  }).strict(),
  freshness: z.object({
    cases: z.array(z.object({
      name: z.string().min(1),
      now: z.string().min(1),
      source_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
      completed_age_hours: z.number().min(0).max(168),
      max_age_hours: z.number().min(1).max(168),
      pending_notifications: z.number().int().nonnegative(),
      failed_dates: z.array(z.string().regex(/^\d{4}-\d{2}-\d{2}$/)),
      unresolved_journal_dates: z.array(z.string().regex(/^\d{4}-\d{2}-\d{2}$/)),
      live_lock_age_minutes: z.number().min(0).nullable(),
      state_read_error: z.boolean(),
      expected: z.object({
        healthy: z.boolean(),
        latest_completed_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
        pending_notifications: z.number().int().nonnegative(),
        failed_dates: z.array(z.string().regex(/^\d{4}-\d{2}-\d{2}$/)),
        unresolved_journal_dates: z.array(z.string().regex(/^\d{4}-\d{2}-\d{2}$/)),
        stale_live_lock: z.boolean(),
        state_read_error: z.boolean(),
        problem: z.string().nullable(),
      }).strict(),
    }).strict()).min(2),
  }).strict(),
}).strict();

type ShadowFixture = z.infer<typeof fixtureSchema>;

const replaySettingsSchema = z.object({
  minimumConfidence: z.number().min(0.5).max(1),
  maxCandidates: z.number().int().min(1).max(500),
  maxPages: z.number().int().min(1).max(100),
});

interface RuntimeRegistry {
  tasks: Array<{
    id: string;
    schedule: {
      kind: string;
      intervals?: Array<{ Hour?: number; Minute?: number }>;
    };
  }>;
}

function argumentValue(argv: string[], name: string): string | null {
  const withEquals = argv.find((argument) => argument.startsWith(`${name}=`));
  if (withEquals) return withEquals.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] ?? null : null;
}

function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function assertRuntimeContext(environment: NodeJS.ProcessEnv): void {
  if (environment.YOUR_COMPANY_RUNTIME_MODE !== "shadow") {
    throw new Error("Gorgias shadow replay requires runtime-manager mode=shadow");
  }
  if (environment.YOUR_COMPANY_RUNTIME_LOCK_GROUP !== SHADOW_LOCK_GROUP) {
    throw new Error(`Gorgias shadow replay requires runtime-manager lock group ${SHADOW_LOCK_GROUP}`);
  }
  const forbidden = [
    "CLAUDE_CODE_OAUTH_TOKEN",
    "GEMINI_API_KEY",
    "OPENROUTER_API_KEY",
    "GOOGLE_API_KEY",
    "GORGIAS_API_KEY",
    "SLACK_BOT_TOKEN",
    "SLACK_TOKEN",
  ].filter((name) => Boolean(environment[name]?.trim()));
  if (forbidden.length > 0) {
    throw new Error(`Gorgias shadow replay refuses credential-bearing variables: ${forbidden.join(", ")}`);
  }
}

function assertOutsideBiz(path: string): void {
  if (!isAbsolute(path)) throw new Error("YOUR_COMPANY_RUNTIME_STATE_ROOT must be absolute");
  const rel = relative(BIZ_ROOT, resolve(path));
  if (rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))) {
    throw new Error("Gorgias shadow state must remain outside the Biz checkout");
  }
}

function validateSchedules(fixture: ShadowFixture): void {
  const registry = JSON.parse(readFileSync(RUNTIME_REGISTRY, "utf8")) as RuntimeRegistry;
  for (const taskId of TASKS) {
    const task = registry.tasks.find((candidate) => candidate.id === taskId);
    if (!task || task.schedule.kind !== "calendar") {
      throw new Error(`runtime registry is missing the calendar schedule for ${taskId}`);
    }
    const expected = fixture.schedules[taskId as keyof typeof fixture.schedules];
    if (expected.kind !== task.schedule.kind || !sameJson(expected.intervals, task.schedule.intervals)) {
      throw new Error(`fixture schedule diverges from the runtime registry for ${taskId}`);
    }
  }
}

class FixtureReviewClient implements TicketReadClient {
  readonly tickets: Ticket[];
  readonly ticketsById: Map<number, Ticket>;
  fixtureReads = 0;

  constructor(tickets: Ticket[]) {
    this.tickets = structuredClone(tickets);
    this.ticketsById = new Map(this.tickets.map((ticket) => [ticket.id, ticket]));
    if (this.ticketsById.size !== this.tickets.length) {
      throw new Error("review fixture contains duplicate ticket IDs");
    }
  }

  async listTickets(): Promise<{ data: Ticket[]; meta: { has_more: false } }> {
    this.fixtureReads += 1;
    return { data: structuredClone(this.tickets), meta: { has_more: false } };
  }

  async getTicket(ticketId: number): Promise<Ticket> {
    this.fixtureReads += 1;
    const ticket = this.ticketsById.get(ticketId);
    if (!ticket) throw new Error(`review fixture has no detail for ticket ${ticketId}`);
    return structuredClone(ticket);
  }
}

async function replayReview(fixture: ShadowFixture): Promise<Record<string, unknown>> {
  const now = new Date(fixture.review.now);
  if (!Number.isFinite(now.getTime())) throw new Error("review fixture now is invalid");
  const settings = replaySettingsSchema.parse(
    JSON.parse(readFileSync(REVIEW_SETTINGS, "utf8")),
  );
  const client = new FixtureReviewClient(fixture.review.tickets as Ticket[]);
  const enumeration = await enumerateSpamCandidates(
    client,
    windowForSourceDate(fixture.review.source_date, "Europe/London"),
    {
      maxPages: settings.maxPages,
      maxCandidates: settings.maxCandidates,
    },
  );
  const eventsByTicket = new Map(
    fixture.review.events.map((entry) => [entry.ticket_id, entry.items as Event[]]),
  );
  const decisionsByTicket = new Map(
    fixture.review.decisions.map((decision) => [decision.ticket_id, decision]),
  );
  if (eventsByTicket.size !== fixture.review.events.length) {
    throw new Error("review fixture contains duplicate event groups");
  }
  if (decisionsByTicket.size !== fixture.review.decisions.length) {
    throw new Error("review fixture contains duplicate classifier decisions");
  }

  const actions = enumeration.tickets.map((ticket) => {
    const classifierInput = buildClassifierInput(ticket);
    const raw = decisionsByTicket.get(ticket.id);
    if (!raw) throw new Error(`review fixture has no classifier decision for ticket ${ticket.id}`);
    const decision = applyClassifierInputRiskFlags(
      classifierInput,
      classifierDecisionSchema.parse(raw),
    );
    const events = eventsByTicket.get(ticket.id);
    if (!events) throw new Error(`review fixture has no event group for ticket ${ticket.id}`);
    const attribution = trashAttribution(events);
    const eligible = eligibleForAutomaticRestore(decision, {
      minimumConfidence: settings.minimumConfidence,
      trashRestoreBlocked: attribution !== "none",
    });
    const action = attribution !== "none" && decision.verdict === "legitimate"
      ? "manual_trash" as const
      : eligible
        ? "dry_run" as const
        : "none" as const;
    return {
      ticket_id: ticket.id,
      eligible,
      action,
      trash_attribution: attribution,
      risk_flags: decision.risk_flags,
      classifier_input_messages: classifierInput.messages.length,
    };
  });
  const expectedActions = fixture.review.expected.actions;
  const comparableActions = actions.map(({ classifier_input_messages: _count, ...action }) => action);
  const actual = {
    rows_fetched: enumeration.rowsFetched,
    candidates: enumeration.tickets.length,
    eligible: actions.filter((action) => action.eligible).length,
    applied: 0,
    actions: comparableActions,
  };
  if (!sameJson(actual, {
    ...fixture.review.expected,
    actions: expectedActions,
  })) {
    throw new Error(`review fixture replay diverged: ${JSON.stringify(actual)}`);
  }
  return {
    ...actual,
    fixture_reads: client.fixtureReads,
    fixture_event_reads: actions.length,
    classifier_fixture_requests: actions.length,
    classifier_input_messages: actions.reduce(
      (total, action) => total + action.classifier_input_messages,
      0,
    ),
    gorgias_api_reads: 0,
    gorgias_api_writes: 0,
    gemini_api_requests: 0,
    slack_writes: 0,
  };
}

function replayFreshness(fixture: ShadowFixture): Record<string, unknown> {
  const cases = fixture.freshness.cases.map((fixtureCase) => {
    const now = new Date(fixtureCase.now);
    if (!Number.isFinite(now.getTime())) {
      throw new Error(`freshness fixture now is invalid for ${fixtureCase.name}`);
    }
    const completedAt = new Date(
      now.getTime() - fixtureCase.completed_age_hours * 3_600_000,
    ).toISOString();
    const result = evaluateFreshness({
      latestCompletedDate: fixtureCase.source_date,
      latestCompletedAt: completedAt,
      pendingNotifications: fixtureCase.pending_notifications,
      failedDates: fixtureCase.failed_dates,
      unresolvedJournalDates: fixtureCase.unresolved_journal_dates,
      liveLockAgeMs: fixtureCase.live_lock_age_minutes === null
        ? null
        : fixtureCase.live_lock_age_minutes * 60_000,
      stateReadError: fixtureCase.state_read_error,
    }, now, fixtureCase.max_age_hours);
    const actual = {
      healthy: result.healthy,
      latest_completed_date: result.latestCompletedDate,
      pending_notifications: result.pendingNotifications,
      failed_dates: result.failedDates,
      unresolved_journal_dates: result.unresolvedJournalDates,
      stale_live_lock: result.staleLiveLock,
      state_read_error: result.stateReadError,
      problem: result.problem ?? null,
    };
    if (!sameJson(actual, fixtureCase.expected)) {
      throw new Error(
        `freshness fixture replay diverged for ${fixtureCase.name}: ${JSON.stringify(actual)}`,
      );
    }
    return { name: fixtureCase.name, ...actual };
  });
  return {
    cases,
    gorgias_api_reads: 0,
    slack_writes: 0,
  };
}

function noEffectEvidence(
  taskId: string,
  replay: Record<string, unknown>,
  networkRequests: number,
): Record<string, unknown> {
  return {
    schema_version: 1,
    mode: "shadow",
    task_id: taskId,
    fixture_redacted: true,
    schedule_verified: true,
    credential_reads: 0,
    network_requests: networkRequests,
    process_spawns: 0,
    state_writes: 0,
    log_writes: 0,
    external_writes: 0,
    temporary_state_files: 0,
    replay,
  };
}

export async function runShadow(argv: string[], environment = process.env): Promise<number> {
  assertRuntimeContext(environment);
  const taskId = argumentValue(argv, "--task");
  const fixturePath = argumentValue(argv, "--fixture");
  if (!taskId || !TASKS.has(taskId)) throw new Error("unsupported or missing --task");
  if (!fixturePath) throw new Error("missing --fixture");
  const fixture = fixtureSchema.parse(JSON.parse(readFileSync(resolve(fixturePath), "utf8")));
  validateSchedules(fixture);

  const stateBase = resolve(environment.YOUR_COMPANY_RUNTIME_STATE_ROOT ?? tmpdir());
  assertOutsideBiz(stateBase);

  let networkRequests = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    networkRequests += 1;
    throw new Error("Gorgias shadow replay forbids network access");
  }) as typeof fetch;
  try {
    const replay = taskId === REVIEW_TASK
      ? await replayReview(fixture)
      : replayFreshness(fixture);
    if (networkRequests !== 0) throw new Error("Gorgias shadow replay attempted network access");
    process.stdout.write(`${JSON.stringify(noEffectEvidence(taskId, replay, networkRequests))}\n`);
    return 0;
  } finally {
    globalThis.fetch = originalFetch;
  }
}

const isMain = process.argv[1]?.endsWith("runtime-shadow.ts")
  || process.argv[1]?.endsWith("runtime-shadow.js");
if (isMain) {
  runShadow(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      process.stderr.write(`gorgias-runtime-shadow: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exit(2);
    },
  );
}
