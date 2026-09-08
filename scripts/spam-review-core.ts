import { createHash } from "node:crypto";
import { z } from "@local/cli-utils";
import type { Event, ListResponse, Ticket } from "./gorgias-client.js";

export const REVIEW_SCHEMA_VERSION = "gorgias-spam-review.v1";
export const PROMPT_VERSION = "spam-false-positive-2026-07-22.v1";
export const DEFAULT_TIME_ZONE = "Europe/London";

export const classifierDecisionSchema = z.object({
  ticket_id: z.number().int().positive(),
  verdict: z.enum(["legitimate", "spam", "uncertain"]),
  category: z.enum([
    "customer_support",
    "operational_business",
    "marketing",
    "phishing",
    "automated_nonactionable",
    "unknown",
  ]),
  confidence: z.number().min(0).max(1),
  reason: z.string().min(1).max(300),
  evidence_codes: z.array(z.enum([
    "customer_question",
    "order_or_return",
    "product_or_accessibility",
    "operational_notification",
    "existing_conversation",
    "unsolicited_sales",
    "bulk_newsletter",
    "credential_or_platform_impersonation",
    "automated_noise",
    "insufficient_context",
  ])).max(8),
  risk_flags: z.array(z.enum([
    "prompt_injection",
    "insufficient_context",
    "ambiguous_intent",
    "truncated_input",
    "attachment_only",
  ])).max(5),
}).strict();

export type ClassifierDecision = z.infer<typeof classifierDecisionSchema>;

export interface DayWindow {
  sourceDate: string;
  timeZone: string;
  start: Date;
  end: Date;
}

export interface ClassifierInput {
  _trust: "untrusted_customer_content";
  ticket_id: number;
  channel: string;
  subject: string;
  sender_domain: string;
  messages: Array<{ created_datetime: string; text: string }>;
  truncated: boolean;
}

export interface TicketFingerprint {
  ticketId: number;
  updatedDatetime: string;
  spam: boolean;
  trashed: boolean;
  status: string;
  priority?: string;
  assigneeUserId: number | null;
  assigneeTeamId: number | null;
  unread: boolean | null;
  tagIds: number[];
  latestMessageId: number | null;
  latestMessageDatetime: string | null;
  contentHash: string;
}

export interface EventBoundary {
  eventId: number | null;
  createdDatetime: string | null;
}

export interface AllowedPostUpdateAutomation {
  kind: "assignment";
  ruleId: number;
  ruleName: string;
  actorUserId: number;
  fromAssigneeUserId: number | null;
  toAssigneeUserId: number;
  maxDelayMs: number;
}

export interface PostUpdateEvidence {
  kind: "unspam" | "allowed_assignment";
  actorUserId: number;
  eventIds: number[];
  ruleId?: number;
  assigneeUserId?: number;
}

export interface EnumeratedCandidates {
  tickets: Ticket[];
  pagesFetched: number;
  rowsFetched: number;
}

export interface ProviderSpamAssessment {
  likelyProviderIngress: boolean;
  evidenceCodes: Array<
    "email_channel" | "spam_at_read" | "unassigned" | "no_marked_spam_event" | "no_rule_execution"
  >;
}

export interface TicketReadClient {
  listTickets(options: {
    limit: number;
    orderBy: string;
    cursor?: string;
    fresh: boolean;
  }): Promise<ListResponse<Ticket>>;
  getTicket(ticketId: number, options: { fresh: boolean }): Promise<Ticket>;
}

function localParts(instant: Date, timeZone: string): Record<string, number> {
  const formatter = new Intl.DateTimeFormat("en-GB", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const out: Record<string, number> = {};
  for (const part of formatter.formatToParts(instant)) {
    if (part.type !== "literal") out[part.type] = Number(part.value);
  }
  return out;
}

function zonedMidnightUtc(sourceDate: string, timeZone: string): Date {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(sourceDate);
  if (!match) throw new Error(`invalid source date: ${sourceDate}`);
  const desired = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]), 0, 0, 0);
  if (new Date(desired).toISOString().slice(0, 10) !== sourceDate) {
    throw new Error(`invalid source date: ${sourceDate}`);
  }
  let guess = desired;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const parts = localParts(new Date(guess), timeZone);
    const represented = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
    const correction = desired - represented;
    guess += correction;
    if (correction === 0) break;
  }
  return new Date(guess);
}

function addCalendarDays(sourceDate: string, days: number): string {
  const [year, month, day] = sourceDate.split("-").map(Number);
  const next = new Date(Date.UTC(year, month - 1, day + days));
  return next.toISOString().slice(0, 10);
}

export function shiftSourceDate(sourceDate: string, days: number): string {
  return addCalendarDays(sourceDate, days);
}

export function windowForSourceDate(
  sourceDate: string,
  timeZone = DEFAULT_TIME_ZONE,
): DayWindow {
  return {
    sourceDate,
    timeZone,
    start: zonedMidnightUtc(sourceDate, timeZone),
    end: zonedMidnightUtc(addCalendarDays(sourceDate, 1), timeZone),
  };
}

export function previousSourceDate(now = new Date(), timeZone = DEFAULT_TIME_ZONE): string {
  const parts = localParts(now, timeZone);
  const today = `${parts.year.toString().padStart(4, "0")}-${parts.month.toString().padStart(2, "0")}-${parts.day.toString().padStart(2, "0")}`;
  return addCalendarDays(today, -1);
}

export function dueWindowOpen(now: Date, timeZone: string, notBeforeHourLocal: number): boolean {
  if (!Number.isInteger(notBeforeHourLocal) || notBeforeHourLocal < 0 || notBeforeHourLocal > 23) {
    throw new Error("not-before hour must be an integer from 0 to 23");
  }
  return localParts(now, timeZone).hour >= notBeforeHourLocal;
}

export function sourceDatesBetween(startDate: string, endDate: string): string[] {
  const out: string[] = [];
  for (let current = startDate; current <= endDate; current = addCalendarDays(current, 1)) {
    out.push(current);
    if (out.length > 370) throw new Error("source date range is unexpectedly large");
  }
  return out;
}

function parseCreated(ticket: Ticket): number {
  if (!Number.isInteger(ticket.id) || ticket.id <= 0) throw new Error("ticket has invalid ID");
  const parsed = Date.parse(ticket.created_datetime);
  if (!Number.isFinite(parsed)) throw new Error(`ticket ${ticket.id} has invalid created_datetime`);
  return parsed;
}

export async function enumerateSpamCandidates(
  client: TicketReadClient,
  window: DayWindow,
  options: { maxPages: number; maxCandidates: number },
): Promise<EnumeratedCandidates> {
  const limit = 100;
  const startMs = window.start.getTime();
  const endMs = window.end.getTime();
  const seenCursors = new Set<string>();
  const seenIds = new Set<number>();
  const candidateRows: Ticket[] = [];
  let cursor: string | undefined;
  let pagesFetched = 0;
  let rowsFetched = 0;
  let previousCreated = Number.POSITIVE_INFINITY;
  let complete = false;

  while (pagesFetched < options.maxPages) {
    if (cursor) {
      if (seenCursors.has(cursor)) throw new Error("Gorgias ticket cursor loop detected");
      seenCursors.add(cursor);
    }
    const page = await client.listTickets({
      limit,
      orderBy: "created_datetime:desc",
      cursor,
      fresh: true,
    });
    pagesFetched += 1;
    const rows = page.data ?? [];
    rowsFetched += rows.length;
    let crossedLowerBound = false;

    for (const ticket of rows) {
      const created = parseCreated(ticket);
      if (created > previousCreated) throw new Error("Gorgias ticket ordering was not descending");
      previousCreated = created;
      if (created < startMs) crossedLowerBound = true;
      if (created >= startMs && created < endMs && ticket.spam === true && !seenIds.has(ticket.id)) {
        seenIds.add(ticket.id);
        candidateRows.push(ticket);
        if (candidateRows.length > options.maxCandidates) {
          throw new Error(`spam candidate overflow: more than ${options.maxCandidates}`);
        }
      }
    }

    const nextCursor = page.meta?.next_cursor ?? page.meta?.cursor;
    if (crossedLowerBound || rows.length === 0) {
      complete = true;
      break;
    }
    if (!nextCursor) {
      if (page.meta?.has_more === true || (rows.length >= limit && rows.every((ticket) => parseCreated(ticket) >= startMs))) {
        throw new Error("Gorgias pagination ended on a full page before the lower date boundary");
      }
      complete = true;
      break;
    }
    if (nextCursor === cursor || seenCursors.has(nextCursor)) {
      throw new Error("Gorgias returned a repeated ticket cursor");
    }
    cursor = nextCursor;
  }

  if (!complete) throw new Error(`Gorgias pagination exceeded ${options.maxPages} pages`);

  const tickets: Ticket[] = [];
  for (const row of candidateRows) {
    const detail = await client.getTicket(row.id, { fresh: true });
    const created = parseCreated(detail);
    if (created < startMs || created >= endMs || detail.spam !== true) continue;
    tickets.push(detail);
  }

  return { tickets, pagesFetched, rowsFetched };
}

function stripHtml(value: string): string {
  return value
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/gi, "\"");
}

function normalizeText(value: string): string {
  return value.replace(/\r\n/g, "\n").replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
}

export function buildClassifierInput(ticket: Ticket): ClassifierInput {
  const allInbound = [...(ticket.messages ?? [])]
    .filter((message) => message.from_agent === false)
    .sort((a, b) => Date.parse(a.created_datetime) - Date.parse(b.created_datetime));
  const inbound = allInbound.slice(-3);
  let remaining = 12_000;
  let truncated = allInbound.length > inbound.length || (ticket.subject ?? "").length > 1_000;
  const messages: ClassifierInput["messages"] = [];
  for (const message of inbound) {
    const raw = message.stripped_text ?? message.body_text ?? stripHtml(message.body_html ?? "");
    const normalized = normalizeText(raw);
    const text = normalized.slice(0, Math.min(4_000, remaining));
    if (text.length < normalized.length) truncated = true;
    remaining -= text.length;
    messages.push({ created_datetime: message.created_datetime, text });
    if (remaining <= 0) {
      truncated = true;
      break;
    }
  }
  const lastInbound = inbound.at(-1);
  const sender = lastInbound?.sender?.email ?? ticket.customer?.email ?? "";
  const at = sender.lastIndexOf("@");
  return {
    _trust: "untrusted_customer_content",
    ticket_id: ticket.id,
    channel: ticket.channel ?? "unknown",
    subject: normalizeText(ticket.subject ?? "").slice(0, 1_000),
    sender_domain: at >= 0 ? sender.slice(at + 1).toLowerCase().slice(0, 253) : "",
    messages,
    truncated,
  };
}

export function applyClassifierInputRiskFlags(
  input: ClassifierInput,
  raw: ClassifierDecision,
): ClassifierDecision {
  const riskFlags = [...raw.risk_flags];
  if (input.truncated && !riskFlags.includes("truncated_input")) {
    riskFlags.push("truncated_input");
  }
  if (
    input.messages.every((message) => message.text.length === 0)
    && !riskFlags.includes("attachment_only")
  ) {
    riskFlags.push("attachment_only");
  }
  return { ...raw, risk_flags: riskFlags };
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function fingerprintTicket(ticket: Ticket): TicketFingerprint {
  const updatedMs = Date.parse(ticket.updated_datetime ?? "");
  if (!Number.isFinite(updatedMs)) throw new Error(`ticket ${ticket.id} has invalid updated_datetime`);
  const messages = [...(ticket.messages ?? [])].sort((a, b) => {
    const time = Date.parse(a.created_datetime) - Date.parse(b.created_datetime);
    return time || a.id - b.id;
  });
  const latest = messages.at(-1);
  const content = messages.map((message) => ({
    id: message.id,
    created: message.created_datetime,
    fromAgent: message.from_agent,
    text: message.stripped_text ?? message.body_text ?? message.body_html ?? "",
  }));
  return {
    ticketId: ticket.id,
    updatedDatetime: new Date(updatedMs).toISOString(),
    spam: ticket.spam === true,
    trashed: Boolean(ticket.trashed_datetime),
    status: ticket.status,
    priority: ticket.priority,
    assigneeUserId: ticket.assignee_user?.id ?? null,
    assigneeTeamId: ticket.assignee_team?.id ?? null,
    unread: typeof ticket.is_unread === "boolean" ? ticket.is_unread : null,
    tagIds: (ticket.tags ?? []).map((tag) => tag.id).sort((a, b) => a - b),
    latestMessageId: latest?.id ?? null,
    latestMessageDatetime: latest?.created_datetime ?? ticket.last_message_datetime ?? null,
    contentHash: sha256(JSON.stringify({ subject: ticket.subject ?? "", content })),
  };
}

export function fingerprintsEqual(a: TicketFingerprint, b: TicketFingerprint): boolean {
  return a.ticketId === b.ticketId
    && a.updatedDatetime === b.updatedDatetime
    && a.spam === b.spam
    && a.trashed === b.trashed
    && a.status === b.status
    && (a.priority === undefined || b.priority === undefined || a.priority === b.priority)
    && a.assigneeUserId === b.assigneeUserId
    && a.assigneeTeamId === b.assigneeTeamId
    && a.unread === b.unread
    && JSON.stringify(a.tagIds) === JSON.stringify(b.tagIds)
    && a.latestMessageId === b.latestMessageId
    && a.latestMessageDatetime === b.latestMessageDatetime
    && a.contentHash === b.contentHash;
}

export function assessProviderSpamIngress(ticket: Ticket, events: Event[]): ProviderSpamAssessment {
  const eventTypes = events.map((event) => event.type.toLowerCase());
  const evidenceCodes: ProviderSpamAssessment["evidenceCodes"] = [];
  if (ticket.channel?.toLowerCase() === "email") evidenceCodes.push("email_channel");
  if (ticket.spam === true) evidenceCodes.push("spam_at_read");
  if (!ticket.assignee_user && !ticket.assignee_team) evidenceCodes.push("unassigned");
  if (!eventTypes.includes("ticket-marked-spam")) evidenceCodes.push("no_marked_spam_event");
  if (!eventTypes.includes("rule-executed")) evidenceCodes.push("no_rule_execution");
  return {
    likelyProviderIngress: evidenceCodes.length === 5,
    evidenceCodes,
  };
}

function eventData(event: Event): Record<string, unknown> | null {
  return event.data !== null && typeof event.data === "object" && !Array.isArray(event.data)
    ? event.data as Record<string, unknown>
    : null;
}

function eventTime(event: Event): number {
  const parsed = Date.parse(event.created_datetime);
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

function fieldsExceptUserAssignmentPreserved(before: TicketFingerprint, after: TicketFingerprint): boolean {
  return before.ticketId === after.ticketId
    && before.status === after.status
    && (before.priority === undefined || before.priority === after.priority)
    && before.assigneeTeamId === after.assigneeTeamId
    && before.unread === after.unread
    && JSON.stringify(before.tagIds) === JSON.stringify(after.tagIds)
    && before.latestMessageId === after.latestMessageId
    && before.latestMessageDatetime === after.latestMessageDatetime
    && before.contentHash === after.contentHash;
}

export function validatePostUpdateTransition(
  before: TicketFingerprint,
  after: TicketFingerprint,
  events: Event[],
  boundary: EventBoundary,
  intentAt: string,
  mutationActorUserId: number,
  allowedAutomations: AllowedPostUpdateAutomation[],
): { ok: true; evidence: PostUpdateEvidence } | { ok: false } {
  if (after.spam || after.trashed || !fieldsExceptUserAssignmentPreserved(before, after)) return { ok: false };
  const intentMs = Date.parse(intentAt);
  const boundaryMs = boundary.createdDatetime ? Date.parse(boundary.createdDatetime) : intentMs;
  if (!Number.isFinite(intentMs) || !Number.isFinite(boundaryMs)) return { ok: false };

  const postEvents = events
    .filter((event) => {
      const created = eventTime(event);
      if (!Number.isFinite(created) || created < boundaryMs) return false;
      return boundary.eventId === null || event.id > boundary.eventId;
    })
    .sort((a, b) => eventTime(a) - eventTime(b) || a.id - b.id);
  if (postEvents.length === 0 || new Set(postEvents.map((event) => event.id)).size !== postEvents.length) {
    return { ok: false };
  }

  const unmarked = postEvents.filter((event) => event.type.toLowerCase() === "ticket-unmarked-spam");
  if (unmarked.length !== 1 || unmarked[0].user_id !== mutationActorUserId) return { ok: false };
  const housekeeping = postEvents.filter((event) => event.type.toLowerCase() === "ticket-updated");
  if (housekeeping.length > 4 || housekeeping.some((event) => {
    const data = eventData(event);
    return event.user_id !== mutationActorUserId || (data !== null && Object.keys(data).length !== 0);
  })) return { ok: false };

  if (before.assigneeUserId === after.assigneeUserId) {
    if (postEvents.some((event) => !["ticket-updated", "ticket-unmarked-spam"].includes(event.type.toLowerCase()))) {
      return { ok: false };
    }
    return {
      ok: true,
      evidence: { kind: "unspam", actorUserId: mutationActorUserId, eventIds: postEvents.map((event) => event.id) },
    };
  }

  const automation = allowedAutomations.find((candidate) =>
    candidate.kind === "assignment"
    && candidate.actorUserId === mutationActorUserId
    && candidate.fromAssigneeUserId === before.assigneeUserId
    && candidate.toAssigneeUserId === after.assigneeUserId);
  if (!automation) return { ok: false };
  if (postEvents.some((event) => ![
    "ticket-updated",
    "ticket-unmarked-spam",
    "rule-executed",
    "ticket-assigned",
  ].includes(event.type.toLowerCase()))) return { ok: false };
  if (postEvents.some((event) => eventTime(event) - intentMs > automation.maxDelayMs)) return { ok: false };

  const rules = postEvents.filter((event) => event.type.toLowerCase() === "rule-executed");
  const assignments = postEvents.filter((event) => event.type.toLowerCase() === "ticket-assigned");
  if (rules.length !== 1 || assignments.length !== 1) return { ok: false };
  const ruleData = eventData(rules[0]);
  const assignmentData = eventData(assignments[0]);
  if (
    rules[0].user_id !== null
    || ruleData?.id !== automation.ruleId
    || ruleData.name !== automation.ruleName
    || ruleData.triggering_event_type !== "ticket-updated"
    || assignments[0].user_id !== mutationActorUserId
    || assignmentData?.assignee_user_id !== automation.toAssigneeUserId
    || Object.keys(assignmentData ?? {}).length !== 1
    || eventTime(unmarked[0]) >= eventTime(rules[0])
    || eventTime(rules[0]) >= eventTime(assignments[0])
  ) return { ok: false };

  return {
    ok: true,
    evidence: {
      kind: "allowed_assignment",
      actorUserId: mutationActorUserId,
      eventIds: postEvents.map((event) => event.id),
      ruleId: automation.ruleId,
      assigneeUserId: automation.toAssigneeUserId,
    },
  };
}

export type TrashAttribution = "none" | "human" | "unknown";

export function trashAttribution(events: Event[]): TrashAttribution {
  const markingEvents = new Set([
    "ticket-marked-spam",
    "ticket-trashed",
  ]);
  const relevant = events.filter((event) => markingEvents.has((event.type ?? "").toLowerCase()));
  if (relevant.some((event) => typeof event.user_id === "number" || typeof event.user?.id === "number")) return "human";
  if (relevant.some((event) => event.user_id === undefined && typeof event.user?.id !== "number")) return "unknown";
  return "none";
}

export function eligibleForAutomaticRestore(
  decision: ClassifierDecision,
  options: { minimumConfidence: number; trashRestoreBlocked: boolean },
): boolean {
  return decision.verdict === "legitimate"
    && (decision.category === "customer_support" || decision.category === "operational_business")
    && decision.confidence >= options.minimumConfidence
    && decision.risk_flags.length === 0
    && !options.trashRestoreBlocked;
}

export function redactAuditText(value: string): string {
  return value
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[email]")
    .replace(/\b(?:\+?\d[\d ()-]{7,}\d)\b/g, "[phone]")
    .slice(0, 300);
}
