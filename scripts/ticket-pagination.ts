import { createHash } from "node:crypto";
import type { ListResponse, Ticket } from "./gorgias-client.js";

const RESUME_PREFIX = "gorgias-ticket-filter.v1.";

export interface TicketListRow extends Ticket {
  excerpt?: string;
  messages_count?: number;
}

export interface FilteredTicketPaginationOptions {
  limit: number;
  status?: "open" | "closed";
  search?: string;
  orderBy?: string;
  cursor?: string;
  customerId?: number;
  updatedAfter?: string;
  resumeToken?: string;
  maxPages?: number;
}

export interface FilteredTicketPaginationResult {
  tickets: TicketListRow[];
  fetchedPages: number;
  pageLimit: number;
  nextCursor: string | null;
  resumeToken: string | null;
  hasMore: boolean;
  coverageComplete: boolean;
  paginationTruncated: boolean;
}

export interface FilteredTicketReadClient {
  listTickets(options: {
    limit: number;
    orderBy?: string;
    cursor?: string;
    customerId?: number;
  }): Promise<ListResponse<Ticket>>;
}

interface ResumeState {
  filterDigest: string;
  providerCursor: string | null;
  matchedOffset: number;
  pageDigest?: string;
}

export class TicketPaginationFailure extends Error {
  readonly partial: FilteredTicketPaginationResult;

  constructor(message: string, partial: FilteredTicketPaginationResult) {
    super(message);
    this.name = "TicketPaginationFailure";
    this.partial = partial;
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function filterDigest(options: FilteredTicketPaginationOptions, pageLimit: number): string {
  return sha256(JSON.stringify({
    status: options.status ?? null,
    search: options.search?.trim().toLowerCase() ?? null,
    orderBy: options.updatedAfter ? "updated_datetime:desc" : options.orderBy ?? null,
    customerId: options.customerId ?? null,
    updatedAfter: options.updatedAfter ?? null,
    pageLimit,
  }));
}

function encodeResume(state: ResumeState): string {
  return `${RESUME_PREFIX}${Buffer.from(JSON.stringify(state), "utf8").toString("base64url")}`;
}

function decodeResume(token: string): ResumeState {
  if (!token.startsWith(RESUME_PREFIX)) throw new Error("resumeToken is not a Gorgias filtered-ticket checkpoint");
  try {
    const parsed = JSON.parse(Buffer.from(token.slice(RESUME_PREFIX.length), "base64url").toString("utf8")) as Partial<ResumeState>;
    if (
      typeof parsed.filterDigest !== "string"
      || (parsed.providerCursor !== null && typeof parsed.providerCursor !== "string")
      || !Number.isInteger(parsed.matchedOffset)
      || (parsed.matchedOffset ?? -1) < 0
      || (parsed.pageDigest !== undefined && typeof parsed.pageDigest !== "string")
    ) {
      throw new Error("invalid fields");
    }
    return parsed as ResumeState;
  } catch {
    throw new Error("resumeToken is malformed");
  }
}

function pageDigest(rows: TicketListRow[]): string {
  return sha256(JSON.stringify(rows.map((ticket) => ({
    id: ticket.id,
    updated_datetime: ticket.updated_datetime ?? null,
    status: ticket.status ?? null,
    subject: ticket.subject ?? null,
    excerpt: ticket.excerpt ?? null,
  }))));
}

function emptyResult(pageLimit: number, resumeToken: string | null): FilteredTicketPaginationResult {
  return {
    tickets: [],
    fetchedPages: 0,
    pageLimit,
    nextCursor: null,
    resumeToken,
    hasMore: resumeToken !== null,
    coverageComplete: false,
    paginationTruncated: false,
  };
}

function filterPage(
  rows: TicketListRow[],
  options: FilteredTicketPaginationOptions,
  updatedAfterMs: number | null,
): TicketListRow[] {
  const search = options.search?.trim().toLowerCase();
  return rows.filter((ticket) => {
    if (updatedAfterMs !== null) {
      const updatedAt = Date.parse(ticket.updated_datetime ?? "");
      if (Number.isFinite(updatedAt) && updatedAt <= updatedAfterMs) return false;
    }
    if (options.status && ticket.status?.toLowerCase() !== options.status) return false;
    if (search) {
      const subject = (ticket.subject ?? "").toLowerCase();
      const excerpt = (ticket.excerpt ?? "").toLowerCase();
      if (!subject.includes(search) && !excerpt.includes(search)) return false;
    }
    return true;
  });
}

export async function paginateFilteredTickets(
  client: FilteredTicketReadClient,
  options: FilteredTicketPaginationOptions,
  onCheckpoint?: (result: FilteredTicketPaginationResult) => void,
): Promise<FilteredTicketPaginationResult> {
  if (options.cursor && options.resumeToken) throw new Error("use either cursor or resumeToken, not both");
  const updatedAfterMs = options.updatedAfter ? Date.parse(options.updatedAfter) : null;
  if (options.updatedAfter && !Number.isFinite(updatedAfterMs)) {
    throw new Error("updatedAfter must be a valid ISO datetime");
  }
  const needsSparseClientFilter = Boolean(options.status || options.search);
  const needsClientFilter = Boolean(needsSparseClientFilter || options.updatedAfter);
  const pageLimit = needsSparseClientFilter ? 100 : Math.min(options.limit, 100);
  const maxPages = options.maxPages ?? (needsClientFilter ? 25 : Math.max(1, Math.ceil(options.limit / 100)));
  const digest = filterDigest(options, pageLimit);
  const resume = options.resumeToken ? decodeResume(options.resumeToken) : null;
  if (resume && resume.filterDigest !== digest) {
    throw new Error("resumeToken does not match the current ticket filters");
  }

  let providerCursor = resume?.providerCursor ?? options.cursor ?? null;
  let resumeOffset = resume?.matchedOffset ?? 0;
  let expectedPageDigest = resume?.pageDigest;
  let result = emptyResult(
    pageLimit,
    encodeResume({ filterDigest: digest, providerCursor, matchedOffset: resumeOffset, ...(expectedPageDigest ? { pageDigest: expectedPageDigest } : {}) }),
  );
  const seenCursors = new Set<string>();

  while (result.fetchedPages < maxPages) {
    if (providerCursor) {
      if (seenCursors.has(providerCursor)) {
        result = { ...result, resumeToken: null, hasMore: true, paginationTruncated: true };
        onCheckpoint?.(result);
        return result;
      }
      seenCursors.add(providerCursor);
    }

    let page: ListResponse<Ticket>;
    try {
      page = await client.listTickets({
        limit: pageLimit,
        orderBy: options.updatedAfter ? "updated_datetime:desc" : options.orderBy,
        cursor: providerCursor ?? undefined,
        ...(options.customerId !== undefined ? { customerId: options.customerId } : {}),
      });
    } catch (error) {
      const resumable = encodeResume({
        filterDigest: digest,
        providerCursor,
        matchedOffset: resumeOffset,
        ...(expectedPageDigest ? { pageDigest: expectedPageDigest } : {}),
      });
      const partial = {
        ...result,
        resumeToken: resumable,
        hasMore: true,
        coverageComplete: false,
        paginationTruncated: true,
      };
      onCheckpoint?.(partial);
      throw new TicketPaginationFailure(
        error instanceof Error ? error.message : "Gorgias ticket page failed",
        partial,
      );
    }

    const rawRows = (page.data ?? []) as TicketListRow[];
    const currentPageDigest = pageDigest(rawRows);
    if (expectedPageDigest && expectedPageDigest !== currentPageDigest) {
      const partial = { ...result, resumeToken: null, hasMore: true, paginationTruncated: true };
      onCheckpoint?.(partial);
      throw new TicketPaginationFailure("resumeToken page changed since the checkpoint", partial);
    }
    if (resumeOffset > 0 && resumeOffset > filterPage(rawRows, options, updatedAfterMs).length) {
      const partial = { ...result, resumeToken: null, hasMore: true, paginationTruncated: true };
      onCheckpoint?.(partial);
      throw new TicketPaginationFailure("resumeToken offset exceeds the current filtered page", partial);
    }

    const crossedUpdatedWindow = updatedAfterMs !== null && rawRows.some((ticket) => {
      const updatedAt = Date.parse(ticket.updated_datetime ?? "");
      return Number.isFinite(updatedAt) && updatedAt <= updatedAfterMs;
    });
    const matched = filterPage(rawRows, options, updatedAfterMs);
    const remainingMatches = matched.slice(resumeOffset);
    const available = Math.max(0, options.limit - result.tickets.length);
    const consumed = remainingMatches.slice(0, available);
    const nextProviderCursor = page.meta?.next_cursor ?? page.meta?.cursor ?? null;
    const nextOffset = resumeOffset + consumed.length;
    const stoppedInsidePage = consumed.length < remainingMatches.length;
    const reachedLimit = result.tickets.length + consumed.length >= options.limit;

    let nextCursor: string | null = null;
    let resumeToken: string | null = null;
    let hasMore = false;
    let coverageComplete = false;
    let paginationTruncated = result.paginationTruncated;

    if (stoppedInsidePage) {
      resumeToken = encodeResume({
        filterDigest: digest,
        providerCursor,
        matchedOffset: nextOffset,
        pageDigest: currentPageDigest,
      });
      hasMore = true;
    } else if (crossedUpdatedWindow) {
      coverageComplete = true;
    } else if (nextProviderCursor) {
      if (nextProviderCursor === providerCursor || seenCursors.has(nextProviderCursor)) {
        hasMore = true;
        paginationTruncated = true;
      } else {
        nextCursor = nextProviderCursor;
        resumeToken = encodeResume({
          filterDigest: digest,
          providerCursor: nextProviderCursor,
          matchedOffset: 0,
        });
        hasMore = true;
      }
    } else if (
      (options.updatedAfter && rawRows.length >= pageLimit)
      || page.meta?.has_more === true
    ) {
      hasMore = true;
      paginationTruncated = true;
    } else {
      coverageComplete = true;
    }

    result = {
      tickets: [...result.tickets, ...consumed],
      fetchedPages: result.fetchedPages + 1,
      pageLimit,
      nextCursor,
      resumeToken,
      hasMore,
      coverageComplete,
      paginationTruncated,
    };
    onCheckpoint?.(result);

    if (reachedLimit || coverageComplete || !nextProviderCursor || !resumeToken) return result;
    providerCursor = nextProviderCursor;
    resumeOffset = 0;
    expectedPageDigest = undefined;
  }

  result = {
    ...result,
    hasMore: result.resumeToken !== null || result.nextCursor !== null,
    coverageComplete: false,
    paginationTruncated: true,
  };
  onCheckpoint?.(result);
  return result;
}
