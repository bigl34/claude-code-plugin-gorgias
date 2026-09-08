import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import {
  type Customer,
  type GorgiasClient,
  type ListResponse,
  type Message,
  type Ticket,
} from "./gorgias-client.js";
import {
  createRunCrypto,
  loadOrCreateRunKey,
  loadRunKey,
  openEncryptedRecord,
  sealEncryptedRecord,
  type RunCrypto,
} from "./customer-match-evidence.js";
import {
  extractCustomerMatchRecord,
  extractMessageMatchRecord,
  type CustomerMatchRecord,
  type MessageMatchRecord,
} from "./customer-match-records.js";

export interface CustomerMatchReadClient {
  listCustomers(options?: Parameters<GorgiasClient["listCustomers"]>[0]): Promise<ListResponse<Customer>>;
  getCustomer(id: number): Promise<Customer>;
  getTicket?(id: number): Promise<Ticket>;
  listTickets(options?: Parameters<GorgiasClient["listTickets"]>[0]): Promise<ListResponse<Ticket>>;
  listMessages(options?: Parameters<GorgiasClient["listMessages"]>[0]): Promise<ListResponse<Message>>;
}

export interface CoverageLedger {
  endpoint: string;
  pages: number;
  count: number;
  totalCount?: number;
  cursors: string[];
  duplicateIds: number[];
  cursorLoop: boolean;
  digest: string;
  complete: boolean;
  errors: string[];
}

export interface CursorRecord {
  id: number;
  created_datetime?: string;
  updated_datetime?: string;
}

export interface MessageCoverage {
  complete: boolean;
  method: "authoritative_total" | "per_ticket_reconciliation" | "per_ticket_reconciliation_with_unlisted_tickets" | "unproven";
  globalCount: number;
  reconciledCount: number;
  missingFromGlobal: number[];
  extraInGlobal: number[];
  unlistedTicketMessages: number[];
}

export interface TicketMatchRecord {
  kind: "ticket";
  ticketId: number;
  customerId?: number;
  spam: boolean;
  trashed: boolean;
  createdDatetime?: string;
  updatedDatetime?: string;
  revision: string;
}

export type CustomerMatchStageRecord =
  | (CustomerMatchRecord & { revision: string })
  | TicketMatchRecord
  | (MessageMatchRecord & { revision: string });

export interface CustomerMatchScanResult {
  schema: "gorgias-customer-match-scan.v2";
  scanComplete: boolean;
  runDir: string;
  stagePath: string;
  keyId: string;
  stabilizationPasses: number;
  customerDrift: number;
  retries: number;
  ledgers: {
    customers: CoverageLedger;
    tickets: CoverageLedger;
    messages: CoverageLedger;
  };
  messageCoverage: MessageCoverage;
  recordCounts: {
    customers: number;
    tickets: number;
    messages: number;
    quarantinedMessages: number;
  };
  errors: string[];
}

export function createCustomerMatchReadClient(client: GorgiasClient): CustomerMatchReadClient {
  client.disableCache();
  return {
    listCustomers: (options) => client.listCustomers(options),
    getCustomer: (id) => client.getCustomer(id),
    getTicket: (id) => client.getTicket(id),
    listTickets: (options) => client.listTickets(options),
    listMessages: (options) => client.listMessages(options),
  };
}

function buildTicketStageRecord(ticket: Ticket): TicketMatchRecord {
  const customerId = ticketCustomerId(ticket);
  return {
    kind: "ticket",
    ticketId: ticket.id,
    ...(customerId ? { customerId } : {}),
    spam: ticket.spam === true,
    trashed: Boolean(ticket.trashed_datetime),
    ...(ticket.created_datetime ? { createdDatetime: ticket.created_datetime } : {}),
    ...(ticket.updated_datetime ? { updatedDatetime: ticket.updated_datetime } : {}),
    revision: revisionFor(ticket),
  };
}

function compactStableStage(
  path: string,
  crypto: ReturnType<typeof createRunCrypto>,
  customers: Customer[],
  tickets: Ticket[],
  messages: Message[],
  defaultCountry: string,
): void {
  const staged = stageRecords(path, crypto);
  const customerByRevision = new Map(
    staged
      .filter((record): record is CustomerMatchRecord & { revision: string } => record.kind === "customer")
      .filter((record) => record.revision === customerStageRevision(record))
      .map((record) => [`${record.customerId}:${record.revision}`, record]),
  );
  const finalRecords: CustomerMatchStageRecord[] = [];
  for (const customer of [...customers].sort((a, b) => a.id - b.id)) {
    const revision = revisionFor(customer);
    const record = customerByRevision.get(`${customer.id}:${revision}`);
    if (!record) throw new Error(`stable customer ${customer.id} is missing its encrypted detail revision`);
    finalRecords.push(record);
  }

  const ticketById = new Map(tickets.map((ticket) => [ticket.id, ticket]));
  for (const ticket of [...tickets].sort((a, b) => a.id - b.id)) {
    finalRecords.push(buildTicketStageRecord(ticket));
  }
  for (const message of [...messages].sort((a, b) => a.id - b.id)) {
    const ticket = ticketById.get(message.ticket_id);
    finalRecords.push({
      ...extractMessageMatchRecord(message, {
        customerId: ticket ? ticketCustomerId(ticket) : undefined,
        spam: ticket?.spam === true,
        trashed: Boolean(ticket?.trashed_datetime),
        defaultCountry,
      }),
      revision: revisionFor(message),
    });
  }

  const temporary = `${path}.compact-${process.pid}`;
  writeFileSync(temporary, finalRecords.map((record) => sealEncryptedRecord(crypto, record)).join("\n") + (finalRecords.length ? "\n" : ""), {
    mode: 0o600,
  });
  renameSync(temporary, path);
  chmodSync(path, 0o600);
}

function recordDigest(records: CursorRecord[]): string {
  const stable = [...records]
    .sort((a, b) => a.id - b.id)
    .map((record) => [record.id, record.updated_datetime ?? record.created_datetime ?? null]);
  return createHash("sha256").update(JSON.stringify(stable), "utf8").digest("hex");
}

export async function enumerateCursorRecords<T extends CursorRecord>(options: {
  endpoint: string;
  fetchPage(cursor: string | undefined): Promise<ListResponse<T>>;
  maxPages?: number;
}): Promise<{ records: T[]; ledger: CoverageLedger }> {
  const records: T[] = [];
  const byId = new Map<number, T>();
  const cursors: string[] = [];
  const seenCursors = new Set<string>();
  const duplicateIds = new Set<number>();
  const errors: string[] = [];
  const maxPages = options.maxPages ?? 100_000;
  let cursor: string | undefined;
  let cursorLoop = false;
  let totalCount: number | undefined;
  let pages = 0;

  while (pages < maxPages) {
    if (cursor) {
      if (seenCursors.has(cursor)) {
        cursorLoop = true;
        errors.push(`${options.endpoint} cursor loop detected`);
        break;
      }
      seenCursors.add(cursor);
      cursors.push(cursor);
    }

    const page = await options.fetchPage(cursor);
    pages += 1;
    if (!Array.isArray(page.data)) {
      errors.push(`${options.endpoint} response is missing its data array`);
      break;
    }
    const pageTotal = page.meta?.total_count;
    if (pageTotal !== undefined) {
      if (totalCount !== undefined && totalCount !== pageTotal) {
        errors.push(`${options.endpoint} authoritative total changed during enumeration`);
      }
      totalCount = pageTotal;
    }

    for (const record of page.data) {
      if (!Number.isInteger(record.id)) {
        errors.push(`${options.endpoint} returned a record without a numeric id`);
        continue;
      }
      if (byId.has(record.id)) {
        duplicateIds.add(record.id);
        continue;
      }
      byId.set(record.id, record);
      records.push(record);
    }

    const nextCursor = page.meta?.next_cursor ?? page.meta?.cursor ?? undefined;
    if (!nextCursor) break;
    if (seenCursors.has(nextCursor)) {
      cursorLoop = true;
      errors.push(`${options.endpoint} cursor loop detected`);
      break;
    }
    cursor = nextCursor;
  }

  if (pages >= maxPages && cursor) errors.push(`${options.endpoint} exceeded the page limit`);
  if (duplicateIds.size > 0) errors.push(`${options.endpoint} returned duplicate record ids`);
  if (totalCount !== undefined && byId.size !== totalCount) {
    errors.push(`${options.endpoint} count does not match authoritative total`);
  }

  records.sort((a, b) => a.id - b.id);
  const ledger: CoverageLedger = {
    endpoint: options.endpoint,
    pages,
    count: records.length,
    ...(totalCount !== undefined ? { totalCount } : {}),
    cursors,
    duplicateIds: [...duplicateIds].sort((a, b) => a - b),
    cursorLoop,
    digest: recordDigest(records),
    complete: errors.length === 0,
    errors,
  };
  return { records, ledger };
}

export function proveMessageCoverage<T extends { id: number; ticket_id?: number }>(
  globalMessages: T[],
  authoritativeTotal?: number,
  perTicketMessages?: T[],
  listedTicketIds?: ReadonlySet<number>,
  unavailableTicketIds?: ReadonlySet<number>,
): MessageCoverage {
  const globalIds = new Set(globalMessages.map((message) => message.id));
  if (authoritativeTotal !== undefined) {
    return {
      complete: globalIds.size === authoritativeTotal,
      method: "authoritative_total",
      globalCount: globalIds.size,
      reconciledCount: authoritativeTotal,
      missingFromGlobal: [],
      extraInGlobal: [],
      unlistedTicketMessages: [],
    };
  }

  if (!perTicketMessages) {
    return {
      complete: false,
      method: "unproven",
      globalCount: globalIds.size,
      reconciledCount: 0,
      missingFromGlobal: [],
      extraInGlobal: [],
      unlistedTicketMessages: [],
    };
  }

  const reconciledIds = new Set(perTicketMessages.map((message) => message.id));
  const missingFromGlobal = [...reconciledIds].filter((id) => !globalIds.has(id)).sort((a, b) => a - b);
  const extraInGlobal = [...globalIds].filter((id) => !reconciledIds.has(id)).sort((a, b) => a - b);
  const extraIds = new Set(extraInGlobal);
  const extraRecords = globalMessages.filter((message) => extraIds.has(message.id));
  const unlistedTicketMessages = listedTicketIds
    ? extraRecords
      .filter((message) => typeof message.ticket_id === "number"
        && Number.isSafeInteger(message.ticket_id)
        && message.ticket_id > 0
        && !listedTicketIds.has(message.ticket_id)
        && unavailableTicketIds?.has(message.ticket_id) === true)
      .map((message) => message.id)
      .sort((a, b) => a - b)
    : [];
  const acceptedUnlisted = new Set(unlistedTicketMessages);
  const unexpectedExtra = extraInGlobal.filter((id) => !acceptedUnlisted.has(id));
  const complete = missingFromGlobal.length === 0 && unexpectedExtra.length === 0;
  return {
    complete,
    method: complete && unlistedTicketMessages.length > 0
      ? "per_ticket_reconciliation_with_unlisted_tickets"
      : "per_ticket_reconciliation",
    globalCount: globalIds.size,
    reconciledCount: reconciledIds.size,
    missingFromGlobal,
    extraInGlobal,
    unlistedTicketMessages,
  };
}

function atomicWriteJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
  chmodSync(path, 0o600);
}

function stageRecords(path: string, crypto: RunCrypto): CustomerMatchStageRecord[] {
  if (!existsSync(path)) return [];
  const raw = readFileSync(path, "utf8");
  if (!raw.trim()) return [];
  return raw.trimEnd().split("\n").map((line) => openEncryptedRecord<CustomerMatchStageRecord>(crypto, line));
}

function appendStageRecord(path: string, crypto: RunCrypto, record: CustomerMatchStageRecord): void {
  appendFileSync(path, `${sealEncryptedRecord(crypto, record)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

export function loadCustomerMatchStage(options: {
  stagePath: string;
  keyPath: string;
  expectedKeyId?: string;
}): { records: CustomerMatchStageRecord[]; crypto: RunCrypto } {
  const key = readFileSync(options.keyPath);
  if (key.length !== 32) throw new Error("customer match run key has invalid length");
  chmodSync(options.keyPath, 0o600);
  const crypto = createRunCrypto(key);
  if (options.expectedKeyId && crypto.keyId !== options.expectedKeyId) {
    throw new Error("customer match stage key does not match the scan ledger");
  }
  return {
    records: stageRecords(options.stagePath, crypto),
    crypto,
  };
}

function revisionFor(record: CursorRecord): string {
  return record.updated_datetime ?? record.created_datetime ?? "unknown";
}

function customerStageRevision(record: CustomerMatchRecord): string {
  return record.updatedDatetime ?? record.createdDatetime ?? "unknown";
}

function ticketCustomerId(ticket: Ticket): number | undefined {
  const id = Number(ticket.customer?.id);
  return Number.isInteger(id) && id > 0 ? id : undefined;
}

function retryableStatus(error: unknown): number | undefined {
  if (!error || typeof error !== "object") return undefined;
  const status = (error as { status?: unknown }).status;
  return typeof status === "number" ? status : undefined;
}

export async function runCustomerMatchScan(options: {
  client: CustomerMatchReadClient;
  runDir: string;
  keyPath: string;
  defaultCountry: string;
  expectedCustomerCount?: number;
  requestIntervalMs?: number;
  maxRetries?: number;
  maxStabilizationPasses?: number;
  resume?: boolean;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}): Promise<CustomerMatchScanResult> {
  const requestIntervalMs = options.requestIntervalMs ?? 1_000;
  const maxRetries = options.maxRetries ?? 5;
  const maxStabilizationPasses = options.maxStabilizationPasses ?? 6;
  const sleep = options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const now = options.now ?? Date.now;
  mkdirSync(options.runDir, { recursive: true, mode: 0o700 });
  chmodSync(options.runDir, 0o700);
  const lockDir = join(options.runDir, "scan.lock");
  try {
    mkdirSync(lockDir, { mode: 0o700 });
  } catch {
    throw new Error("customer match scan found an active run lock");
  }

  const stagePath = join(options.runDir, "evidence-stage.jsonl.enc");
  const resultPath = join(options.runDir, "scan.json");
  try {
    if (!options.resume && existsSync(stagePath) && statSync(stagePath).size > 0) {
      throw new Error("customer match run directory already contains staging data; use --resume or a new run directory");
    }
    const hasEncryptedStage = existsSync(stagePath) && statSync(stagePath).size > 0;
    const key = options.resume && hasEncryptedStage
      ? (() => {
        try {
          return loadRunKey(options.keyPath);
        } catch (error) {
          const code = error && typeof error === "object" ? (error as { code?: unknown }).code : undefined;
          if (code === "ENOENT") throw new Error("customer match resume requires the existing run key");
          throw error;
        }
      })()
      : loadOrCreateRunKey(options.keyPath);
    const crypto = createRunCrypto(key);
    if (!existsSync(stagePath)) writeFileSync(stagePath, "", { flag: "wx", mode: 0o600 });
    chmodSync(stagePath, 0o600);
    const existing = stageRecords(stagePath, crypto);
    const stagedKeys = new Set(existing.flatMap((record) => {
      if (record.kind === "customer") {
        if (record.revision !== customerStageRevision(record)) return [];
        return [`customer:${record.customerId}:${record.revision}`];
      }
      if (record.kind === "ticket") return [`ticket:${record.ticketId}:${record.revision}`];
      return [`message:${record.messageId}:${record.revision}`];
    }));

    let lastRequestStart = Number.NEGATIVE_INFINITY;
    let retries = 0;
    const call = async <T>(operation: () => Promise<T>): Promise<T> => {
      for (let attempt = 0; ; attempt += 1) {
        const wait = Math.max(0, lastRequestStart + requestIntervalMs - now());
        if (wait > 0) await sleep(wait);
        lastRequestStart = now();
        try {
          return await operation();
        } catch (error) {
          const status = retryableStatus(error);
          const retryable = status === 429 || (status !== undefined && status >= 500) || status === undefined;
          if (!retryable || attempt >= maxRetries) throw error;
          retries += 1;
          const providerDelay = error && typeof error === "object"
            ? (error as { retryAfterMs?: unknown }).retryAfterMs
            : undefined;
          const delay = typeof providerDelay === "number"
            ? providerDelay
            : Math.min(30_000, 1_000 * (2 ** attempt));
          await sleep(delay + Math.floor(Math.random() * 100));
        }
      }
    };

    let previousDigests: string | undefined;
    let stabilizationPasses = 0;
    let stable = false;
    let finalCustomers!: Awaited<ReturnType<typeof enumerateCursorRecords<Customer>>>;
    let finalTickets!: Awaited<ReturnType<typeof enumerateCursorRecords<Ticket>>>;
    let finalMessages!: Awaited<ReturnType<typeof enumerateCursorRecords<Message>>>;

    for (let pass = 1; pass <= maxStabilizationPasses; pass += 1) {
      stabilizationPasses = pass;
      let customerDetailDrift = false;
      const customers = await enumerateCursorRecords<Customer>({
        endpoint: "customers",
        fetchPage: (cursor) => call(() => options.client.listCustomers({ limit: 100, cursor })),
      });
      const tickets = await enumerateCursorRecords<Ticket>({
        endpoint: "tickets",
        fetchPage: (cursor) => call(() => options.client.listTickets({
          limit: 100,
          cursor,
          orderBy: "created_datetime:asc",
          trashed: true,
        })),
      });
      const messages = await enumerateCursorRecords<Message>({
        endpoint: "messages",
        fetchPage: (cursor) => call(() => options.client.listMessages({
          limit: 100,
          cursor,
          orderBy: "created_datetime:asc",
        })),
      });
      finalCustomers = customers;
      finalTickets = tickets;
      finalMessages = messages;

      const ticketById = new Map(tickets.records.map((ticket) => [ticket.id, ticket]));
      for (const customer of customers.records) {
        const revision = revisionFor(customer);
        const keyName = `customer:${customer.id}:${revision}`;
        if (stagedKeys.has(keyName)) continue;
        const detail = await call(() => options.client.getCustomer(customer.id));
        if (detail.id !== customer.id) {
          throw new Error(`customer detail id mismatch for ${customer.id}`);
        }
        const detailRevision = revisionFor(detail);
        const detailKeyName = `customer:${customer.id}:${detailRevision}`;
        if (detailRevision !== revision) {
          customerDetailDrift = true;
          if (!stagedKeys.has(detailKeyName)) {
            appendStageRecord(stagePath, crypto, {
              ...extractCustomerMatchRecord(detail, { defaultCountry: options.defaultCountry }),
              revision: detailRevision,
            });
            stagedKeys.add(detailKeyName);
          }
          continue;
        }
        appendStageRecord(stagePath, crypto, {
          ...extractCustomerMatchRecord(detail, { defaultCountry: options.defaultCountry }),
          revision: detailRevision,
        });
        stagedKeys.add(detailKeyName);
      }

      for (const ticket of tickets.records) {
        const revision = revisionFor(ticket);
        const keyName = `ticket:${ticket.id}:${revision}`;
        if (stagedKeys.has(keyName)) continue;
        appendStageRecord(stagePath, crypto, buildTicketStageRecord(ticket));
        stagedKeys.add(keyName);
      }

      for (const message of messages.records) {
        const revision = revisionFor(message);
        const keyName = `message:${message.id}:${revision}`;
        if (stagedKeys.has(keyName)) continue;
        const ticket = ticketById.get(message.ticket_id);
        appendStageRecord(stagePath, crypto, {
          ...extractMessageMatchRecord(message, {
            customerId: ticket ? ticketCustomerId(ticket) : undefined,
            spam: ticket?.spam === true,
            trashed: Boolean(ticket?.trashed_datetime),
            defaultCountry: options.defaultCountry,
          }),
          revision,
        });
        stagedKeys.add(keyName);
      }

      const digests = [customers.ledger.digest, tickets.ledger.digest, messages.ledger.digest].join(":");
      if (digests === previousDigests && !customerDetailDrift) {
        stable = true;
        break;
      }
      previousDigests = digests;
    }

    let reconciledMessages: Message[] | undefined;
    const unavailableTicketIds = new Set<number>();
    if (finalMessages.ledger.totalCount === undefined) {
      reconciledMessages = [];
      for (const ticket of finalTickets.records) {
        const ticketMessages = await enumerateCursorRecords<Message>({
          endpoint: `messages:ticket:${ticket.id}`,
          fetchPage: (cursor) => call(() => options.client.listMessages({
            limit: 100,
            cursor,
            orderBy: "created_datetime:asc",
            ticketId: ticket.id,
          })),
        });
        const mismatchedTicketIds = ticketMessages.records
          .filter((message) => message.ticket_id !== ticket.id)
          .map((message) => message.id);
        if (mismatchedTicketIds.length > 0) {
          finalMessages.ledger.errors.push(`messages ticket filter returned rows for a different ticket (${ticket.id})`);
        }
        if (!ticketMessages.ledger.complete) finalMessages.ledger.errors.push(...ticketMessages.ledger.errors);
        reconciledMessages.push(...ticketMessages.records.filter((message) => message.ticket_id === ticket.id));
      }

      const reconciledIds = new Set(reconciledMessages.map((message) => message.id));
      const listedTicketIds = new Set(finalTickets.records.map((ticket) => ticket.id));
      const candidateUnavailableTicketIds = new Set(finalMessages.records
        .filter((message) => !reconciledIds.has(message.id))
        .map((message) => message.ticket_id)
        .filter((ticketId) => Number.isSafeInteger(ticketId) && ticketId > 0 && !listedTicketIds.has(ticketId)));
      if (candidateUnavailableTicketIds.size > 0 && !options.client.getTicket) {
        finalMessages.ledger.errors.push("unlisted ticket availability cannot be verified");
      } else {
        for (const ticketId of candidateUnavailableTicketIds) {
          try {
            await call(() => options.client.getTicket!(ticketId));
            finalMessages.ledger.errors.push(`unlisted ticket ${ticketId} remains retrievable`);
          } catch (error) {
            const status = retryableStatus(error);
            if (status === 404) unavailableTicketIds.add(ticketId);
            else finalMessages.ledger.errors.push(`unlisted ticket availability check failed (${status ?? "unknown"})`);
          }
        }
      }
    }
    const messageCoverage = proveMessageCoverage(
      finalMessages.records,
      finalMessages.ledger.totalCount,
      reconciledMessages,
      new Set(finalTickets.records.map((ticket) => ticket.id)),
      unavailableTicketIds,
    );
    if (!messageCoverage.complete) finalMessages.ledger.errors.push("global message coverage is unproven");
    finalMessages.ledger.complete = finalMessages.ledger.errors.length === 0;

    if (stable) {
      compactStableStage(
        stagePath,
        crypto,
        finalCustomers.records,
        finalTickets.records,
        finalMessages.records,
        options.defaultCountry,
      );
    }

    const records = stageRecords(stagePath, crypto);
    const latestByKind = {
      customers: new Set(records.filter((record) => record.kind === "customer").map((record) => record.customerId)).size,
      tickets: new Set(records.filter((record) => record.kind === "ticket").map((record) => record.ticketId)).size,
      messages: new Set(records.filter((record) => record.kind === "message").map((record) => record.messageId)).size,
      quarantinedMessages: records.filter((record) => record.kind === "message" && !record.positiveEligible).length,
    };
    const errors = [
      ...finalCustomers.ledger.errors,
      ...finalTickets.ledger.errors,
      ...finalMessages.ledger.errors,
      ...(!stable ? ["snapshot did not stabilize within the pass limit"] : []),
    ];
    const customerDrift = options.expectedCustomerCount === undefined
      ? 0
      : finalCustomers.records.length - options.expectedCustomerCount;
    if (options.expectedCustomerCount !== undefined && customerDrift !== 0) {
      errors.push(`expected customer count ${options.expectedCustomerCount} but observed ${finalCustomers.records.length}`);
    }
    const result: CustomerMatchScanResult = {
      schema: "gorgias-customer-match-scan.v2",
      scanComplete: stable
        && finalCustomers.ledger.complete
        && finalTickets.ledger.complete
        && finalMessages.ledger.complete
        && messageCoverage.complete
        && customerDrift === 0,
      runDir: options.runDir,
      stagePath,
      keyId: crypto.keyId,
      stabilizationPasses,
      customerDrift,
      retries,
      ledgers: {
        customers: finalCustomers.ledger,
        tickets: finalTickets.ledger,
        messages: finalMessages.ledger,
      },
      messageCoverage,
      recordCounts: latestByKind,
      errors,
    };
    atomicWriteJson(resultPath, result);
    return result;
  } finally {
    rmSync(lockDir, { recursive: true, force: true });
  }
}
