
import { loadServiceConfig, z } from "@local/cli-utils";
import { PluginCache, TTL, createCacheKey } from "@local/plugin-cache";

const REQUEST_TIMEOUT_MS = 30_000;

const GorgiasConfigSchema = z.object({
  gorgias: z.object({
    domain: z.string().min(1),
    email: z.string().min(1),
    apiKey: z.string().min(1),
  }),
});

interface GorgiasConfig {
  domain: string;
  email: string;
  apiKey: string;
}

export interface Ticket {
  id: number;
  subject: string;
  status: string;
  priority: string;
  channel: string;
  created_datetime: string;
  updated_datetime: string;
  spam?: boolean;
  trashed_datetime?: string | null;
  is_unread?: boolean;
  last_message_datetime?: string | null;
  assignee_user?: { id: number; email?: string; name?: string } | null;
  assignee_team?: { id: number; name?: string } | null;
  customer?: Customer;
  messages?: Message[];
  tags?: Tag[];
}

export interface Customer {
  id: number;
  email: string;
  name?: string;
  firstname?: string;
  lastname?: string;
  created_datetime: string;
  updated_datetime?: string;
  channels?: Array<Record<string, unknown>>;
  data?: unknown;
  integrations?: unknown;
}

export interface Message {
  id: number;
  ticket_id: number;
  body_text?: string;
  body_html?: string;
  sender?: {
    id: number;
    email?: string;
    name?: string;
  };
  receiver?: Record<string, unknown> | null;
  source?: Record<string, unknown> | null;
  auth_customer_identity?: Record<string, unknown> | null;
  channel?: string;
  integration_id?: number | null;
  public?: boolean;
  external_id?: string | null;
  message_id?: string | null;
  stripped_text?: string | null;
  created_datetime: string;
  from_agent: boolean;
}

export interface Tag {
  id: number;
  name: string;
}

export interface Event {
  id: number;
  type: string;
  created_datetime: string;
  object_id?: number;
  object_type?: string;
  user_id?: number | null;
  user?: { id: number; email?: string; name?: string } | null;
  data?: unknown;
}

export interface TicketUpdateResult {
  httpStatus: number;
  ticket?: Ticket;
}

export interface ListResponse<T> {
  data: T[];
  meta?: {
    total_count?: number;
    cursor?: string;
    next_cursor?: string;
    has_more?: boolean;
  };
}

interface CustomerInspection {
  customerId: number;
  httpStatus: number;
  status: "ok" | "merged_redirect" | "not_found";
  location?: string;
  customer?: Customer;
}

export class GorgiasApiError extends Error {
  readonly status: number;
  readonly requestId?: string;
  readonly retryAfterMs?: number;

  constructor(status: number, requestId?: string, retryAfterMs?: number) {
    super(`Gorgias API error (${status})`);
    this.name = "GorgiasApiError";
    this.status = status;
    this.requestId = requestId;
    this.retryAfterMs = retryAfterMs;
  }
}

let productionCache: PluginCache | null = null;

function getProductionCache(): PluginCache {
  productionCache ??= new PluginCache({
    namespace: "gorgias-support-manager",
    defaultTTL: TTL.FIVE_MINUTES,
  });
  return productionCache;
}

const DEFAULT_REQUEST_INTERVAL_MS = 334;

const DEFAULT_READ_MAX_RETRIES = 3;

const MAX_BACKOFF_MS = 30_000;

const BACKOFF_JITTER_RATIO = 0.25;

export class GorgiasClient {
  private config: GorgiasConfig;
  private baseUrl: string;
  private cacheDisabled: boolean = false;
  private fetchImpl: typeof fetch;
  private sleepImpl: (ms: number) => Promise<void>;
  private randomImpl: () => number;
  private requestIntervalMs: number;
  private readMaxRetries: number;
  private cache: PluginCache;
  private lastRequestStartedAt: number = 0;
  private requestStartQueue: Promise<void> = Promise.resolve();

  constructor(opts?: {
    fetchImpl?: typeof fetch;
    config?: GorgiasConfig;
    sleepImpl?: (ms: number) => Promise<void>;
    randomImpl?: () => number;
    requestIntervalMs?: number;
    readMaxRetries?: number;
    cacheDir?: string;
  }) {
    if (opts?.config && (!opts.config.domain || !opts.config.email || !opts.config.apiKey)) {
      throw new Error(
        "Missing required config: opts.config needs { domain, email, apiKey }"
      );
    }
    if ((opts?.fetchImpl || opts?.config) && !opts.cacheDir) {
      throw new Error("Injected Gorgias clients require cacheDir isolation");
    }
    this.cache = opts?.cacheDir
      ? new PluginCache({
          namespace: "gorgias-support-manager",
          defaultTTL: TTL.FIVE_MINUTES,
          cacheDir: opts.cacheDir,
        })
      : getProductionCache();
    this.fetchImpl = opts?.fetchImpl ?? fetch;
    this.sleepImpl = opts?.sleepImpl ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.randomImpl = opts?.randomImpl ?? Math.random;
    this.requestIntervalMs = Math.max(0, opts?.requestIntervalMs ?? DEFAULT_REQUEST_INTERVAL_MS);
    this.readMaxRetries = Math.max(0, opts?.readMaxRetries ?? DEFAULT_READ_MAX_RETRIES);

    if (opts?.config) {
      this.config = opts.config;
      this.baseUrl = `https://${this.config.domain}.gorgias.com/api`;
      return;
    }

    const configFile = loadServiceConfig("gorgias-support-manager", {
      schema: GorgiasConfigSchema,
    });
    this.config = configFile.gorgias;
    this.baseUrl = `https://${this.config.domain}.gorgias.com/api`;
  }

  getSubdomain(): string {
    return this.config.domain;
  }


  disableCache(): void {
    this.cacheDisabled = true;
    this.cache.disable();
  }

  enableCache(): void {
    this.cacheDisabled = false;
    this.cache.enable();
  }

  getCacheStats() {
    return this.cache.getStats();
  }

  clearCache(): number {
    return this.cache.clear();
  }

  invalidateCustomerCaches(): number {
    const wasDisabled = this.cacheDisabled;
    if (wasDisabled) this.cache.enable();
    try {
      return this.cache.invalidatePattern(/^customer/) + this.cache.invalidatePattern(/^customers(?:\?|$)/);
    } finally {
      if (wasDisabled) this.cache.disable();
    }
  }

  invalidateCacheKey(key: string): boolean {
    return this.cache.invalidate(key);
  }

  private getAuthHeader(): string {
    const credentials = Buffer.from(
      `${this.config.email}:${this.config.apiKey}`
    ).toString("base64");
    return `Basic ${credentials}`;
  }

  private async waitForRequestSlot(): Promise<void> {
    if (this.requestIntervalMs <= 0) return;
    let release!: () => void;
    const previous = this.requestStartQueue;
    this.requestStartQueue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      const remaining = this.requestIntervalMs - (Date.now() - this.lastRequestStartedAt);
      if (remaining > 0) await this.sleepImpl(remaining);
      this.lastRequestStartedAt = Date.now();
    } finally {
      release();
    }
  }

  private async requestResponse(
    method: string,
    endpoint: string,
    body?: Record<string, unknown>,
    requestOptions?: { redirect?: RequestRedirect },
  ): Promise<Response> {
    await this.waitForRequestSlot();
    const url = `${this.baseUrl}${endpoint}`;

    const headers: Record<string, string> = {
      Authorization: this.getAuthHeader(),
      "Content-Type": "application/json",
      Accept: "application/json",
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    const fetchOptions: RequestInit = {
      method,
      headers,
      signal: controller.signal,
      redirect: requestOptions?.redirect,
    };

    if (body) {
      fetchOptions.body = JSON.stringify(body);
    }

    try {
      return await this.fetchImpl(url, fetchOptions);
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Gorgias API request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async request<T>(
    method: string,
    endpoint: string,
    body?: Record<string, unknown>,
  ): Promise<T> {
    let attempt = 0;
    let response = await this.requestResponse(method, endpoint, body);

    while (method === "GET" && response.status === 429 && attempt < this.readMaxRetries) {
      const delayMs = this.retryAfterMs(response, 1_000 * 2 ** attempt);
      await response.text().catch(() => "");
      attempt += 1;
      await this.sleepImpl(delayMs);
      response = await this.requestResponse(method, endpoint, body);
    }

    if (!response.ok) {
      await response.text().catch(() => "");
      const retryAfterMs = response.status === 429
        ? this.retryAfterMs(response, 1_000)
        : undefined;
      throw new GorgiasApiError(
        response.status,
        response.headers.get("x-request-id") ?? response.headers.get("x-gorgias-request-id") ?? undefined,
        retryAfterMs,
      );
    }

    return response.json() as Promise<T>;
  }


  async listTickets(options?: {
    limit?: number;
    status?: string;
    orderBy?: string;
    cursor?: string;
    customerId?: number;
    trashed?: boolean;
    fresh?: boolean;
  }): Promise<ListResponse<Ticket>> {
    const cacheKey = createCacheKey("tickets", {
      limit: options?.limit,
      status: options?.status,
      orderBy: options?.orderBy,
      cursor: options?.cursor,
      customerId: options?.customerId,
      trashed: options?.trashed,
    });

    return this.cache.getOrFetch(
      cacheKey,
      async () => {
        const params = new URLSearchParams();

        if (options?.limit) params.set("limit", options.limit.toString());
        if (options?.orderBy) params.set("order_by", options.orderBy);
        if (options?.cursor) params.set("cursor", options.cursor);
        if (options?.customerId) params.set("customer_id", options.customerId.toString());
        if (options?.trashed !== undefined) params.set("trashed", String(options.trashed));
        const queryString = params.toString();
        const endpoint = `/tickets${queryString ? `?${queryString}` : ""}`;

        const result = await this.request<ListResponse<Ticket>>("GET", endpoint);
        if (options?.status) {
          result.data = result.data.filter(t => t.status === options.status);
        }
        return result;
      },
      { ttl: TTL.FIVE_MINUTES, bypassCache: this.cacheDisabled || options?.fresh === true }
    );
  }

  async getTicket(ticketId: number, options?: { fresh?: boolean }): Promise<Ticket> {
    const cacheKey = createCacheKey("ticket", { id: ticketId });

    return this.cache.getOrFetch(
      cacheKey,
      () => this.request<Ticket>("GET", `/tickets/${ticketId}`),
      { ttl: TTL.MINUTE, bypassCache: this.cacheDisabled || options?.fresh === true }
    );
  }

  async listEvents(options: {
    objectId: number;
    objectType?: "Ticket";
    limit?: number;
    cursor?: string;
    orderBy?: "created_datetime:asc" | "created_datetime:desc";
  }): Promise<ListResponse<Event>> {
    const params = new URLSearchParams();
    params.set("object_id", String(options.objectId));
    params.set("object_type", options.objectType ?? "Ticket");
    if (options.limit) params.set("limit", String(options.limit));
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.orderBy) params.set("order_by", options.orderBy);
    return this.request<ListResponse<Event>>("GET", `/events?${params.toString()}`);
  }

  private invalidateTicketCaches(ticketId: number): void {
    const wasDisabled = this.cacheDisabled;
    if (wasDisabled) this.cache.enable();
    try {
      this.cache.invalidate(createCacheKey("ticket", { id: ticketId }));
      this.cache.invalidatePattern(/^tickets(?:\?|$)/);
    } finally {
      if (wasDisabled) this.cache.disable();
    }
  }

  async updateTicketSpamState(
    ticketId: number,
    update: { spam: boolean; trashedDatetime?: string | null },
  ): Promise<TicketUpdateResult> {
    const body: Record<string, unknown> = { spam: update.spam };
    if (Object.prototype.hasOwnProperty.call(update, "trashedDatetime")) {
      body.trashed_datetime = update.trashedDatetime;
    }

    const response = await this.requestResponse("PUT", `/tickets/${ticketId}`, body);
    if (!response.ok) {
      await response.text().catch(() => "");
      const retryAfterMs = response.status === 429
        ? this.retryAfterMs(response, 1_000)
        : undefined;
      throw new GorgiasApiError(
        response.status,
        response.headers.get("x-request-id") ?? response.headers.get("x-gorgias-request-id") ?? undefined,
        retryAfterMs,
      );
    }

    this.invalidateTicketCaches(ticketId);
    const text = await response.text();
    if (!text.trim()) return { httpStatus: response.status };
    try {
      return { httpStatus: response.status, ticket: JSON.parse(text) as Ticket };
    } catch {
      return { httpStatus: response.status };
    }
  }

  async listMessages(options?: {
    limit?: number;
    cursor?: string;
    orderBy?: "created_datetime:asc" | "created_datetime:desc";
    ticketId?: number;
  }): Promise<ListResponse<Message>> {
    const params = new URLSearchParams();
    if (options?.limit) params.set("limit", options.limit.toString());
    if (options?.cursor) params.set("cursor", options.cursor);
    if (options?.orderBy) params.set("order_by", options.orderBy);
    if (options?.ticketId) params.set("ticket_id", options.ticketId.toString());
    const queryString = params.toString();
    return this.request<ListResponse<Message>>("GET", `/messages${queryString ? `?${queryString}` : ""}`);
  }

  async createTicket(data: {
    customerEmail: string;
    subject: string;
    message: string;
  }): Promise<Ticket> {
    const body = {
      channel: "api",
      customer: { email: data.customerEmail },
      messages: [
        {
          channel: "api",
          body_text: data.message,
          from_agent: false,
          via: "api",
        },
      ],
      subject: data.subject,
    };

    const result = await this.request<Ticket>("POST", "/tickets", body);
    this.cache.invalidatePattern(/^ticket/);
    return result;
  }

  async addMessage(
    ticketId: number,
    message: string,
    fromAgent: boolean
  ): Promise<Message> {
    const body = {
      channel: "api",
      body_text: message,
      from_agent: fromAgent,
      via: "api",
      sender: fromAgent
        ? { email: this.config.email }
        : undefined,
    };

    if (!body.sender) delete body.sender;

    const result = await this.request<Message>(
      "POST",
      `/tickets/${ticketId}/messages`,
      body
    );
    this.cache.invalidate(createCacheKey("ticket", { id: ticketId }));
    this.cache.invalidatePattern(/^tickets(?:\?|$)/);
    return result;
  }


  async listCustomers(options?: {
    limit?: number;
    email?: string;
    cursor?: string;
  }): Promise<ListResponse<Customer>> {
    const cacheKey = createCacheKey("customers", {
      limit: options?.limit,
      email: options?.email,
      cursor: options?.cursor,
    });

    return this.cache.getOrFetch(
      cacheKey,
      async () => {
        const params = new URLSearchParams();

        if (options?.limit) params.set("limit", options.limit.toString());
        if (options?.email) params.set("email", options.email);
        if (options?.cursor) params.set("cursor", options.cursor);

        const queryString = params.toString();
        const endpoint = `/customers${queryString ? `?${queryString}` : ""}`;

        return this.request<ListResponse<Customer>>("GET", endpoint);
      },
      { ttl: TTL.FIFTEEN_MINUTES, bypassCache: this.cacheDisabled }
    );
  }

  async getCustomer(customerId: number): Promise<Customer> {
    const cacheKey = createCacheKey("customer", { id: customerId });

    return this.cache.getOrFetch(
      cacheKey,
      () => this.request<Customer>("GET", `/customers/${customerId}`),
      { ttl: TTL.FIFTEEN_MINUTES, bypassCache: this.cacheDisabled }
    );
  }

  private retryAfterMs(response: Response, fallbackMs: number): number {
    const retryAfter = response.headers.get("retry-after");
    if (!retryAfter) return this.boundBackoff(fallbackMs);
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return this.boundBackoff(Math.ceil(seconds * 1000));
    const retryDate = Date.parse(retryAfter);
    if (!Number.isNaN(retryDate)) return this.boundBackoff(Math.max(0, retryDate - Date.now()));
    return this.boundBackoff(fallbackMs);
  }

  private boundBackoff(delayMs: number): number {
    const capped = Math.min(Math.max(0, delayMs), MAX_BACKOFF_MS);
    const jitter = capped * BACKOFF_JITTER_RATIO * this.randomImpl();
    return Math.ceil(capped + jitter);
  }

  async mergeCustomers(options: {
    sourceId: number;
    targetId: number;
    maxRetries?: number;
    retryDelayMs?: number;
    updateData?: Record<string, unknown>;
  }): Promise<unknown> {
    const maxRetries = options.maxRetries ?? 3;
    const retryDelayMs = options.retryDelayMs ?? 500;
    const params = new URLSearchParams({
      source_id: String(options.sourceId),
      target_id: String(options.targetId),
    });
    let attempt = 0;

    while (true) {
      const response = await this.requestResponse(
        "PUT",
        `/customers/merge?${params.toString()}`,
        options.updateData ?? {},
      );

      if (response.status === 429 && attempt < maxRetries) {
        const delayMs = this.retryAfterMs(response, retryDelayMs * 2 ** attempt);
        attempt += 1;
        await this.sleepImpl(delayMs);
        continue;
      }

      if (!response.ok) {
        await response.text().catch(() => "");
        throw new GorgiasApiError(response.status, response.headers.get("x-request-id") ?? response.headers.get("x-gorgias-request-id") ?? undefined);
      }

      this.invalidateCustomerCaches();
      const text = await response.text();
      return text ? JSON.parse(text) : {};
    }
  }

  async inspectCustomer(customerId: number): Promise<CustomerInspection> {
    const response = await this.requestResponse(
      "GET",
      `/customers/${customerId}`,
      undefined,
      { redirect: "manual" },
    );

    if (response.status === 301) {
      return {
        customerId,
        httpStatus: response.status,
        status: "merged_redirect",
        location: response.headers.get("location") ?? undefined,
      };
    }

    if (response.status === 404) {
      return {
        customerId,
        httpStatus: response.status,
        status: "not_found",
      };
    }

    if (!response.ok) {
      await response.text().catch(() => "");
      throw new GorgiasApiError(response.status, response.headers.get("x-request-id") ?? response.headers.get("x-gorgias-request-id") ?? undefined);
    }

    return {
      customerId,
      httpStatus: response.status,
      status: "ok",
      customer: await response.json() as Customer,
    };
  }


  getTools(): Array<{ name: string; description: string }> {
    return [
      { name: "list-tickets", description: "List tickets with optional filters" },
      { name: "get-ticket", description: "Get a specific ticket by ID" },
      { name: "create-ticket", description: "Create a new ticket" },
      { name: "add-message", description: "Add a message to an existing ticket" },
      { name: "list-customers", description: "List customers with optional filters" },
      { name: "get-customer", description: "Get a specific customer by ID" },
      { name: "export-customers", description: "Export PII-minimized customer dedupe evidence" },
      { name: "generate-merge-manifest", description: "Generate a customer merge approval manifest" },
      { name: "discover-customer-matches", description: "Build a non-executable customer match review proposal" },
      { name: "merge-customers", description: "Merge approved Gorgias customer pairs from a manifest" },
      { name: "verify-merge-batch", description: "Verify post-merge customer outcomes from a manifest batch" },
      { name: "cache-stats", description: "Show cache statistics" },
      { name: "cache-clear", description: "Clear all cached data" },
    ];
  }
}

export default GorgiasClient;
