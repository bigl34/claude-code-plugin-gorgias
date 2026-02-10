/**
 * Gorgias API Client
 *
 * Direct client for the Gorgias REST API using HTTP Basic Auth.
 * Reads configuration from config.json file.
 */

import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { PluginCache, TTL, createCacheKey } from "@local/plugin-cache";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Request timeout for API calls (30 seconds)
const REQUEST_TIMEOUT_MS = 30_000;

interface GorgiasConfig {
  domain: string;
  email: string;
  apiKey: string;
}

interface ConfigFile {
  gorgias: {
    domain: string;
    email: string;
    apiKey: string;
  };
}

interface Ticket {
  id: number;
  subject: string;
  status: string;
  priority: string;
  channel: string;
  created_datetime: string;
  updated_datetime: string;
  customer?: Customer;
  messages?: Message[];
  tags?: Tag[];
}

interface Customer {
  id: number;
  email: string;
  name?: string;
  firstname?: string;
  lastname?: string;
  created_datetime: string;
}

interface Message {
  id: number;
  ticket_id: number;
  body_text?: string;
  body_html?: string;
  sender?: {
    id: number;
    email: string;
    name?: string;
  };
  created_datetime: string;
  from_agent: boolean;
}

interface Tag {
  id: number;
  name: string;
}

interface ListResponse<T> {
  data: T[];
  meta?: {
    total_count?: number;
    cursor?: string;
  };
}

// Initialize cache with namespace
const cache = new PluginCache({
  namespace: "gorgias-support-manager",
  defaultTTL: TTL.FIVE_MINUTES,
});

export class GorgiasClient {
  private config: GorgiasConfig;
  private baseUrl: string;
  private cacheDisabled: boolean = false;

  constructor() {
    // When compiled, __dirname is dist/, so look in parent for config.json
    const configPath = join(__dirname, "..", "config.json");
    const configFile: ConfigFile = JSON.parse(readFileSync(configPath, "utf-8"));

    if (!configFile.gorgias?.domain || !configFile.gorgias?.email || !configFile.gorgias?.apiKey) {
      throw new Error(
        "Missing required config in config.json: gorgias.domain, gorgias.email, gorgias.apiKey"
      );
    }

    this.config = configFile.gorgias;
    this.baseUrl = `https://${this.config.domain}.gorgias.com/api`;
  }

  // ============================================
  // CACHE CONTROL
  // ============================================

  /**
   * Disables caching for all subsequent requests.
   * Useful for debugging or when fresh data is required.
   */
  disableCache(): void {
    this.cacheDisabled = true;
    cache.disable();
  }

  /**
   * Re-enables caching after it was disabled.
   */
  enableCache(): void {
    this.cacheDisabled = false;
    cache.enable();
  }

  /**
   * Returns cache statistics including hit/miss counts.
   * @returns Cache stats object with hits, misses, and entry count
   */
  getCacheStats() {
    return cache.getStats();
  }

  /**
   * Clears all cached data.
   * @returns Number of cache entries cleared
   */
  clearCache(): number {
    return cache.clear();
  }

  /**
   * Invalidates a specific cache entry by key.
   * @param key - The cache key to invalidate
   * @returns true if entry was found and removed, false otherwise
   */
  invalidateCacheKey(key: string): boolean {
    return cache.invalidate(key);
  }

  private getAuthHeader(): string {
    const credentials = Buffer.from(
      `${this.config.email}:${this.config.apiKey}`
    ).toString("base64");
    return `Basic ${credentials}`;
  }

  private async request<T>(
    method: string,
    endpoint: string,
    body?: Record<string, any>
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;

    const headers: Record<string, string> = {
      Authorization: this.getAuthHeader(),
      "Content-Type": "application/json",
      Accept: "application/json",
    };

    // Set up timeout with AbortController
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    const options: RequestInit = {
      method,
      headers,
      signal: controller.signal,
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    try {
      const response = await fetch(url, options);

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Gorgias API error (${response.status}): ${errorText}`);
      }

      return response.json() as Promise<T>;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Gorgias API request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ============================================
  // TICKET OPERATIONS
  // ============================================

  /**
   * Lists support tickets with optional filtering and pagination.
   *
   * @param options - Filter and pagination options
   * @param options.limit - Maximum tickets to return (default: 30)
   * @param options.status - Filter by status: "open", "closed", "snoozed", etc.
   * @param options.orderBy - Sort field (e.g., "created_datetime", "-updated_datetime")
   * @param options.cursor - Pagination cursor from previous response
   * @returns Paginated response with tickets array and meta cursor
   *
   * @cached TTL: 5 minutes
   *
   * @example
   * // Get open tickets
   * const { data: tickets } = await client.listTickets({ status: "open", limit: 50 });
   */
  async listTickets(options?: {
    limit?: number;
    status?: string;
    orderBy?: string;
    cursor?: string;
  }): Promise<ListResponse<Ticket>> {
    const cacheKey = createCacheKey("tickets", {
      limit: options?.limit,
      status: options?.status,
      orderBy: options?.orderBy,
      cursor: options?.cursor,
    });

    return cache.getOrFetch(
      cacheKey,
      async () => {
        const params = new URLSearchParams();

        if (options?.limit) params.set("limit", options.limit.toString());
        // Note: Gorgias API does NOT support `status` as a query param (returns 400).
        // Client-side filtering is applied below instead.
        if (options?.orderBy) params.set("order_by", options.orderBy);
        if (options?.cursor) params.set("cursor", options.cursor);

        const queryString = params.toString();
        const endpoint = `/tickets${queryString ? `?${queryString}` : ""}`;

        const result = await this.request<ListResponse<Ticket>>("GET", endpoint);
        if (options?.status) {
          result.data = result.data.filter(t => t.status === options.status);
        }
        return result;
      },
      { ttl: TTL.FIVE_MINUTES, bypassCache: this.cacheDisabled }
    );
  }

  /**
   * Retrieves a single ticket by ID with full details including messages.
   *
   * @param ticketId - The Gorgias ticket ID
   * @returns The ticket object with messages and customer data
   *
   * @cached TTL: 1 minute
   *
   * @example
   * const ticket = await client.getTicket(12345);
   * console.log(ticket.subject, ticket.messages?.length);
   */
  async getTicket(ticketId: number): Promise<Ticket> {
    const cacheKey = createCacheKey("ticket", { id: ticketId });

    return cache.getOrFetch(
      cacheKey,
      () => this.request<Ticket>("GET", `/tickets/${ticketId}`),
      { ttl: TTL.MINUTE, bypassCache: this.cacheDisabled }
    );
  }

  /**
   * Creates a new support ticket.
   *
   * @param data - Ticket creation data
   * @param data.customerEmail - Customer's email address (required)
   * @param data.subject - Ticket subject line
   * @param data.message - Initial message body text
   * @returns The created ticket object
   *
   * @invalidates ticket/*
   *
   * @example
   * const ticket = await client.createTicket({
   *   customerEmail: "customer@example.com",
   *   subject: "Order inquiry",
   *   message: "I have a question about my order #1234"
   * });
   */
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
    // Invalidate ticket caches after mutation
    cache.invalidatePattern(/^ticket/);
    return result;
  }

  /**
   * Adds a message to an existing ticket.
   *
   * @param ticketId - The ticket ID to add the message to
   * @param message - Message body text
   * @param fromAgent - true if message is from agent, false if from customer
   * @returns The created message object
   *
   * @invalidates ticket/{ticketId}
   *
   * @example
   * // Add agent reply
   * await client.addMessage(12345, "Thank you for contacting us!", true);
   *
   * // Add customer message
   * await client.addMessage(12345, "Any update on this?", false);
   */
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
    };

    const result = await this.request<Message>(
      "POST",
      `/tickets/${ticketId}/messages`,
      body
    );
    // Invalidate specific ticket cache
    cache.invalidate(createCacheKey("ticket", { id: ticketId }));
    return result;
  }

  // ============================================
  // CUSTOMER OPERATIONS
  // ============================================

  /**
   * Lists customers with optional filtering and pagination.
   *
   * @param options - Filter and pagination options
   * @param options.limit - Maximum customers to return (default: 30)
   * @param options.email - Filter by exact email address
   * @param options.cursor - Pagination cursor from previous response
   * @returns Paginated response with customers array and meta cursor
   *
   * @cached TTL: 15 minutes
   *
   * @example
   * // Search by email
   * const { data: customers } = await client.listCustomers({ email: "john@example.com" });
   */
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

    return cache.getOrFetch(
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

  /**
   * Retrieves a single customer by ID.
   *
   * @param customerId - The Gorgias customer ID
   * @returns The customer object with contact details
   *
   * @cached TTL: 15 minutes
   *
   * @example
   * const customer = await client.getCustomer(67890);
   * console.log(customer.email, customer.name);
   */
  async getCustomer(customerId: number): Promise<Customer> {
    const cacheKey = createCacheKey("customer", { id: customerId });

    return cache.getOrFetch(
      cacheKey,
      () => this.request<Customer>("GET", `/customers/${customerId}`),
      { ttl: TTL.FIFTEEN_MINUTES, bypassCache: this.cacheDisabled }
    );
  }

  // ============================================
  // UTILITIES
  // ============================================

  /**
   * Returns list of available CLI commands for this client.
   * Used for CLI help text generation.
   *
   * @returns Array of tool definitions with name and description
   */
  getTools(): Array<{ name: string; description: string }> {
    return [
      { name: "list-tickets", description: "List tickets with optional filters" },
      { name: "get-ticket", description: "Get a specific ticket by ID" },
      { name: "create-ticket", description: "Create a new ticket" },
      { name: "add-message", description: "Add a message to an existing ticket" },
      { name: "list-customers", description: "List customers with optional filters" },
      { name: "get-customer", description: "Get a specific customer by ID" },
      { name: "cache-stats", description: "Show cache statistics" },
      { name: "cache-clear", description: "Clear all cached data" },
    ];
  }
}

export default GorgiasClient;
