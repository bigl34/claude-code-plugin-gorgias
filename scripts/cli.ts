#!/usr/bin/env npx tsx
/**
 * Gorgias Support CLI
 *
 * Zod-validated CLI for Gorgias support ticket management.
 */

import { z, createCommand, runCli, cacheCommands, cliTypes, wrapUntrustedField, buildSafeOutput } from "@local/cli-utils";
import { GorgiasClient } from "./gorgias-client.js";

// Define commands with Zod schemas
const commands = {
  "list-tools": createCommand(
    z.object({}),
    async (_args, client: GorgiasClient) => client.getTools(),
    "List all available CLI commands"
  ),

  // Ticket commands
  "list-tickets": createCommand(
    z.object({
      limit: cliTypes.limit(50, 250),
      status: z.enum(["open", "closed"]).optional().describe("Filter by status (client-side)"),
      search: z.string().optional().describe("Search tickets by keyword (client-side)"),
      orderBy: z.string().optional().describe("Order by field (e.g., created_datetime:desc)"),
    }),
    async (args, client: GorgiasClient) => {
      const { limit, status, search, orderBy } = args as {
        limit: number;
        status?: "open" | "closed";
        search?: string;
        orderBy?: string;
      };

      // Fetch more tickets if filtering client-side (API doesn't support status/search)
      const needsClientFilter = status || search;
      const fetchLimit = needsClientFilter ? 100 : limit;

      const result = await client.listTickets({
        limit: fetchLimit,
        orderBy,
      });

      let tickets = result.data || [];

      // Client-side filtering for status (API doesn't support this)
      if (status) {
        tickets = tickets.filter(
          (ticket: any) =>
            ticket.status?.toLowerCase() === status.toLowerCase()
        );
      }

      // Client-side filtering for search (matches subject or excerpt)
      if (search) {
        const searchTerm = search.toLowerCase();
        tickets = tickets.filter((ticket: any) => {
          const subject = (ticket.subject || "").toLowerCase();
          const excerpt = (ticket.excerpt || "").toLowerCase();
          return subject.includes(searchTerm) || excerpt.includes(searchTerm);
        });
      }

      // Apply limit after filtering
      tickets = tickets.slice(0, limit);

      // Wrap each ticket with content safety
      const wrappedTickets = tickets.map((ticket: any) => ({
        metadata: {
          id: ticket.id,
          status: ticket.status,
          priority: ticket.priority,
          channel: ticket.channel,
          created_datetime: ticket.created_datetime,
          updated_datetime: ticket.updated_datetime,
          tags: (ticket.tags || []).map((t: any) => t?.name),
          messages_count: ticket.messages_count,
        },
        content: {
          subject: wrapUntrustedField("subject", ticket.subject, { maxChars: 500 }),
          excerpt: wrapUntrustedField("excerpt", ticket.excerpt, { maxChars: 500 }),
          customerName: wrapUntrustedField("customer.name", ticket.customer?.name, { maxChars: 200 }),
          customerEmail: wrapUntrustedField("customer.email", ticket.customer?.email, { maxChars: 200 }),
        },
      }));

      return buildSafeOutput(
        { command: "list-tickets", count: wrappedTickets.length },
        { tickets: wrappedTickets }
      );
    },
    "List tickets with optional filtering"
  ),

  "get-ticket": createCommand(
    z.object({
      id: cliTypes.int(1).describe("Ticket ID"),
    }),
    async (args, client: GorgiasClient) => {
      const { id } = args as { id: number };
      const ticket: any = await client.getTicket(id);

      const metadata = {
        id: ticket.id,
        status: ticket.status,
        priority: ticket.priority,
        channel: ticket.channel,
        created_datetime: ticket.created_datetime,
        updated_datetime: ticket.updated_datetime,
        opened_datetime: ticket.opened_datetime,
        closed_datetime: ticket.closed_datetime,
        tags: (ticket.tags || []).map((t: any) => t?.name),
        messages_count: ticket.messages_count,
        is_unread: ticket.is_unread,
      };

      const messages = (ticket.messages || []).map((msg: any) => ({
        metadata: {
          id: msg.id,
          from_agent: msg.from_agent,
          created_datetime: msg.created_datetime,
        },
        content: {
          body: wrapUntrustedField(
            "message.body",
            msg.body_text || msg.body_html || "",
            {
              maxChars: 8000,
              convertHtml: !msg.body_text && !!msg.body_html,
            }
          ),
          senderName: wrapUntrustedField("message.sender.name", msg.sender?.name, { maxChars: 200 }),
          senderEmail: wrapUntrustedField("message.sender.email", msg.sender?.email, { maxChars: 200 }),
        },
      }));

      const content = {
        subject: wrapUntrustedField("subject", ticket.subject, { maxChars: 500 }),
        customerName: wrapUntrustedField("customer.name", ticket.customer?.name, { maxChars: 200 }),
        customerEmail: wrapUntrustedField("customer.email", ticket.customer?.email, { maxChars: 200 }),
        messages,
      };

      return buildSafeOutput(metadata, content);
    },
    "Get ticket details by ID"
  ),

  "create-ticket": createCommand(
    z.object({
      customerEmail: z.string().email().describe("Customer email address"),
      subject: z.string().min(1).describe("Ticket subject"),
      message: z.string().min(1).describe("Initial message content"),
    }),
    async (args, client: GorgiasClient) => {
      const { customerEmail, subject, message } = args as {
        customerEmail: string;
        subject: string;
        message: string;
      };
      return client.createTicket({ customerEmail, subject, message });
    },
    "Create a new support ticket"
  ),

  "add-message": createCommand(
    z.object({
      ticketId: cliTypes.int(1).describe("Ticket ID"),
      message: z.string().min(1).describe("Message text"),
      fromAgent: cliTypes.bool().default(false).describe("Whether message is from agent"),
    }),
    async (args, client: GorgiasClient) => {
      const { ticketId, message, fromAgent } = args as {
        ticketId: number;
        message: string;
        fromAgent: boolean;
      };
      return client.addMessage(ticketId, message, fromAgent);
    },
    "Add a message to an existing ticket"
  ),

  // Customer commands
  "list-customers": createCommand(
    z.object({
      limit: cliTypes.limit(50, 250),
      email: z.string().optional().describe("Filter by email address"),
    }),
    async (args, client: GorgiasClient) => {
      const { limit, email } = args as { limit: number; email?: string };
      const result = await client.listCustomers({ limit, email });

      const customers = (result.data || []).map((customer: any) => ({
        metadata: {
          id: customer.id,
          created_datetime: customer.created_datetime,
        },
        content: {
          name: wrapUntrustedField("name", customer.name, { maxChars: 200 }),
          firstname: wrapUntrustedField("firstname", customer.firstname, { maxChars: 200 }),
          lastname: wrapUntrustedField("lastname", customer.lastname, { maxChars: 200 }),
          email: wrapUntrustedField("email", customer.email, { maxChars: 200 }),
        },
      }));

      return buildSafeOutput(
        { command: "list-customers", count: customers.length },
        { customers }
      );
    },
    "List customers with optional email filter"
  ),

  "get-customer": createCommand(
    z.object({
      id: cliTypes.int(1).describe("Customer ID"),
    }),
    async (args, client: GorgiasClient) => {
      const { id } = args as { id: number };
      const customer: any = await client.getCustomer(id);

      return buildSafeOutput(
        {
          command: "get-customer",
          id: customer.id,
          created_datetime: customer.created_datetime,
        },
        {
          name: wrapUntrustedField("name", customer.name, { maxChars: 200 }),
          firstname: wrapUntrustedField("firstname", customer.firstname, { maxChars: 200 }),
          lastname: wrapUntrustedField("lastname", customer.lastname, { maxChars: 200 }),
          email: wrapUntrustedField("email", customer.email, { maxChars: 200 }),
        }
      );
    },
    "Get customer details by ID"
  ),

  // Pre-built cache commands
  ...cacheCommands<GorgiasClient>(),
};

// Run CLI
runCli(commands, GorgiasClient, {
  programName: "gorgias-cli",
  description: "Gorgias support ticket management",
});
