#!/usr/bin/env npx tsx
/**
 * Gorgias Support CLI
 *
 * Zod-validated CLI for Gorgias support ticket management.
 */

import { z, createCommand, runCli, cacheCommands, cliTypes } from "@local/cli-utils";
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

      let result = await client.listTickets({
        limit: fetchLimit,
        orderBy,
      });

      // Client-side filtering for status (API doesn't support this)
      if (status && result.data) {
        result.data = result.data.filter(
          (ticket: { status?: string }) =>
            ticket.status?.toLowerCase() === status.toLowerCase()
        );
      }

      // Client-side filtering for search (matches subject or excerpt)
      if (search && result.data) {
        const searchTerm = search.toLowerCase();
        result.data = result.data.filter((ticket: { subject?: string; excerpt?: string }) => {
          const subject = (ticket.subject || "").toLowerCase();
          const excerpt = (ticket.excerpt || "").toLowerCase();
          return subject.includes(searchTerm) || excerpt.includes(searchTerm);
        });
      }

      // Apply limit after filtering
      if (result.data) {
        result.data = result.data.slice(0, limit);
      }

      return result;
    },
    "List tickets with optional filtering"
  ),

  "get-ticket": createCommand(
    z.object({
      id: cliTypes.int(1).describe("Ticket ID"),
    }),
    async (args, client: GorgiasClient) => {
      const { id } = args as { id: number };
      return client.getTicket(id);
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
      return client.listCustomers({ limit, email });
    },
    "List customers with optional email filter"
  ),

  "get-customer": createCommand(
    z.object({
      id: cliTypes.int(1).describe("Customer ID"),
    }),
    async (args, client: GorgiasClient) => {
      const { id } = args as { id: number };
      return client.getCustomer(id);
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
