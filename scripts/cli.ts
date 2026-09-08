#!/usr/bin/env npx tsx

import { z, createCommand, runCli, cacheCommands, cliTypes, wrapUntrustedField, buildSafeOutput } from "@local/cli-utils";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { GorgiasClient } from "./gorgias-client.js";
import {
  buildMergeManifestFromSummaries,
  summarizeCustomerForDedupe,
  validateApprovedMergeBatch,
  type CustomerSummary,
  type MergeManifest,
} from "./customer-dedupe.js";
import {
  buildCustomerMatchReview,
  type CustomerMatchReviewProposal,
  type MatchConfidence,
} from "./customer-match-engine.js";
import {
  createCustomerMatchReadClient,
  loadCustomerMatchStage,
  runCustomerMatchScan,
  type CustomerMatchScanResult,
} from "./customer-match-scan.js";
import {
  assessMergeIntegrationSafety,
  verifyMergeIntegrationReadback,
} from "./customer-merge-safety.js";
import {
  paginateFilteredTickets,
  TicketPaginationFailure,
  type FilteredTicketPaginationResult,
} from "./ticket-pagination.js";

type Ticket = Awaited<ReturnType<GorgiasClient["getTicket"]>>;
type TicketDetails = Ticket & {
  opened_datetime?: string;
  closed_datetime?: string;
  messages_count?: number;
  is_unread?: boolean;
};
type Customer = Awaited<ReturnType<GorgiasClient["getCustomer"]>>;
type CustomerInspection = Awaited<ReturnType<GorgiasClient["inspectCustomer"]>>;
type CustomerListItem = Awaited<ReturnType<GorgiasClient["listCustomers"]>>["data"][number];
type TicketTag = NonNullable<Ticket["tags"]>[number];
type TicketMessage = NonNullable<Ticket["messages"]>[number];

function renderTicketPaginationOutput(
  client: Pick<GorgiasClient, "getSubdomain">,
  pagination: FilteredTicketPaginationResult,
  checkpointPath?: string,
  failure?: Record<string, unknown>,
) {
  const wrappedTickets = pagination.tickets.map((ticket) => ({
    metadata: {
      id: ticket.id,
      status: ticket.status,
      priority: ticket.priority,
      channel: ticket.channel,
      created_datetime: ticket.created_datetime,
      updated_datetime: ticket.updated_datetime,
      tags: (ticket.tags || []).map((tag: TicketTag) => tag?.name),
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
    {
      command: "list-tickets",
      count: wrappedTickets.length,
      customer_subdomain: client.getSubdomain(),
      next_cursor: pagination.nextCursor,
      resume_token: pagination.resumeToken,
      has_more: pagination.hasMore,
      coverage_complete: pagination.coverageComplete,
      fetched_pages: pagination.fetchedPages,
      page_limit: pagination.pageLimit,
      pagination_truncated: pagination.paginationTruncated,
      checkpoint_path: checkpointPath ?? null,
      partial_failure: Boolean(failure),
    },
    {
      tickets: wrappedTickets,
      ...(failure ? { failure } : {}),
    },
  );
}

function wrapProviderResponse(command: string, result: unknown) {
  return buildSafeOutput(
    { command },
    {
      result: wrapUntrustedField("result", JSON.stringify(result), { maxChars: 12000 }),
    },
  );
}

const boolDefaultFalse = () =>
  z.preprocess(
    (val) => {
      if (val === undefined || val === null || val === "") return false;
      if (val === true || val === "true") return true;
      if (val === false || val === "false") return false;
      return undefined;
    },
    z.boolean().default(false),
  );

const intDefault = (defaultVal: number, min: number, max: number) =>
  z.preprocess(
    (val) => {
      if (val === undefined || val === null || val === "") return defaultVal;
      if (typeof val === "boolean") return NaN;
      return Number(val);
    },
    z.number().int().min(min).max(max).default(defaultVal),
  );

const optionalInt = (min: number, max: number) =>
  z.preprocess(
    (val) => {
      if (val === undefined || val === null || val === "") return undefined;
      if (typeof val === "boolean") return NaN;
      return Number(val);
    },
    z.number().int().min(min).max(max).optional(),
  );

const mergeManifestPairSchema = z.object({
  id: z.string().min(1),
  source_id: z.number().int().positive(),
  target_id: z.number().int().positive(),
  status: z.enum(["eligible", "review", "blocked"]),
  requires_approval: z.boolean(),
  reviewer_decision: z.enum(["approved", "rejected", "pending"]),
  batch_id: z.string().min(1).optional(),
  pair_digest: z.string().min(1),
  source_evidence_hash: z.string().min(1),
  target_evidence_hash: z.string().min(1),
  evidence: z.object({
    match_type: z.enum(["email", "phone", "name"]),
    identifier_hash: z.string().min(1),
    masked_value: z.string(),
  }).strict(),
  recommendation: z.object({ reason: z.string() }).strict(),
  block_reasons: z.array(z.string()),
}).strict();

const mergeManifestV1Schema = z.object({
  schema: z.literal("gorgias-customer-merge-manifest.v1"),
  generated_at: z.string().min(1),
  exporter_version: z.string().min(1),
  immutable_manifest_digest: z.string().min(1),
  canary_completed: z.boolean(),
  batches: z.array(z.object({
    id: z.string().min(1),
    approved: z.boolean(),
    approved_pair_count: z.number().int().nonnegative().optional(),
    approved_pair_digests: z.array(z.string()).optional(),
    approved_at: z.string().optional(),
    approved_by: z.string().optional(),
  }).strict()),
  pairs: z.array(mergeManifestPairSchema),
}).strict();

function serviceVersion(): string {
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  for (const candidate of [join(moduleDir, "VERSION"), join(moduleDir, "..", "VERSION")]) {
    try {
      const version = readFileSync(candidate, "utf8").trim();
      if (/^\d+\.\d+\.\d+$/.test(version)) return version;
    } catch {
    }
  }
  return "unknown";
}

function readJsonFile<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function readMergeManifestV1(path: string): MergeManifest {
  const parsed = mergeManifestV1Schema.safeParse(readJsonFile<unknown>(path));
  if (!parsed.success) {
    throw new Error("merge manifest must match the exact gorgias-customer-merge-manifest.v1 schema");
  }
  return parsed.data as MergeManifest;
}

function writeJsonFile(path: string | undefined, value: unknown): void {
  if (!path) return;
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function writeRestrictedFile(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(temporary, contents, { mode: 0o600 });
  renameSync(temporary, path);
  chmodSync(path, 0o600);
}

function writeRestrictedJson(path: string, value: unknown): void {
  writeRestrictedFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

function isRunOwnedPath(runDir: string, path: string): boolean {
  const pathFromRun = relative(resolve(runDir), resolve(path));
  return pathFromRun.length > 0 && !pathFromRun.startsWith("..") && !isAbsolute(pathFromRun);
}

type CustomerMatchDiscoveryArgs = {
  runDir: string;
  keyPath: string;
  defaultCountry: string;
  expectedCustomerCount?: number;
  requestIntervalMs: number;
  maxRetries: number;
  maxStabilizationPasses: number;
  resume: boolean;
  auditPerStratum: number;
  proposalPath?: string;
  reportPath?: string;
  auditPath?: string;
  operator?: string;
  gitCommit?: string;
};

function discoverBizRoot(moduleUrl: string): string {
  let candidate = dirname(fileURLToPath(moduleUrl));
  for (let depth = 0; depth < 6; depth += 1) {
    if (
      existsSync(join(candidate, "config/sync-protected-artifacts.json")) &&
      existsSync(join(candidate, "scripts/sync/protected-artifact-recovery.mjs"))
    ) return candidate;
    const parent = dirname(candidate);
    if (parent === candidate) break;
    candidate = parent;
  }
  throw new Error("could not locate the Biz protected-artifact controller root");
}

const BIZ_ROOT = discoverBizRoot(import.meta.url);
const PROTECTED_PRODUCER = join(BIZ_ROOT, "scripts/sync/protected-artifact-recovery.mjs");
const CUSTOMER_MATCH_PREFIX = join(BIZ_ROOT, "var/gorgias-customer-dedupe");
const CUSTOMER_MATCH_PRODUCER = "gorgias-customer-match-discovery";

export const protectedCustomerMatchProducerPathsForTest = Object.freeze({
  bizRoot: BIZ_ROOT,
  producer: PROTECTED_PRODUCER,
  prefix: CUSTOMER_MATCH_PREFIX,
});

function producerChild(args: string[]): Record<string, unknown> {
  const result = spawnSync(process.execPath, [PROTECTED_PRODUCER, ...args, "--json"], {
    cwd: BIZ_ROOT,
    encoding: "utf8",
    env: process.env,
    maxBuffer: 1024 * 1024,
    timeout: 30_000,
  });
  let value: Record<string, unknown>;
  try {
    value = JSON.parse(result.stdout) as Record<string, unknown>;
  } catch {
    throw new Error("protected artifact producer returned malformed output");
  }
  if (result.status !== 0 || value.status !== "OK") {
    throw new Error("protected artifact producer failed closed");
  }
  return value;
}

function producerContainedPath(runDir: string, path: string, label: string): string {
  const fromRun = relative(runDir, resolve(path));
  if (!fromRun || fromRun.startsWith("..") || isAbsolute(fromRun)) {
    throw new Error(`${label} must be a file inside the registered run directory`);
  }
  return fromRun;
}

function rewriteStagedPaths(value: unknown, stagePath: string, finalPath: string): unknown {
  if (typeof value === "string") {
    return value === stagePath || value.startsWith(`${stagePath}/`)
      ? `${finalPath}${value.slice(stagePath.length)}`
      : value;
  }
  if (Array.isArray(value)) return value.map((entry) => rewriteStagedPaths(entry, stagePath, finalPath));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, rewriteStagedPaths(entry, stagePath, finalPath)]));
  }
  return value;
}

function normalizeCustomerMatchProducerPlaintext(
  stagePath: string,
  finalRunDir: string,
  args: CustomerMatchDiscoveryArgs,
): void {
  const jsonPaths = [
    join(stagePath, "scan.json"),
    join(stagePath, "run-notes.json"),
    args.proposalPath ?? join(stagePath, "match-proposal.json"),
    args.auditPath ?? join(stagePath, "match-audit.json"),
  ].filter((path) => existsSync(path));
  for (const path of jsonPaths) {
    const value = JSON.parse(readFileSync(path, "utf8")) as unknown;
    const normalized = rewriteStagedPaths(value, stagePath, finalRunDir);
    writeRestrictedJson(path, normalized);
    if (JSON.stringify(normalized).includes(stagePath)) {
      throw new Error("protected discovery JSON retained a private staging path");
    }
  }
  const reportPath = args.reportPath ?? join(stagePath, "match-report.md");
  const report = readFileSync(reportPath, "utf8");
  const normalizedReport = report.split(stagePath).join(finalRunDir);
  writeRestrictedFile(reportPath, normalizedReport);
  if (normalizedReport.includes(stagePath)) {
    throw new Error("protected discovery report retained a private staging path");
  }
  for (const path of [...jsonPaths, reportPath]) {
    if (readFileSync(path, "utf8").includes(stagePath)) {
      throw new Error("protected discovery plaintext retained a private staging path");
    }
  }
}

function validateCustomerMatchProducerOutput(
  stagePath: string,
  args: CustomerMatchDiscoveryArgs,
  logicalArgs: CustomerMatchDiscoveryArgs,
  result: unknown,
): void {
  const metadata = (result as { metadata?: Record<string, unknown> })?.metadata;
  const complete = metadata?.scan_complete === true;
  const expected = new Set([
    resolve(args.keyPath),
    resolve(stagePath, "evidence-stage.jsonl.enc"),
    resolve(stagePath, "scan.json"),
    resolve(args.reportPath ?? join(stagePath, "match-report.md")),
    resolve(stagePath, "run-notes.json"),
    ...(complete ? [
      resolve(args.proposalPath ?? join(stagePath, "match-proposal.json")),
      resolve(args.auditPath ?? join(stagePath, "match-audit.json")),
    ] : []),
  ]);
  const observed = new Set<string>();
  const walk = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const stats = lstatSync(path);
      if (stats.isSymbolicLink()) throw new Error("protected discovery output contains a symlink");
      if (stats.isDirectory()) walk(path);
      else if (stats.isFile()) observed.add(resolve(path));
      else throw new Error("protected discovery output has an unsupported type");
    }
  };
  walk(stagePath);
  if (
    observed.size !== expected.size ||
    [...expected].some((path) => !observed.has(path)) ||
    [...observed].some((path) => !expected.has(path))
  ) throw new Error("protected discovery output inventory violated its registered invariant");
  const scan = JSON.parse(readFileSync(join(stagePath, "scan.json"), "utf8")) as {
    scanComplete?: boolean; runDir?: string; stagePath?: string;
  };
  const notes = JSON.parse(readFileSync(join(stagePath, "run-notes.json"), "utf8")) as {
    command?: string; status?: string; arguments?: Record<string, unknown>;
  };
  const expectedLogical = {
    runDir: resolve(logicalArgs.runDir),
    keyPath: resolve(logicalArgs.keyPath),
    proposalPath: resolve(logicalArgs.proposalPath ?? join(logicalArgs.runDir, "match-proposal.json")),
    reportPath: resolve(logicalArgs.reportPath ?? join(logicalArgs.runDir, "match-report.md")),
    auditPath: resolve(logicalArgs.auditPath ?? join(logicalArgs.runDir, "match-audit.json")),
  };
  if (
    scan.scanComplete !== complete ||
    scan.runDir !== expectedLogical.runDir ||
    scan.stagePath !== join(expectedLogical.runDir, "evidence-stage.jsonl.enc") ||
    notes.command !== "discover-customer-matches" ||
    typeof notes.status !== "string" ||
    notes.arguments?.runDir !== expectedLogical.runDir ||
    notes.arguments?.keyPath !== expectedLogical.keyPath ||
    notes.arguments?.proposalPath !== expectedLogical.proposalPath ||
    notes.arguments?.reportPath !== expectedLogical.reportPath ||
    notes.arguments?.auditPath !== expectedLogical.auditPath ||
    JSON.stringify(result).includes(stagePath) ||
    readFileSync(args.keyPath).length < 32 ||
    readFileSync(join(stagePath, "evidence-stage.jsonl.enc")).length === 0 ||
    readFileSync(args.reportPath ?? join(stagePath, "match-report.md")).length === 0
  ) throw new Error("protected discovery output semantic invariant failed");
}

export async function withProtectedCustomerMatchProducer<T>(
  input: CustomerMatchDiscoveryArgs,
  operation: (args: CustomerMatchDiscoveryArgs) => Promise<T>,
  producerCommand: (args: string[]) => Record<string, unknown> = producerChild,
): Promise<T> {
  const finalRunDir = resolve(input.runDir);
  const fromPrefix = relative(CUSTOMER_MATCH_PREFIX, finalRunDir);
  if (!fromPrefix || fromPrefix.startsWith("..") || isAbsolute(fromPrefix)) {
    throw new Error("runDir must be inside the registered Gorgias protected prefix");
  }
  const paths = {
    keyPath: producerContainedPath(finalRunDir, input.keyPath, "keyPath"),
    ...(input.proposalPath ? { proposalPath: producerContainedPath(finalRunDir, input.proposalPath, "proposalPath") } : {}),
    ...(input.reportPath ? { reportPath: producerContainedPath(finalRunDir, input.reportPath, "reportPath") } : {}),
    ...(input.auditPath ? { auditPath: producerContainedPath(finalRunDir, input.auditPath, "auditPath") } : {}),
  };
  const expectedPath = relative(BIZ_ROOT, finalRunDir).split("\\").join("/");
  const fingerprint = createHash("sha256").update(JSON.stringify({
    expectedPath,
    defaultCountry: input.defaultCountry,
    expectedCustomerCount: input.expectedCustomerCount ?? null,
    requestIntervalMs: input.requestIntervalMs,
    maxRetries: input.maxRetries,
    maxStabilizationPasses: input.maxStabilizationPasses,
    resume: input.resume,
    auditPerStratum: input.auditPerStratum,
    operator: input.operator ?? process.env.USER ?? "unknown",
    gitCommit: input.gitCommit ?? "unknown",
    outputPaths: paths,
  })).digest("hex");
  const begun = producerCommand([
    "producer-begin", "--producer-id", CUSTOMER_MATCH_PRODUCER,
    "--expected-path", expectedPath, "--input-fingerprint", fingerprint,
  ]);
  const transactionId = begun.transactionId;
  const stagePath = begun.stagePath;
  if (typeof transactionId !== "string" || typeof stagePath !== "string" || !isAbsolute(stagePath)) {
    throw new Error("protected artifact producer returned an invalid transaction");
  }
  const stagedArgs: CustomerMatchDiscoveryArgs = {
    ...input,
    runDir: stagePath,
    keyPath: join(stagePath, paths.keyPath),
    ...(paths.proposalPath ? { proposalPath: join(stagePath, paths.proposalPath) } : {}),
    ...(paths.reportPath ? { reportPath: join(stagePath, paths.reportPath) } : {}),
    ...(paths.auditPath ? { auditPath: join(stagePath, paths.auditPath) } : {}),
  };
  const logicalArgs: CustomerMatchDiscoveryArgs = {
    ...input,
    runDir: finalRunDir,
    keyPath: join(finalRunDir, paths.keyPath),
    ...(paths.proposalPath ? { proposalPath: join(finalRunDir, paths.proposalPath) } : {}),
    ...(paths.reportPath ? { reportPath: join(finalRunDir, paths.reportPath) } : {}),
    ...(paths.auditPath ? { auditPath: join(finalRunDir, paths.auditPath) } : {}),
  };
  try {
    const result = await operation(stagedArgs);
    normalizeCustomerMatchProducerPlaintext(stagePath, finalRunDir, stagedArgs);
    const normalizedResult = rewriteStagedPaths(result, stagePath, finalRunDir) as T;
    validateCustomerMatchProducerOutput(stagePath, stagedArgs, logicalArgs, normalizedResult);
    producerCommand([
      "producer-commit", "--producer-id", CUSTOMER_MATCH_PRODUCER,
      "--transaction-id", transactionId,
    ]);
    return normalizedResult;
  } catch (error) {
    try {
      producerCommand([
        "producer-abort", "--producer-id", CUSTOMER_MATCH_PRODUCER,
        "--transaction-id", transactionId,
      ]);
    } catch (abortError) {
      throw new Error("protected artifact producer rollback failed", { cause: abortError });
    }
    throw error;
  }
}

function exportedSummariesFrom(value: unknown): CustomerSummary[] {
  const root = value as {
    customers?: unknown;
    content?: { customers?: unknown };
  };
  const customers = root.content?.customers ?? root.customers;
  if (!Array.isArray(customers)) {
    throw new Error("export artifact must contain content.customers");
  }
  return customers as CustomerSummary[];
}

function withOperationStatus<T extends object>(
  output: T,
  ok: boolean,
  errorCount: number,
): T & { ok: boolean; partialFailure: boolean; errorCount: number } {
  return Object.assign(output, {
    ok,
    partialFailure: !ok || errorCount > 0,
    errorCount,
  });
}

function disableClientCache(client: GorgiasClient): void {
  const maybeClient = client as { disableCache?: unknown };
  if (typeof maybeClient.disableCache === "function") {
    maybeClient.disableCache();
  }
}

function sanitizeCustomerInspection(inspection: CustomerInspection): Record<string, unknown> {
  const safe: Record<string, unknown> = {
    customerId: inspection.customerId,
    httpStatus: inspection.httpStatus,
    status: inspection.status,
  };
  if (inspection.location) {
    safe.location = inspection.location;
  }
  if (inspection.customer) {
    const summary = summarizeCustomerForDedupe(inspection.customer);
    safe.evidence_hash = summary.evidence_hash;
    safe.summary = {
      id: summary.id,
      created_datetime: summary.created_datetime,
      updated_datetime: summary.updated_datetime,
      email_hash_count: summary.email_hashes.length,
      phone_hash_count: summary.phone_hashes.length,
      channel_count: summary.channel_count,
      integration_names: summary.integration_names,
      shopify_customer_id_count: summary.shopify_customer_id_count,
      has_shopify_orders: summary.has_shopify_orders,
      shopify_order_count: summary.shopify_order_count,
    };
  }
  return safe;
}

interface CustomerMergeLock {
  lockRoot: string;
  lockDirs: string[];
}

interface MergeStatusFile {
  schema: "gorgias-customer-merge-status.v2";
  manifest_digest: string;
  batch_id: string;
  mode: "shadow" | "enforce";
  status: string;
  updated_at: string;
  results: Array<Record<string, unknown>>;
}

const MERGE_RUN_STATUSES = new Set([
  "preflight_failed",
  "shadow_complete",
  "preflight_passed",
  "merge_requested",
  "merge_accepted",
  "readback_failed",
  "running",
  "failed",
  "completed",
]);

const MERGE_PAIR_STATUSES = new Set([
  "preflight_passed",
  "preflight_blocked",
  "merge_requested",
  "merge_accepted",
  "provider_failed",
  "readback_failed",
  "verified",
]);

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function customerMatchScanDigest(scan: CustomerMatchScanResult): string {
  return sha256(JSON.stringify({
    schema: scan.schema,
    keyId: scan.keyId,
    stabilizationPasses: scan.stabilizationPasses,
    customerDrift: scan.customerDrift,
    ledgers: {
      customers: {
        count: scan.ledgers.customers.count,
        totalCount: scan.ledgers.customers.totalCount ?? null,
        digest: scan.ledgers.customers.digest,
      },
      tickets: {
        count: scan.ledgers.tickets.count,
        totalCount: scan.ledgers.tickets.totalCount ?? null,
        digest: scan.ledgers.tickets.digest,
      },
      messages: {
        count: scan.ledgers.messages.count,
        totalCount: scan.ledgers.messages.totalCount ?? null,
        digest: scan.ledgers.messages.digest,
      },
    },
    messageCoverage: scan.messageCoverage,
    recordCounts: scan.recordCounts,
  }));
}

function customerMatchConfidenceCounts(proposal: CustomerMatchReviewProposal): Record<MatchConfidence, number> {
  const counts: Record<MatchConfidence, number> = {
    strong_candidate: 0,
    corroborated_candidate: 0,
    possible_match: 0,
    relationship_only: 0,
    conflict: 0,
  };
  for (const edge of proposal.edges) counts[edge.confidence] += 1;
  return counts;
}

function renderCustomerMatchReport(
  scan: CustomerMatchScanResult,
  proposal: CustomerMatchReviewProposal,
): string {
  const confidenceCounts = customerMatchConfidenceCounts(proposal);
  const lines = [
    "# Gorgias Customer Match Review",
    "",
    `Generated: ${proposal.generatedAt}`,
    `Proposal digest: ${proposal.proposalDigest}`,
    `Profiles scanned: ${proposal.profileCount}`,
    `Profiles excluded by internal-domain policy: ${proposal.excludedProfileCount}`,
    `Profiles eligible for matching: ${proposal.profileCount - proposal.excludedProfileCount}`,
    `Candidate/relationship edges: ${proposal.edgeCount}`,
    `Customers scanned: ${scan.recordCounts.customers}`,
    `Tickets scanned: ${scan.recordCounts.tickets}`,
    `Messages scanned: ${scan.recordCounts.messages}`,
    "",
    "No live merges were executed. This artifact is review-only and has no source/target or approval fields.",
    "",
    "## Confidence Counts",
    "",
    ...Object.entries(confidenceCounts).map(([confidence, count]) => `- ${confidence}: ${count}`),
    "",
    "## Rule Counts",
    "",
    ...Object.entries(proposal.ruleCounts).map(([rule, count]) => `- ${rule}: ${count}`),
    "",
    "## Audit",
    "",
    `Audit ready: ${proposal.audit.ready}`,
    `Requested per stratum: ${proposal.audit.perStratum}`,
    ...Object.entries(proposal.audit.shortfalls).map(([stratum, count]) => `- ${stratum} shortfall: ${count}`),
    "",
    "## Review Edges",
    "",
    "| Edge | Customer records | Confidence | Rules | Blockers | Relationship flags | Shopify verification |",
    "|---|---:|---|---|---|---|---|",
    ...proposal.edges.map((edge) => [
      edge.edgeId,
      edge.recordIds.join(" / "),
      edge.confidence,
      edge.rules.join(", ") || "-",
      edge.blockers.join(", ") || "-",
      edge.relationshipFlags.join(", ") || "-",
      edge.evidence.some((entry) => entry.requiresShopifyVerification) ? "required" : "no",
    ].map((value) => String(value).replaceAll("|", "\\|")).join(" | ")).map((row) => `| ${row} |`),
    "",
  ];
  return `${lines.join("\n")}\n`;
}

function renderIncompleteCustomerMatchReport(scan: CustomerMatchScanResult): string {
  const lines = [
    "# Gorgias Customer Match Review",
    "",
    "Scan status: incomplete",
    `Customers observed: ${scan.recordCounts.customers}`,
    `Tickets observed: ${scan.recordCounts.tickets}`,
    `Messages observed: ${scan.recordCounts.messages}`,
    "",
    "No proposal was generated and no live merges were executed.",
    "",
    "## Coverage Errors",
    "",
    ...(scan.errors.length > 0 ? scan.errors.map((error) => `- ${error}`) : ["- coverage could not be proven"]),
    "",
  ];
  return `${lines.join("\n")}\n`;
}

function defaultMergeLockRoot(): string {
  return process.env.GORGIAS_MERGE_LOCK_ROOT || fileURLToPath(new URL("../../var/gorgias-customer-merge-locks", import.meta.url));
}

function defaultMergeStatusPath(manifest: MergeManifest, batchId: string): string {
  const statusRoot = process.env.GORGIAS_MERGE_STATUS_ROOT || fileURLToPath(new URL("../../var/gorgias-customer-merges", import.meta.url));
  return join(statusRoot, `${batchId}-${manifest.immutable_manifest_digest.slice(0, 16)}.status.json`);
}

function acquireCustomerMergeLocks(
  customerIds: number[],
  metadata: Record<string, unknown>,
): CustomerMergeLock {
  const lockRoot = defaultMergeLockRoot();
  mkdirSync(lockRoot, { recursive: true });
  const created: string[] = [];
  const uniqueIds = [...new Set(customerIds)].sort((a, b) => a - b);
  try {
    for (const customerId of uniqueIds) {
      const lockDir = join(lockRoot, `customer-${customerId}.lock`);
      mkdirSync(lockDir);
      created.push(lockDir);
      writeFileSync(join(lockDir, "lock.json"), `${JSON.stringify({
        ...metadata,
        customer_id: customerId,
        pid: process.pid,
        created_at: new Date().toISOString(),
      }, null, 2)}\n`);
    }
    return { lockRoot, lockDirs: created };
  } catch (error) {
    for (const lockDir of created.reverse()) {
      rmSync(lockDir, { recursive: true, force: true });
    }
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`merge-customers found an active customer lock; refusing concurrent execution (${message})`);
  }
}

function releaseCustomerMergeLocks(lock: CustomerMergeLock | undefined): void {
  if (!lock) return;
  for (const lockDir of lock.lockDirs.slice().reverse()) {
    rmSync(lockDir, { recursive: true, force: true });
  }
}

function writeMergeStatus(
  statusPath: string,
  manifest: MergeManifest,
  batchId: string,
  mode: "shadow" | "enforce",
  status: string,
  results: Array<Record<string, unknown>>,
): void {
  writeRestrictedJson(statusPath, {
    schema: "gorgias-customer-merge-status.v2",
    manifest_digest: manifest.immutable_manifest_digest,
    batch_id: batchId,
    mode,
    status,
    updated_at: new Date().toISOString(),
    results,
  } satisfies MergeStatusFile);
}

function readMergeStatus(
  statusPath: string,
  manifest: MergeManifest,
  batchId: string,
  expectedMode: "shadow" | "enforce",
): MergeStatusFile | null {
  if (!existsSync(statusPath)) return null;
  let parsed: unknown;
  try {
    parsed = readJsonFile<unknown>(statusPath);
  } catch {
    throw new Error("existing merge status is unreadable; refusing to risk a duplicate provider write");
  }
  const record = parsed && typeof parsed === "object" ? parsed as Partial<MergeStatusFile> : {};
  const expectedPairs = new Map(
    manifest.pairs
      .filter((pair) => pair.batch_id === batchId)
      .map((pair) => [pair.id, pair] as const),
  );
  const seenPairIds = new Set<string>();
  const validResults = Array.isArray(record.results)
    && record.results.length === expectedPairs.size
    && record.results.every((value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) return false;
      const result = value as Record<string, unknown>;
      const pairId = typeof result.pairId === "string" ? result.pairId : "";
      const expectedPair = expectedPairs.get(pairId);
      if (!expectedPair || seenPairIds.has(pairId)) return false;
      seenPairIds.add(pairId);
      return result.sourceId === expectedPair.source_id
        && result.targetId === expectedPair.target_id
        && typeof result.status === "string"
        && MERGE_PAIR_STATUSES.has(result.status);
    });
  if (
    record.schema !== "gorgias-customer-merge-status.v2"
    || record.manifest_digest !== manifest.immutable_manifest_digest
    || record.batch_id !== batchId
    || record.mode !== expectedMode
    || typeof record.status !== "string"
    || !MERGE_RUN_STATUSES.has(record.status)
    || typeof record.updated_at !== "string"
    || !Number.isFinite(Date.parse(record.updated_at))
    || !validResults
  ) {
    throw new Error("existing merge status does not match this manifest batch; refusing to overwrite it");
  }
  return record as MergeStatusFile;
}

function replaceMergeResult(
  results: Array<Record<string, unknown>>,
  pairId: string,
  replacement: Record<string, unknown>,
): Array<Record<string, unknown>> {
  const existingIndex = results.findIndex((result) => result.pairId === pairId);
  if (existingIndex < 0) return [...results, replacement];
  return results.map((result, index) => index === existingIndex ? replacement : result);
}

function persistedPairStatus(result: Record<string, unknown> | undefined): string | undefined {
  return typeof result?.status === "string" ? result.status : undefined;
}

function sanitizeMergeError(error: unknown): Record<string, unknown> {
  const record = error && typeof error === "object" ? error as Record<string, unknown> : {};
  const status = typeof record.status === "number" ? record.status : undefined;
  const requestId = typeof record.requestId === "string" ? record.requestId : undefined;
  return {
    category: status ? "gorgias_api_error" : "merge_error",
    message: status ? `Gorgias API error (${status})` : "merge operation failed",
    ...(status ? { status } : {}),
    ...(requestId ? { request_id: requestId } : {}),
    error_hash: sha256(error instanceof Error ? error.message : String(error)).slice(0, 16),
  };
}

export const commands = {
  "list-tools": createCommand(
    z.object({}),
    async (_args, client: GorgiasClient) => client.getTools(),
    "List all available CLI commands",
    { sideEffect: "read" }
  ),

  "list-tickets": createCommand(
    z.object({
      limit: cliTypes.limit(50, 250),
      status: z.enum(["open", "closed"]).optional().describe("Filter by status (client-side)"),
      search: z.string().optional().describe("Search tickets by keyword (client-side)"),
      orderBy: z.string().optional().describe("Order by field (e.g., created_datetime:desc)"),
      cursor: z.string().optional().describe("Opaque pagination cursor from metadata.next_cursor"),
      resumeToken: z.string().optional().describe("Opaque filtered-pagination token from metadata.resume_token"),
      checkpointPath: z.string().optional().describe("Optional 0600 JSON checkpoint rewritten after every provider page"),
      updatedAfter: z.string().optional().describe(
        "ISO datetime cursor — client-side filter over tickets ordered by updated_datetime:desc"
      ),
    }),
    async (args, client: GorgiasClient) => {
      const { limit, status, search, orderBy, cursor, resumeToken, checkpointPath, updatedAfter } = args as {
        limit: number;
        status?: "open" | "closed";
        search?: string;
        orderBy?: string;
        cursor?: string;
        resumeToken?: string;
        checkpointPath?: string;
        updatedAfter?: string;
      };
      const checkpoint = (pagination: FilteredTicketPaginationResult) => {
        if (!checkpointPath) return;
        writeRestrictedJson(
          checkpointPath,
          renderTicketPaginationOutput(client, pagination, checkpointPath),
        );
      };
      try {
        const pagination = await paginateFilteredTickets(client, {
          limit,
          status,
          search,
          orderBy,
          cursor,
          updatedAfter,
          resumeToken,
        }, checkpoint);
        return renderTicketPaginationOutput(client, pagination, checkpointPath);
      } catch (error) {
        if (checkpointPath && error instanceof TicketPaginationFailure) {
          writeRestrictedJson(
            checkpointPath,
            renderTicketPaginationOutput(client, error.partial, checkpointPath, sanitizeMergeError(error)),
          );
        }
        throw error;
      }
    },
    "List tickets with optional filtering",
    { sideEffect: "read" }
  ),

  "get-ticket": createCommand(
    z.object({
      id: cliTypes.int(1).describe("Ticket ID"),
    }),
    async (args, client: GorgiasClient) => {
      const { id } = args as { id: number };
      const ticket = await client.getTicket(id) as TicketDetails;

      const metadata = {
        id: ticket.id,
        status: ticket.status,
        priority: ticket.priority,
        channel: ticket.channel,
        created_datetime: ticket.created_datetime,
        updated_datetime: ticket.updated_datetime,
        opened_datetime: ticket.opened_datetime,
        closed_datetime: ticket.closed_datetime,
        tags: (ticket.tags || []).map((t: TicketTag) => t?.name),
        messages_count: ticket.messages_count,
        is_unread: ticket.is_unread,
        spam: ticket.spam,
        trashed_datetime: ticket.trashed_datetime ?? null,
        customer_subdomain: client.getSubdomain(),
      };

      const messages = (ticket.messages || []).map((msg: TicketMessage) => ({
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
    "Get ticket details by ID",
    { sideEffect: "read" }
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
      const result = await client.createTicket({ customerEmail, subject, message });
      return wrapProviderResponse("create-ticket", result);
    },
    "Create a new support ticket",
    { sideEffect: "write", requiresSafeOutput: true }
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
      if (fromAgent) {
        const ticket = await client.getTicket(ticketId, { fresh: true });
        if (ticket.channel?.toLowerCase() === "email") {
          throw new Error(
            "refusing generic add-message for an email ticket: fixture-backed routing fields and delivery-state polling are not implemented",
          );
        }
      }
      const result = await client.addMessage(ticketId, message, fromAgent);
      return wrapProviderResponse("add-message", result);
    },
    "Add an API-channel message to a non-email ticket",
    { sideEffect: "external_send", requiresConfirmation: true, requiresSafeOutput: true }
  ),

  "list-customers": createCommand(
    z.object({
      limit: cliTypes.limit(50, 250),
      email: z.string().optional().describe("Filter by email address"),
    }),
    async (args, client: GorgiasClient) => {
      const { limit, email } = args as { limit: number; email?: string };
      const result = await client.listCustomers({ limit, email });

      const customers = (result.data || []).map((customer: CustomerListItem) => ({
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
    "List customers with optional email filter",
    { sideEffect: "read" }
  ),

  "get-customer": createCommand(
    z.object({
      id: cliTypes.int(1).describe("Customer ID"),
    }),
    async (args, client: GorgiasClient) => {
      const { id } = args as { id: number };
      const customer: Customer = await client.getCustomer(id);

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
    "Get customer details by ID",
    { sideEffect: "read" }
  ),

  "export-customers": createCommand(
    z.object({
      limit: cliTypes.limit(500, 100000).describe("Maximum customers to export"),
      pageLimit: cliTypes.limit(100, 250).describe("Customers per API page"),
      maxPages: intDefault(1000, 1, 10000).describe("Maximum API pages to read"),
      outputPath: z.string().optional().describe("Optional path to write the JSON export"),
    }),
    async (args, client: GorgiasClient) => {
      const { limit, pageLimit, maxPages, outputPath } = args as {
        limit: number;
        pageLimit: number;
        maxPages: number;
        outputPath?: string;
      };
      const customers: CustomerSummary[] = [];
      let cursor: string | undefined;
      let pages = 0;
      let nextCursor: string | undefined;

      while (customers.length < limit && pages < maxPages) {
        const page = await client.listCustomers({
          limit: Math.min(pageLimit, limit - customers.length),
          cursor,
        });
        pages += 1;
        for (const customer of page.data || []) {
          customers.push(summarizeCustomerForDedupe(customer));
          if (customers.length >= limit) break;
        }
        nextCursor = page.meta?.next_cursor ?? page.meta?.cursor ?? undefined;
        if (!nextCursor) break;
        cursor = nextCursor;
      }

      const output = buildSafeOutput(
        {
          command: "export-customers",
          count: customers.length,
          pages,
          has_more: Boolean(nextCursor),
          next_cursor: nextCursor ?? null,
          exporter_version: serviceVersion(),
          output_path: outputPath ?? null,
          pii: "pseudonymous-masked-and-hashed",
          hash_strategy: "deterministic-sha256-service-prefix",
        },
        { customers },
      );
      writeJsonFile(outputPath, output);
      return output;
    },
    "Export PII-minimized customer dedupe evidence",
    { sideEffect: "read" },
  ),

  "generate-merge-manifest": createCommand(
    z.object({
      exportPath: z.string().min(1).describe("Path to export-customers JSON"),
      outputPath: z.string().optional().describe("Optional path to write the manifest"),
      batchId: z.string().default("batch-1").describe("Initial approval batch ID"),
    }),
    async (args) => {
      const { exportPath, outputPath, batchId } = args as {
        exportPath: string;
        outputPath?: string;
        batchId: string;
      };
      const summaries = exportedSummariesFrom(readJsonFile<unknown>(exportPath));
      const manifest = buildMergeManifestFromSummaries({
        summaries,
        batchId,
        generatedAt: new Date().toISOString(),
        exporterVersion: serviceVersion(),
      });
      writeJsonFile(outputPath, manifest);
      return buildSafeOutput(
        {
          command: "generate-merge-manifest",
          pair_count: manifest.pairs.length,
          eligible_count: manifest.pairs.filter((pair) => pair.status === "eligible").length,
          blocked_count: manifest.pairs.filter((pair) => pair.status === "blocked").length,
          review_count: manifest.pairs.filter((pair) => pair.status === "review").length,
          output_path: outputPath ?? null,
        },
        { manifest },
      );
    },
    "Generate a customer merge approval manifest",
    { sideEffect: "read" },
  ),

  "discover-customer-matches": createCommand(
    z.object({
      runDir: z.string().min(1).describe("Restricted directory for this review run"),
      keyPath: z.string().min(1).describe("Path to the 0600 per-run encryption key"),
      defaultCountry: z.string().length(2).default("GB").describe("ISO country used for local phone parsing"),
      expectedCustomerCount: optionalInt(1, 10_000_000).describe("Optional strict customer count gate"),
      requestIntervalMs: intDefault(1_000, 0, 60_000).describe("Minimum delay between Gorgias GET requests"),
      maxRetries: intDefault(5, 0, 20).describe("Maximum retries for retryable GET failures"),
      maxStabilizationPasses: intDefault(6, 2, 20).describe("Maximum full enumeration passes"),
      resume: boolDefaultFalse().describe("Resume an existing encrypted scan"),
      auditPerStratum: intDefault(60, 1, 1_000).describe("Review sample size for each audit stratum"),
      proposalPath: z.string().min(1).optional().describe("Optional v2 proposal output path"),
      reportPath: z.string().min(1).optional().describe("Optional Markdown report output path"),
      auditPath: z.string().min(1).optional().describe("Optional audit review output path"),
      operator: z.string().min(1).max(200).optional().describe("Operator recorded in run notes"),
      gitCommit: z.string().min(1).max(100).optional().describe("Git commit recorded in run notes"),
    }),
    async (args, client: GorgiasClient, globals) => {
      const testProducer = (globals as typeof globals & {
        protectedCustomerMatchProducerForTest?: typeof withProtectedCustomerMatchProducer;
      }).protectedCustomerMatchProducerForTest;
      const producer = testProducer ?? withProtectedCustomerMatchProducer;
      return producer(args as CustomerMatchDiscoveryArgs, async (protectedArgs) => {
      const {
        runDir,
        keyPath,
        defaultCountry,
        expectedCustomerCount,
        requestIntervalMs,
        maxRetries,
        maxStabilizationPasses,
        resume,
        auditPerStratum,
        proposalPath,
        reportPath,
        auditPath,
        operator,
        gitCommit,
      } = protectedArgs;
      const startedAt = new Date().toISOString();
      const resolvedProposalPath = proposalPath ?? join(runDir, "match-proposal.json");
      const resolvedReportPath = reportPath ?? join(runDir, "match-report.md");
      const resolvedAuditPath = auditPath ?? join(runDir, "match-audit.json");
      const runNotesPath = join(runDir, "run-notes.json");
      const scan = await runCustomerMatchScan({
        client: createCustomerMatchReadClient(client),
        runDir,
        keyPath,
        defaultCountry: defaultCountry.toUpperCase(),
        ...(expectedCustomerCount !== undefined ? { expectedCustomerCount } : {}),
        requestIntervalMs,
        maxRetries,
        maxStabilizationPasses,
        resume,
      });
      const runArguments = {
        runDir,
        keyPath,
        defaultCountry: defaultCountry.toUpperCase(),
        expectedCustomerCount: expectedCustomerCount ?? null,
        requestIntervalMs,
        maxRetries,
        maxStabilizationPasses,
        resume,
        auditPerStratum,
        proposalPath: resolvedProposalPath,
        reportPath: resolvedReportPath,
        auditPath: resolvedAuditPath,
      };

      if (!scan.scanComplete) {
        if (isRunOwnedPath(runDir, resolvedProposalPath)) rmSync(resolvedProposalPath, { force: true });
        if (isRunOwnedPath(runDir, resolvedAuditPath)) rmSync(resolvedAuditPath, { force: true });
        writeRestrictedFile(resolvedReportPath, renderIncompleteCustomerMatchReport(scan));
        writeRestrictedJson(runNotesPath, {
          schema: "gorgias-customer-match-run-notes.v2",
          command: "discover-customer-matches",
          status: "scan_incomplete",
          operator: operator ?? process.env.USER ?? "unknown",
          gitCommit: gitCommit ?? "unknown",
          cliVersion: serviceVersion(),
          startedAt,
          completedAt: new Date().toISOString(),
          arguments: runArguments,
          sensitiveData: "encrypted staging and pseudonymous review artifacts",
          liveMergesExecuted: 0,
        });
        const errorCount = Math.max(1, scan.errors.length);
        return withOperationStatus(
          buildSafeOutput(
            {
              command: "discover-customer-matches",
              scan_complete: false,
              proposal_generated: false,
              report_path: resolvedReportPath,
              run_notes_path: runNotesPath,
              no_live_merges: true,
            },
            { errors: scan.errors, record_counts: scan.recordCounts },
          ),
          false,
          errorCount,
        );
      }

      const loaded = loadCustomerMatchStage({
        stagePath: scan.stagePath,
        keyPath,
        expectedKeyId: scan.keyId,
      });
      const generatedAt = new Date().toISOString();
      const proposal = buildCustomerMatchReview({
        records: loaded.records,
        crypto: loaded.crypto,
        generatedAt,
        scanDigest: customerMatchScanDigest(scan),
        scanComplete: true,
        auditPerStratum,
      });
      const auditArtifact = {
        schema: "gorgias-customer-match-audit.v2",
        generatedAt,
        proposalDigest: proposal.proposalDigest,
        inputDigest: proposal.inputDigest,
        ...proposal.audit,
      };
      const confidenceCounts = customerMatchConfidenceCounts(proposal);
      writeRestrictedJson(resolvedProposalPath, proposal);
      writeRestrictedFile(resolvedReportPath, renderCustomerMatchReport(scan, proposal));
      writeRestrictedJson(resolvedAuditPath, auditArtifact);
      writeRestrictedJson(runNotesPath, {
        schema: "gorgias-customer-match-run-notes.v2",
        command: "discover-customer-matches",
        status: "proposal_ready_for_human_review",
        operator: operator ?? process.env.USER ?? "unknown",
        gitCommit: gitCommit ?? "unknown",
        cliVersion: serviceVersion(),
        startedAt,
        completedAt: new Date().toISOString(),
        arguments: runArguments,
        proposalDigest: proposal.proposalDigest,
        sensitiveData: "encrypted staging and pseudonymous review artifacts",
        liveMergesExecuted: 0,
      });

      return withOperationStatus(
        buildSafeOutput(
          {
            command: "discover-customer-matches",
            scan_complete: true,
            proposal_generated: true,
            profile_count: proposal.profileCount,
            excluded_profile_count: proposal.excludedProfileCount,
            matching_profile_count: proposal.profileCount - proposal.excludedProfileCount,
            edge_count: proposal.edgeCount,
            proposal_digest: proposal.proposalDigest,
            audit_ready: proposal.audit.ready,
            proposal_path: resolvedProposalPath,
            report_path: resolvedReportPath,
            audit_path: resolvedAuditPath,
            run_notes_path: runNotesPath,
            no_live_merges: true,
          },
          {
            record_counts: scan.recordCounts,
            confidence_counts: confidenceCounts,
            rule_counts: proposal.ruleCounts,
            audit_shortfalls: proposal.audit.shortfalls,
          },
        ),
        true,
        0,
      );
      });
    },
    "Scan all Gorgias evidence and write a non-executable customer match review proposal",
    { sideEffect: "read", operationResultExit: true },
  ),

  "merge-customers": createCommand(
    z.object({
      manifest: z.string().min(1).describe("Path to approved merge manifest"),
      batch: z.string().min(1).describe("Approved batch ID to execute"),
      execute: boolDefaultFalse().describe("Actually perform approved merges"),
      maxFailures: intDefault(1, 1, 100).describe("Halt after this many merge failures"),
      interMergeDelayMs: intDefault(350, 0, 10000).describe("Delay between merge writes"),
      statusPath: z.string().optional().describe("Optional path for persisted per-pair merge status"),
      integrationMode: z.enum(["shadow", "enforce"]).default("shadow").describe(
        "shadow reports deep integration differences; enforce is mandatory for live writes",
      ),
      readbackAttempts: intDefault(3, 1, 10).describe("Fresh post-merge verification attempts"),
      readbackDelayMs: intDefault(500, 0, 10000).describe("Delay between post-merge verification attempts"),
    }),
    async (args, client: GorgiasClient, globals) => {
      const {
        manifest: manifestPath,
        batch,
        execute,
        maxFailures,
        interMergeDelayMs,
        statusPath,
        integrationMode: requestedIntegrationMode,
        readbackAttempts: requestedReadbackAttempts,
        readbackDelayMs: requestedReadbackDelayMs,
      } = args as {
        manifest: string;
        batch: string;
        execute: boolean;
        maxFailures: number;
        interMergeDelayMs: number;
        statusPath?: string;
        integrationMode?: "shadow" | "enforce";
        readbackAttempts?: number;
        readbackDelayMs?: number;
      };
      const integrationMode = requestedIntegrationMode ?? "shadow";
      const readbackAttempts = requestedReadbackAttempts ?? 3;
      const readbackDelayMs = requestedReadbackDelayMs ?? 500;
      if (execute && globals.confirm !== true) {
        throw new Error("merge-customers requires --confirm when --execute true");
      }
      if (execute && integrationMode !== "enforce") {
        throw new Error("merge-customers live execution requires --integration-mode enforce");
      }

      const manifest = readMergeManifestV1(manifestPath);
      const batchPairs = manifest.pairs.filter((pair) => pair.batch_id === batch);
      if (batchPairs.length === 0) {
        throw new Error(`merge manifest has no pairs for batch ${batch}`);
      }
      const ids = new Set<number>();
      batchPairs.forEach((pair) => {
        ids.add(pair.source_id);
        ids.add(pair.target_id);
      });
      const persistedStatusPath = statusPath ?? defaultMergeStatusPath(manifest, batch);
      const lock = execute
        ? acquireCustomerMergeLocks([...ids], {
          manifest_digest: manifest.immutable_manifest_digest,
          manifest_hash: sha256(readFileSync(manifestPath, "utf8")),
          batch_id: batch,
        })
        : undefined;

      try {
        if (execute) {
          const priorStatus = readMergeStatus(persistedStatusPath, manifest, batch, integrationMode);
          if (priorStatus) {
            const verifiedCount = priorStatus.results.filter((result) => result.status === "verified").length;
            if (priorStatus.status === "completed" && verifiedCount === batchPairs.length) {
              return withOperationStatus(
                buildSafeOutput(
                  {
                    command: "merge-customers",
                    ok: true,
                    dry_run: false,
                    idempotent_replay: true,
                    integration_mode: integrationMode,
                    planned_count: batchPairs.length,
                    merged_count: verifiedCount,
                    error_count: 0,
                    status_path: persistedStatusPath,
                  },
                  { results: priorStatus.results },
                ),
                true,
                0,
              );
            }
            return withOperationStatus(
              buildSafeOutput(
                {
                  command: "merge-customers",
                  ok: false,
                  dry_run: false,
                  idempotent_replay: true,
                  integration_mode: integrationMode,
                  planned_count: batchPairs.length,
                  merged_count: verifiedCount,
                  error_count: 1,
                  status_path: persistedStatusPath,
                },
                {
                  errors: [
                    `existing merge status is ${priorStatus.status}; verify and reconcile it before any retry`,
                  ],
                  results: priorStatus.results,
                },
              ),
              false,
              1,
            );
          }
        }

        disableClientCache(client);
        const latest = new Map<number, CustomerSummary>();
        const rawCustomers = new Map<number, Customer>();
        for (const id of ids) {
          const customer = await client.getCustomer(id);
          rawCustomers.set(id, customer);
          latest.set(id, summarizeCustomerForDedupe(customer));
        }
        const validation = validateApprovedMergeBatch(manifest, batch, latest);
        if (!validation.ok) {
          return withOperationStatus(
            buildSafeOutput(
              {
                command: "merge-customers",
                ok: false,
                dry_run: !execute,
                planned_count: 0,
                merged_count: 0,
                error_count: validation.errors.length,
              },
              { errors: validation.errors },
            ),
            false,
            validation.errors.length,
          );
        }

        const preflights = validation.operations.map((operation) => {
          const source = rawCustomers.get(operation.sourceId);
          const target = rawCustomers.get(operation.targetId);
          if (!source || !target) throw new Error(`pair ${operation.pairId} is missing raw preflight evidence`);
          return {
            operation,
            source,
            target,
            report: assessMergeIntegrationSafety(source, target),
          };
        });
        const integrationErrors = preflights.flatMap(({ operation, report }) =>
          report.blockers.map((blocker) => `pair ${operation.pairId}: ${blocker}`),
        );
        const preflightResults = preflights.map(({ operation, report }) => ({
          ...operation,
          status: report.ok ? "preflight_passed" : "preflight_blocked",
          integration_preflight: report,
        }));

        if (integrationErrors.length > 0 && integrationMode === "enforce") {
          if (execute || statusPath) {
            writeMergeStatus(
              persistedStatusPath,
              manifest,
              batch,
              integrationMode,
              "preflight_failed",
              preflightResults,
            );
          }
          return withOperationStatus(
            buildSafeOutput(
              {
                command: "merge-customers",
                ok: false,
                dry_run: !execute,
                integration_mode: integrationMode,
                integration_preflight_ok: false,
                would_block_count: integrationErrors.length,
                planned_count: validation.operations.length,
                merged_count: 0,
                error_count: integrationErrors.length,
                status_path: execute || statusPath ? persistedStatusPath : null,
              },
              { errors: integrationErrors, results: preflightResults },
            ),
            false,
            integrationErrors.length,
          );
        }

        if (!execute || integrationMode === "shadow") {
          if (statusPath) {
            writeMergeStatus(
              persistedStatusPath,
              manifest,
              batch,
              integrationMode,
              "shadow_complete",
              preflightResults,
            );
          }
          return withOperationStatus(
            buildSafeOutput(
              {
                command: "merge-customers",
                ok: true,
                dry_run: true,
                integration_mode: integrationMode,
                integration_preflight_ok: integrationErrors.length === 0,
                would_block_count: integrationErrors.length,
                planned_count: validation.operations.length,
                merged_count: 0,
                error_count: 0,
                status_path: statusPath ? persistedStatusPath : null,
              },
              {
                operations: validation.operations,
                results: preflightResults,
                ...(integrationErrors.length > 0 ? { warnings: integrationErrors } : {}),
              },
            ),
            true,
            0,
          );
        }

        let results: Array<Record<string, unknown>> = preflightResults;
        writeMergeStatus(persistedStatusPath, manifest, batch, integrationMode, "preflight_passed", results);
        let failures = 0;
        for (const preflight of preflights) {
          const { operation } = preflight;
          try {
            const [freshSource, freshTarget] = await Promise.all([
              client.getCustomer(operation.sourceId),
              client.getCustomer(operation.targetId),
            ]);
            const latestAtDispatch = new Map(latest);
            latestAtDispatch.set(operation.sourceId, summarizeCustomerForDedupe(freshSource));
            latestAtDispatch.set(operation.targetId, summarizeCustomerForDedupe(freshTarget));
            const dispatchValidation = validateApprovedMergeBatch(manifest, batch, latestAtDispatch);
            const freshIntegrationReport = assessMergeIntegrationSafety(freshSource, freshTarget);
            const operationStillApproved = dispatchValidation.operations.some(
              (candidate) => candidate.pairId === operation.pairId
                && candidate.sourceId === operation.sourceId
                && candidate.targetId === operation.targetId,
            );
            if (!dispatchValidation.ok || !operationStillApproved || !freshIntegrationReport.ok) {
              failures += 1;
              results = replaceMergeResult(results, operation.pairId, {
                ...operation,
                status: "revalidation_blocked",
                integration_preflight: freshIntegrationReport,
                errors: [
                  ...dispatchValidation.errors,
                  ...freshIntegrationReport.blockers.map((blocker) => `pair ${operation.pairId}: ${blocker}`),
                ],
                completed_at: new Date().toISOString(),
              });
              writeMergeStatus(persistedStatusPath, manifest, batch, integrationMode, "failed", results);
              if (failures >= maxFailures) break;
              continue;
            }
            preflight.source = freshSource;
            preflight.target = freshTarget;
            preflight.report = freshIntegrationReport;
          } catch (error) {
            failures += 1;
            results = replaceMergeResult(results, operation.pairId, {
              ...operation,
              status: "revalidation_failed",
              integration_preflight: preflight.report,
              error: sanitizeMergeError(error),
              completed_at: new Date().toISOString(),
            });
            writeMergeStatus(persistedStatusPath, manifest, batch, integrationMode, "failed", results);
            if (failures >= maxFailures) break;
            continue;
          }
          results = replaceMergeResult(results, operation.pairId, {
            ...operation,
            status: "merge_requested",
            integration_preflight: preflight.report,
            requested_at: new Date().toISOString(),
          });
          writeMergeStatus(persistedStatusPath, manifest, batch, integrationMode, "merge_requested", results);

          try {
            const mergeResult = await client.mergeCustomers({
              sourceId: operation.sourceId,
              targetId: operation.targetId,
            });
            const mergedId = typeof mergeResult === "object" && mergeResult !== null
              ? (mergeResult as { id?: unknown }).id
              : undefined;
            results = replaceMergeResult(results, operation.pairId, {
              ...operation,
              status: "merge_accepted",
              integration_preflight: preflight.report,
              returnedCustomerId: typeof mergedId === "number" ? mergedId : undefined,
              accepted_at: new Date().toISOString(),
            });
            writeMergeStatus(persistedStatusPath, manifest, batch, integrationMode, "merge_accepted", results);
          } catch (error) {
            failures += 1;
            results = replaceMergeResult(results, operation.pairId, {
              ...operation,
              status: "provider_failed",
              integration_preflight: preflight.report,
              error: sanitizeMergeError(error),
              completed_at: new Date().toISOString(),
            });
            writeMergeStatus(persistedStatusPath, manifest, batch, integrationMode, "failed", results);
            if (failures >= maxFailures) break;
            continue;
          }

          let verified = false;
          let lastReadback: Record<string, unknown> | undefined;
          for (let attempt = 1; attempt <= readbackAttempts; attempt += 1) {
            try {
              const [sourceInspection, targetAfter] = await Promise.all([
                client.inspectCustomer(operation.sourceId),
                client.getCustomer(operation.targetId),
              ]);
              const integrationReadback = verifyMergeIntegrationReadback(
                preflight.source,
                preflight.target,
                targetAfter,
              );
              lastReadback = {
                attempt,
                source_status: sourceInspection.status,
                source_http_status: sourceInspection.httpStatus,
                integration: integrationReadback,
              };
              if (sourceInspection.status === "merged_redirect" && integrationReadback.ok) {
                verified = true;
                break;
              }
            } catch (error) {
              lastReadback = { attempt, error: sanitizeMergeError(error) };
            }
            if (attempt < readbackAttempts && readbackDelayMs > 0) {
              await new Promise((resolve) => setTimeout(resolve, readbackDelayMs));
            }
          }

          if (!verified) {
            failures += 1;
            results = replaceMergeResult(results, operation.pairId, {
              ...operation,
              status: "readback_failed",
              integration_preflight: preflight.report,
              readback: lastReadback,
              completed_at: new Date().toISOString(),
            });
            writeMergeStatus(persistedStatusPath, manifest, batch, integrationMode, "readback_failed", results);
            break;
          }

          results = replaceMergeResult(results, operation.pairId, {
            ...operation,
            status: "verified",
            integration_preflight: preflight.report,
            readback: lastReadback,
            completed_at: new Date().toISOString(),
          });
          writeMergeStatus(persistedStatusPath, manifest, batch, integrationMode, "running", results);
          if (interMergeDelayMs > 0) {
            await new Promise((resolve) => setTimeout(resolve, interMergeDelayMs));
          }
        }
        writeMergeStatus(
          persistedStatusPath,
          manifest,
          batch,
          integrationMode,
          failures > 0 ? "failed" : "completed",
          results,
        );

        return withOperationStatus(
          buildSafeOutput(
            {
              command: "merge-customers",
              ok: failures === 0,
              dry_run: false,
              integration_mode: integrationMode,
              planned_count: validation.operations.length,
              merged_count: results.filter((result) => persistedPairStatus(result) === "verified").length,
              error_count: failures,
              status_path: persistedStatusPath,
            },
            { results },
          ),
          failures === 0,
          failures,
        );
      } finally {
        releaseCustomerMergeLocks(lock);
      }
    },
    "Merge approved Gorgias customer pairs from a manifest",
    {
      sideEffect: "destructive",
      requiresConfirmation: true,
      dryRunSupported: true,
      requiresSafeOutput: true,
      operationResultExit: true,
    },
  ),

  "verify-merge-batch": createCommand(
    z.object({
      manifest: z.string().min(1).describe("Path to merge manifest"),
      batch: z.string().min(1).describe("Batch ID to verify"),
    }),
    async (args, client: GorgiasClient) => {
      const { manifest: manifestPath, batch } = args as { manifest: string; batch: string };
      const manifest = readMergeManifestV1(manifestPath);
      const pairs = manifest.pairs.filter((pair) => pair.batch_id === batch);
      const results = [];
      for (const pair of pairs) {
        const [source, target] = await Promise.all([
          client.inspectCustomer(pair.source_id),
          client.inspectCustomer(pair.target_id),
        ]);
        results.push({
          pair_id: pair.id,
          source: sanitizeCustomerInspection(source),
          target: sanitizeCustomerInspection(target),
        });
      }
      return buildSafeOutput(
        {
          command: "verify-merge-batch",
          verified_count: results.length,
        },
        { results },
      );
    },
    "Verify post-merge customer outcomes from a manifest batch",
    { sideEffect: "read" },
  ),

  ...cacheCommands<GorgiasClient>(),
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runCli(commands, GorgiasClient, {
    programName: "gorgias-cli",
    description: "Gorgias support ticket management",
  });
}

