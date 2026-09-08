import { createHash } from "node:crypto";

export type MergePairStatus = "eligible" | "review" | "blocked";
export type MergeDecision = "approved" | "rejected" | "pending";

export interface CustomerSummary {
  id: number;
  created_datetime?: string;
  updated_datetime?: string;
  email_hashes: string[];
  email_masked: string[];
  phone_hashes: string[];
  phone_masked: string[];
  name_hash?: string;
  name_masked?: string;
  channel_count: number;
  integration_names: string[];
  external_id_hashes: string[];
  external_id_count: number;
  shopify_customer_id_hashes: string[];
  shopify_customer_id_count: number;
  shopify_order_count: number;
  has_shopify_orders: boolean;
  evidence_hash: string;
}

export interface MergeManifestPair {
  id: string;
  source_id: number;
  target_id: number;
  status: MergePairStatus;
  requires_approval: boolean;
  reviewer_decision: MergeDecision;
  batch_id?: string;
  pair_digest: string;
  source_evidence_hash: string;
  target_evidence_hash: string;
  evidence: {
    match_type: "email" | "phone" | "name";
    identifier_hash: string;
    masked_value: string;
  };
  recommendation: {
    reason: string;
  };
  block_reasons: string[];
}

export interface MergeManifestBatch {
  id: string;
  approved: boolean;
  approved_pair_count?: number;
  approved_pair_digests?: string[];
  approved_at?: string;
  approved_by?: string;
}

export interface MergeManifest {
  schema: "gorgias-customer-merge-manifest.v1";
  generated_at: string;
  exporter_version: string;
  immutable_manifest_digest: string;
  canary_completed: boolean;
  batches: MergeManifestBatch[];
  pairs: MergeManifestPair[];
}

export interface BuildMergeManifestOptions {
  customers: unknown[];
  batchId: string;
  generatedAt: string;
  exporterVersion: string;
}

export interface BuildMergeManifestFromSummariesOptions {
  summaries: CustomerSummary[];
  batchId: string;
  generatedAt: string;
  exporterVersion: string;
}

export interface MergeOperation {
  pairId: string;
  sourceId: number;
  targetId: number;
}

export interface BatchValidationResult {
  ok: boolean;
  errors: string[];
  operations: MergeOperation[];
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableStringify(entryValue)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hashIdentifier(value: string): string {
  return sha256(`gorgias-customer-dedupe:v1:${value}`);
}

function normaliseEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalised = value.trim().toLowerCase();
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalised) ? normalised : null;
}

function normalisePhone(value: unknown): string | null {
  if (typeof value !== "string") return null;
  let normalised = value.trim().replace(/[^\d+]/g, "");
  if (normalised.startsWith("00")) normalised = `+${normalised.slice(2)}`;
  if (normalised.startsWith("+")) {
    const digits = normalised.slice(1).replace(/\D/g, "");
    return digits.length >= 7 ? `+${digits}` : null;
  }
  const digits = normalised.replace(/\D/g, "");
  return digits.length >= 7 ? digits : null;
}

function normaliseName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalised = value.trim().toLowerCase().replace(/\s+/g, " ");
  return normalised.length >= 3 ? normalised : null;
}

function maskEmail(value: string): string {
  const [local, domain] = value.split("@");
  const domainParts = domain.split(".");
  const domainLabel = domainParts[0] ?? "";
  const suffix = domainParts.slice(1).join(".");
  return `${local.slice(0, 1)}***@${domainLabel.slice(0, 1)}***${suffix ? `.${suffix}` : ""}`;
}

function maskPhone(value: string): string {
  const tail = value.replace(/\D/g, "").slice(-4);
  return tail ? `***${tail}` : "***";
}

function maskName(value: string): string {
  return value
    .split(" ")
    .filter(Boolean)
    .map((part) => `${part.slice(0, 1).toUpperCase()}***`)
    .join(" ");
}

function readString(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (value && typeof value === "object") {
    const nestedValue = (value as { value?: unknown }).value;
    if (typeof nestedValue === "string") return nestedValue;
    if (typeof nestedValue === "number" && Number.isFinite(nestedValue)) return String(nestedValue);
  }
  return undefined;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function pushUnique<T>(items: T[], value: T | undefined | null): void {
  if (value === undefined || value === null) return;
  if (!items.includes(value)) items.push(value);
}

function walk(value: unknown, visitor: (key: string, value: unknown) => void, key = ""): void {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) walk(item, visitor, key);
    return;
  }
  for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>)) {
    visitor(childKey, childValue);
    walk(childValue, visitor, childKey);
  }
}

function extractIntegrationNames(record: Record<string, unknown>): string[] {
  const names: string[] = [];
  for (const key of ["integrations", "integration_data", "data"]) {
    const value = record[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        const itemRecord = asRecord(item);
        const name = readString(itemRecord.name) ?? readString(itemRecord.type) ?? readString(itemRecord.provider);
        if (name) pushUnique(names, name.toLowerCase());
      }
    } else if (value && typeof value === "object") {
      for (const integrationName of Object.keys(value as Record<string, unknown>)) {
        pushUnique(names, integrationName.toLowerCase());
      }
    }
  }
  return names.sort();
}

function extractExternalIds(record: Record<string, unknown>): string[] {
  const ids: string[] = [];
  walk(record, (key, value) => {
    if (/external_?id$/i.test(key) || /^external_?id$/i.test(key)) {
      const text = readString(value);
      if (text) pushUnique(ids, text);
    }
  });
  return ids.sort();
}

function extractShopifyCustomerIds(record: Record<string, unknown>): string[] {
  const ids: string[] = [];
  const collectShopifyPayload = (value: unknown): void => {
    const payload = asRecord(value);
    if (!payload) return;
    walk(payload, (key, childValue) => {
      const text = readString(childValue);
      if (text && (/shopify/i.test(key) && /customer/i.test(key) && /id/i.test(key))) {
        pushUnique(ids, text);
      }
      if (text && /gid:\/\/shopify\/Customer\//i.test(text)) pushUnique(ids, text);
      if (/^customer$/i.test(key)) {
        const customer = asRecord(childValue);
        pushUnique(ids, readString(customer.id));
        pushUnique(ids, readString(customer.customer_id));
      }
    });
  };
  const isShopifyEntry = (key: string, value: unknown): boolean => {
    if (/shopify/i.test(key)) return true;
    const entry = asRecord(value);
    if (!entry) return false;
    return ["name", "type", "provider", "__integration_type__"]
      .map((field) => readString(entry[field]))
      .some((identity) => Boolean(identity && /shopify/i.test(identity)));
  };

  for (const containerKey of ["integrations", "integration_data", "data"]) {
    const container = record[containerKey];
    if (Array.isArray(container)) {
      for (const entry of container) {
        if (isShopifyEntry("", entry)) collectShopifyPayload(entry);
      }
      continue;
    }
    const containerRecord = asRecord(container);
    if (!containerRecord) continue;
    for (const [integrationKey, entry] of Object.entries(containerRecord)) {
      if (isShopifyEntry(integrationKey, entry)) collectShopifyPayload(entry);
    }
  }

  walk(record, (key, value) => {
    const text = readString(value);
    if (!text) return;
    if (/shopify/i.test(key) && /customer/i.test(key) && /id/i.test(key)) {
      pushUnique(ids, text);
    }
    if (/gid:\/\/shopify\/Customer\//i.test(text)) {
      pushUnique(ids, text);
    }
  });
  return ids.sort();
}

function extractShopifyOrderCount(record: Record<string, unknown>): number {
  let count = 0;
  walk(record, (key, value) => {
    if (/orders?_count$/i.test(key) && typeof value === "number") count += value;
    if (/orders?$/i.test(key) && Array.isArray(value)) count += value.length;
  });
  return count;
}

export function computeCustomerEvidenceHash(summary: Omit<CustomerSummary, "evidence_hash"> | CustomerSummary): string {
  return sha256(stableStringify({
    id: summary.id,
    created_datetime: summary.created_datetime,
    updated_datetime: summary.updated_datetime,
    email_hashes: summary.email_hashes,
    phone_hashes: summary.phone_hashes,
    name_hash: summary.name_hash,
    integration_names: summary.integration_names,
    external_id_hashes: summary.external_id_hashes,
    external_id_count: summary.external_id_count,
    shopify_customer_id_hashes: summary.shopify_customer_id_hashes,
    shopify_customer_id_count: summary.shopify_customer_id_count,
    shopify_order_count: summary.shopify_order_count,
  }));
}

export function summarizeCustomerForDedupe(customer: unknown): CustomerSummary {
  const record = asRecord(customer);
  const id = Number(record.id);
  if (!Number.isInteger(id) || id < 1) {
    throw new Error("customer record is missing a numeric id");
  }

  const emailValues: Array<{ hash: string; masked: string }> = [];
  const phoneValues: Array<{ hash: string; masked: string }> = [];

  const primaryEmail = normaliseEmail(record.email);
  if (primaryEmail) emailValues.push({ hash: hashIdentifier(`email:${primaryEmail}`), masked: maskEmail(primaryEmail) });

  const channels = Array.isArray(record.channels) ? record.channels : [];
  for (const channel of channels) {
    const channelRecord = asRecord(channel);
    const address = readString(channelRecord.address) ?? readString(channelRecord.email) ?? readString(channelRecord.phone);
    const type = (readString(channelRecord.type) ?? "").toLowerCase();
    const email = normaliseEmail(address);
    if (email) emailValues.push({ hash: hashIdentifier(`email:${email}`), masked: maskEmail(email) });
    const phone = type === "phone" || type === "sms" ? normalisePhone(address) : normalisePhone(readString(channelRecord.phone));
    if (phone) phoneValues.push({ hash: hashIdentifier(`phone:${phone}`), masked: maskPhone(phone) });
  }

  const name =
    normaliseName(record.name) ??
    normaliseName([readString(record.firstname), readString(record.lastname)].filter(Boolean).join(" "));

  const dedupeByHash = <T extends { hash: string }>(items: T[]): T[] => {
    const seen = new Set<string>();
    return items.filter((item) => {
      if (seen.has(item.hash)) return false;
      seen.add(item.hash);
      return true;
    });
  };

  const emailDedupe = dedupeByHash(emailValues).sort((a, b) => a.hash.localeCompare(b.hash));
  const phoneDedupe = dedupeByHash(phoneValues).sort((a, b) => a.hash.localeCompare(b.hash));
  const externalIds = extractExternalIds(record);
  const shopifyCustomerIds = extractShopifyCustomerIds(record);
  const summary: Omit<CustomerSummary, "evidence_hash"> = {
    id,
    created_datetime: readString(record.created_datetime),
    updated_datetime: readString(record.updated_datetime),
    email_hashes: emailDedupe.map((item) => item.hash),
    email_masked: emailDedupe.map((item) => item.masked),
    phone_hashes: phoneDedupe.map((item) => item.hash),
    phone_masked: phoneDedupe.map((item) => item.masked),
    name_hash: name ? hashIdentifier(`name:${name}`) : undefined,
    name_masked: name ? maskName(name) : undefined,
    channel_count: channels.length,
    integration_names: extractIntegrationNames(record),
    external_id_hashes: externalIds.map((value) => hashIdentifier(`external_id:${value}`)).sort(),
    external_id_count: externalIds.length,
    shopify_customer_id_hashes: shopifyCustomerIds.map((value) => hashIdentifier(`shopify_customer_id:${value}`)).sort(),
    shopify_customer_id_count: shopifyCustomerIds.length,
    shopify_order_count: extractShopifyOrderCount(record),
    has_shopify_orders: extractShopifyOrderCount(record) > 0,
  };
  return { ...summary, evidence_hash: computeCustomerEvidenceHash(summary) };
}

function profileStrength(summary: CustomerSummary): number {
  let score = 0;
  if (summary.has_shopify_orders) score += 120;
  if (summary.shopify_customer_id_count > 0) score += 80;
  score += summary.integration_names.length * 10;
  score += summary.channel_count * 3;
  score += summary.email_hashes.length * 2;
  score += summary.phone_hashes.length * 2;
  return score;
}

function chooseTarget(group: CustomerSummary[]): { target?: CustomerSummary; ambiguous: boolean } {
  const ranked = [...group].sort((a, b) => {
    const scoreDelta = profileStrength(b) - profileStrength(a);
    if (scoreDelta !== 0) return scoreDelta;
    const aCreated = a.created_datetime ? Date.parse(a.created_datetime) : Number.POSITIVE_INFINITY;
    const bCreated = b.created_datetime ? Date.parse(b.created_datetime) : Number.POSITIVE_INFINITY;
    if (aCreated !== bCreated) return aCreated - bCreated;
    return a.id - b.id;
  });
  const top = ranked[0];
  const second = ranked[1];
  return { target: top, ambiguous: !!second && profileStrength(top) === profileStrength(second) && top.created_datetime === second.created_datetime };
}

function intersection(a: string[], b: string[]): string[] {
  const bSet = new Set(b);
  return a.filter((value) => bSet.has(value));
}

function disjointNonEmpty(a: string[], b: string[]): boolean {
  return a.length > 0 && b.length > 0 && intersection(a, b).length === 0;
}

function pairDigest(pair: Omit<MergeManifestPair, "pair_digest">): string {
  return sha256(stableStringify({
    source_id: pair.source_id,
    target_id: pair.target_id,
    status: pair.status,
    source_evidence_hash: pair.source_evidence_hash,
    target_evidence_hash: pair.target_evidence_hash,
    evidence: pair.evidence,
    block_reasons: pair.block_reasons,
  }));
}

function buildPair(
  matchType: "email" | "phone" | "name",
  identifierHash: string,
  maskedValue: string,
  group: CustomerSummary[],
): MergeManifestPair[] {
  const { target, ambiguous } = chooseTarget(group);
  if (!target) return [];
  return group
    .filter((summary) => summary.id !== target.id)
    .map((source) => {
      const blockReasons: string[] = [];
      if (matchType === "name") blockReasons.push("name_only_match_not_mergeable");
      if (ambiguous) blockReasons.push("ambiguous_target_selection");
      if (disjointNonEmpty(source.shopify_customer_id_hashes, target.shopify_customer_id_hashes)) {
        blockReasons.push("differing_shopify_customer_ids");
      }
      if (source.has_shopify_orders && target.has_shopify_orders) {
        blockReasons.push("split_shopify_order_ownership");
      }
      if (disjointNonEmpty(source.external_id_hashes, target.external_id_hashes)) {
        blockReasons.push("conflicting_external_ids");
      }
      const status: MergePairStatus = blockReasons.length > 0 ? "blocked" : "eligible";
      const withoutDigest: Omit<MergeManifestPair, "pair_digest"> = {
        id: sha256(`${source.id}:${target.id}:${identifierHash}`).slice(0, 16),
        source_id: source.id,
        target_id: target.id,
        status,
        requires_approval: true,
        reviewer_decision: "pending",
        source_evidence_hash: source.evidence_hash,
        target_evidence_hash: target.evidence_hash,
        evidence: {
          match_type: matchType,
          identifier_hash: identifierHash,
          masked_value: maskedValue,
        },
        recommendation: {
          reason: status === "eligible" ? "target has stronger or older identity evidence" : "blocked until data conflicts are resolved",
        },
        block_reasons: blockReasons.sort(),
      };
      return { ...withoutDigest, pair_digest: pairDigest(withoutDigest) };
    });
}

function deriveMergePairs(summaries: CustomerSummary[]): MergeManifestPair[] {
  const byKey = new Map<string, { type: "email" | "phone" | "name"; masked: string; customers: CustomerSummary[] }>();
  const add = (key: string, type: "email" | "phone" | "name", masked: string, summary: CustomerSummary) => {
    const existing = byKey.get(key) ?? { type, masked, customers: [] };
    existing.customers.push(summary);
    byKey.set(key, existing);
  };

  for (const summary of [...summaries].sort((a, b) => a.id - b.id)) {
    summary.email_hashes.forEach((hash, index) => add(`email:${hash}`, "email", summary.email_masked[index] ?? "***", summary));
    summary.phone_hashes.forEach((hash, index) => add(`phone:${hash}`, "phone", summary.phone_masked[index] ?? "***", summary));
    if (summary.name_hash && summary.email_hashes.length === 0 && summary.phone_hashes.length === 0) {
      add(`name:${summary.name_hash}`, "name", summary.name_masked ?? "***", summary);
    }
  }

  const pairs: MergeManifestPair[] = [];
  const seenPairs = new Set<string>();
  for (const [key, group] of [...byKey.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    if (group.customers.length < 2) continue;
    const identifierHash = key.slice(key.indexOf(":") + 1);
    for (const pair of buildPair(group.type, identifierHash, group.masked, group.customers)) {
      const pairKey = `${pair.source_id}:${pair.target_id}`;
      if (seenPairs.has(pairKey)) continue;
      seenPairs.add(pairKey);
      pairs.push(pair);
    }
  }

  return pairs.sort((a, b) => a.target_id - b.target_id || a.source_id - b.source_id || a.id.localeCompare(b.id));
}

export function computeImmutableManifestDigest(manifest: Pick<MergeManifest, "schema" | "generated_at" | "exporter_version" | "pairs">): string {
  return sha256(stableStringify({
    schema: manifest.schema,
    generated_at: manifest.generated_at,
    exporter_version: manifest.exporter_version,
    pairs: manifest.pairs.map((pair) => ({
      id: pair.id,
      source_id: pair.source_id,
      target_id: pair.target_id,
      status: pair.status,
      source_evidence_hash: pair.source_evidence_hash,
      target_evidence_hash: pair.target_evidence_hash,
      evidence: pair.evidence,
      block_reasons: pair.block_reasons,
      pair_digest: pair.pair_digest,
    })),
  }));
}

export function buildMergeManifestFromSummaries(options: BuildMergeManifestFromSummariesOptions): MergeManifest {
  const pairs = deriveMergePairs(options.summaries);
  for (const pair of pairs) {
    pair.batch_id = options.batchId;
  }
  const manifest: MergeManifest = {
    schema: "gorgias-customer-merge-manifest.v1",
    generated_at: options.generatedAt,
    exporter_version: options.exporterVersion,
    immutable_manifest_digest: "",
    canary_completed: false,
    batches: [{ id: options.batchId, approved: false, approved_pair_count: 0, approved_pair_digests: [] }],
    pairs,
  };
  manifest.immutable_manifest_digest = computeImmutableManifestDigest(manifest);
  return manifest;
}

export function buildMergeManifest(options: BuildMergeManifestOptions): MergeManifest {
  return buildMergeManifestFromSummaries({
    summaries: options.customers.map(summarizeCustomerForDedupe),
    batchId: options.batchId,
    generatedAt: options.generatedAt,
    exporterVersion: options.exporterVersion,
  });
}

function recomputePairDigest(pair: MergeManifestPair): string {
  const { pair_digest: _pairDigest, ...withoutDigest } = pair;
  return pairDigest(withoutDigest);
}

export function validateApprovedMergeBatch(
  manifest: MergeManifest,
  batchId: string,
  latestCustomers: Map<number, CustomerSummary>,
): BatchValidationResult {
  const errors: string[] = [];
  const operations: MergeOperation[] = [];
  if (manifest.immutable_manifest_digest !== computeImmutableManifestDigest(manifest)) {
    errors.push("immutable manifest digest mismatch");
  }
  const batch = manifest.batches.find((entry) => entry.id === batchId);
  if (!batch) errors.push(`batch ${batchId} not found`);
  if (batch && !batch.approved) errors.push(`batch ${batchId} is not approved`);

  const pairs = manifest.pairs.filter((pair) => pair.batch_id === batchId);
  if (pairs.length === 0) {
    errors.push(`batch ${batchId} has no assigned pairs`);
  }
  if (batch?.approved) {
    const approvedDigests = [...(batch.approved_pair_digests ?? [])].sort();
    const pairDigests = pairs.map((pair) => pair.pair_digest).sort();
    if (batch.approved_pair_count !== pairs.length) {
      errors.push(`batch ${batchId} approved pair count mismatch`);
    }
    if (
      approvedDigests.length !== pairDigests.length ||
      approvedDigests.some((digest, index) => digest !== pairDigests[index])
    ) {
      errors.push(`batch ${batchId} approved pair digests mismatch`);
    }
  }

  const sourceIds = new Map<number, number>();
  const targetIds = new Set<number>();
  for (const pair of pairs) {
    sourceIds.set(pair.source_id, (sourceIds.get(pair.source_id) ?? 0) + 1);
    targetIds.add(pair.target_id);
  }
  for (const [sourceId, count] of sourceIds.entries()) {
    if (count > 1) {
      errors.push(`customer ${sourceId} appears as source in multiple batch pairs`);
    }
  }
  const targetCounts = new Map<number, number>();
  for (const pair of pairs) {
    targetCounts.set(pair.target_id, (targetCounts.get(pair.target_id) ?? 0) + 1);
  }
  for (const [targetId, count] of targetCounts.entries()) {
    if (count > 1) {
      errors.push(`customer ${targetId} appears as target in multiple batch pairs`);
    }
  }
  for (const targetId of targetIds) {
    if (sourceIds.has(targetId)) {
      errors.push(`customer ${targetId} used as both source and target in batch ${batchId}`);
    }
  }

  if (pairs.length > 1 && manifest.canary_completed !== true) {
    errors.push("batches larger than 1 pair require canary_completed=true");
  }

  const batchCustomerIds = [...new Set(pairs.flatMap((pair) => [pair.source_id, pair.target_id]))];
  const currentPairs = deriveMergePairs(
    batchCustomerIds
      .map((id) => latestCustomers.get(id))
      .filter((summary): summary is CustomerSummary => summary !== undefined),
  );

  for (const pair of pairs) {
    if (pair.pair_digest !== recomputePairDigest(pair)) {
      errors.push(`pair ${pair.id} digest mismatch`);
      continue;
    }
    if (pair.status !== "eligible") {
      errors.push(`pair ${pair.id} is ${pair.status}, not eligible`);
      continue;
    }
    if (pair.reviewer_decision !== "approved") {
      errors.push(`pair ${pair.id} is not reviewer-approved`);
      continue;
    }
    const source = latestCustomers.get(pair.source_id);
    const target = latestCustomers.get(pair.target_id);
    if (!source) {
      errors.push(`pair ${pair.id} missing latest source evidence`);
      continue;
    }
    if (!target) {
      errors.push(`pair ${pair.id} missing latest target evidence`);
      continue;
    }
    if (source.evidence_hash !== pair.source_evidence_hash) {
      errors.push(`pair ${pair.id} stale source evidence`);
      continue;
    }
    if (target.evidence_hash !== pair.target_evidence_hash) {
      errors.push(`pair ${pair.id} stale target evidence`);
      continue;
    }
    const currentPair = currentPairs.find(
      (candidate) => candidate.source_id === pair.source_id && candidate.target_id === pair.target_id,
    );
    if (!currentPair) {
      errors.push(`pair ${pair.id} source-to-target direction is not derivable from current dedupe rules`);
      continue;
    }
    if (currentPair.status !== pair.status) {
      errors.push(`pair ${pair.id} current eligibility status mismatch`);
      continue;
    }
    if (stableStringify(currentPair.evidence) !== stableStringify(pair.evidence)) {
      errors.push(`pair ${pair.id} current match evidence mismatch`);
      continue;
    }
    if (stableStringify(currentPair.block_reasons) !== stableStringify(pair.block_reasons)) {
      errors.push(`pair ${pair.id} current block state mismatch`);
      continue;
    }
    operations.push({ pairId: pair.id, sourceId: pair.source_id, targetId: pair.target_id });
  }

  return { ok: errors.length === 0, errors, operations: errors.length === 0 ? operations : [] };
}
