import { createHash } from "node:crypto";

const SNAPSHOT_SCHEMA = "gorgias-customer-integration-snapshot.v1" as const;
const MAX_INTEGRATION_DEPTH = 32;
const MAX_INTEGRATION_NODES = 50_000;

type CanonicalScalar = string | number | boolean | null;
type CanonicalValue = CanonicalScalar | CanonicalValue[] | { [key: string]: CanonicalValue };

export interface SanitizedIntegrationEntry {
  integration_key_hash: string;
  value_digest: string;
  meaningful_leaf_count: number;
}

export interface SanitizedCustomerIntegrationSnapshot {
  schema: typeof SNAPSHOT_SCHEMA;
  customer_id: number;
  customer_updated_datetime?: string;
  integration_count: number;
  integrations: readonly Readonly<SanitizedIntegrationEntry>[];
  snapshot_digest: string;
}

export interface SanitizedIntegrationDiff {
  integration_key_hash: string;
  source_digest: string;
  target_digest: string;
  source_only_count: number;
  target_only_count: number;
  source_only_path_hashes: readonly string[];
  target_only_path_hashes: readonly string[];
  source_data_loss_risk: boolean;
}

export interface MergeIntegrationPreflight {
  ok: boolean;
  source_snapshot: Readonly<SanitizedCustomerIntegrationSnapshot>;
  target_snapshot: Readonly<SanitizedCustomerIntegrationSnapshot>;
  shared_integration_count: number;
  source_only_integration_count: number;
  target_only_integration_count: number;
  risky_shared_integration_count: number;
  risky_source_only_integration_count: number;
  diffs: readonly Readonly<SanitizedIntegrationDiff>[];
  blockers: readonly string[];
}

export interface MergeIntegrationReadback {
  ok: boolean;
  source_preserved: boolean;
  target_preserved: boolean;
  missing_source_value_count: number;
  missing_target_value_count: number;
  missing_path_hashes: readonly string[];
}

interface CanonicalizationBudget {
  nodes: number;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stableStringify(value: CanonicalValue): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value as Readonly<T>;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function canonicalize(value: unknown, budget: CanonicalizationBudget, depth = 0): CanonicalValue | undefined {
  budget.nodes += 1;
  if (budget.nodes > MAX_INTEGRATION_NODES) {
    throw new Error(`integration payload exceeds ${MAX_INTEGRATION_NODES} nodes`);
  }
  if (depth > MAX_INTEGRATION_DEPTH) {
    throw new Error(`integration payload exceeds ${MAX_INTEGRATION_DEPTH} levels`);
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (Array.isArray(value)) {
    return value
      .map((entry) => canonicalize(entry, budget, depth + 1))
      .filter((entry): entry is CanonicalValue => entry !== undefined)
      .sort((left, right) => stableStringify(left).localeCompare(stableStringify(right)));
  }
  const record = asRecord(value);
  if (!record) return undefined;
  const entries = Object.entries(record)
    .sort(([left], [right]) => left.localeCompare(right))
    .flatMap(([key, entry]) => {
      const canonical = canonicalize(entry, budget, depth + 1);
      return canonical === undefined ? [] : [[key, canonical] as const];
    });
  return Object.fromEntries(entries);
}

function canonicalizeRoot(value: unknown): CanonicalValue {
  return canonicalize(value, { nodes: 0 }) ?? null;
}

function isMeaningful(value: CanonicalValue): boolean {
  if (value === null || value === "") return false;
  if (Array.isArray(value)) return value.some(isMeaningful);
  if (typeof value === "object") return Object.values(value).some(isMeaningful);
  return true;
}

function meaningfulLeafCount(value: CanonicalValue): number {
  if (!isMeaningful(value)) return 0;
  if (Array.isArray(value)) {
    return value.reduce<number>((count, child) => count + meaningfulLeafCount(child), 0);
  }
  if (value !== null && typeof value === "object") {
    return Object.values(value).reduce<number>((count, child) => count + meaningfulLeafCount(child), 0);
  }
  return 1;
}

function integrationMap(customer: unknown): Map<string, CanonicalValue> {
  const customerRecord = asRecord(customer);
  if (!customerRecord) throw new Error("customer merge preflight requires a customer object");
  const values = new Map<string, CanonicalValue[]>();
  const dataRecord = asRecord(customerRecord.data);
  const nestedDataContainers = dataRecord
    ? [dataRecord.integrations, dataRecord.integration_data].filter(
      (value) => value !== undefined && value !== null,
    )
    : [];
  const containers = [
    customerRecord.integrations,
    customerRecord.integration_data,
    ...nestedDataContainers,
    ...(nestedDataContainers.length === 0 && customerRecord.data !== undefined ? [customerRecord.data] : []),
  ].filter((container) => container !== undefined && container !== null);

  const pushValue = (key: string, rawValue: unknown) => {
    const current = values.get(key) ?? [];
    values.set(key, [...current, canonicalizeRoot(rawValue)]);
  };

  for (const container of containers) {
    if (Array.isArray(container)) {
      for (const rawValue of container) {
        const entry = asRecord(rawValue);
        const stableKey = entry
          ? ["integration_id", "name", "type", "provider", "__integration_type__"]
            .map((field) => entry[field])
            .find((value) => typeof value === "string" || (typeof value === "number" && Number.isFinite(value)))
          : undefined;
        const key = stableKey === undefined
          ? "array:unkeyed"
          : `array:${String(stableKey).trim().toLowerCase()}`;
        pushValue(key, rawValue);
      }
      continue;
    }
    const record = asRecord(container);
    if (!record) {
      pushValue("scalar:unkeyed", container);
      continue;
    }
    for (const [key, rawValue] of Object.entries(record)) {
      pushValue(key, rawValue);
    }
  }

  return new Map(
    [...values.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entries]) => [
        key,
        entries.length === 1
          ? entries[0]
          : [...entries].sort((left, right) => stableStringify(left).localeCompare(stableStringify(right))),
      ]),
  );
}

function customerId(customer: unknown): number {
  const id = Number(asRecord(customer)?.id);
  if (!Number.isInteger(id) || id < 1) throw new Error("customer merge preflight requires a numeric customer ID");
  return id;
}

function customerUpdatedDatetime(customer: unknown): string | undefined {
  const value = asRecord(customer)?.updated_datetime;
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function sanitizedSnapshotFromMap(
  customer: unknown,
  integrations: Map<string, CanonicalValue>,
): Readonly<SanitizedCustomerIntegrationSnapshot> {
  const entries = [...integrations.entries()].map(([key, value]) => ({
    integration_key_hash: sha256(`gorgias-integration-key:v1:${key}`),
    value_digest: sha256(stableStringify(value)),
    meaningful_leaf_count: meaningfulLeafCount(value),
  }));
  const withoutDigest = {
    schema: SNAPSHOT_SCHEMA,
    customer_id: customerId(customer),
    customer_updated_datetime: customerUpdatedDatetime(customer),
    integration_count: entries.length,
    integrations: entries,
  };
  return deepFreeze({
    ...withoutDigest,
    snapshot_digest: sha256(JSON.stringify(withoutDigest)),
  });
}

function sourceOnlyPaths(
  source: CanonicalValue,
  target: CanonicalValue | undefined,
  path = "$",
): string[] {
  if (!isMeaningful(source)) return [];
  if (target === undefined || !isMeaningful(target)) return [path];
  if (Array.isArray(source)) {
    if (!Array.isArray(target)) return [path];
    const remainingTargets = [...target];
    const missing: string[] = [];
    source.forEach((sourceEntry, index) => {
      if (!isMeaningful(sourceEntry)) return;
      const matchIndex = remainingTargets.findIndex(
        (targetEntry) => sourceOnlyPaths(sourceEntry, targetEntry).length === 0,
      );
      if (matchIndex < 0) {
        missing.push(`${path}[]:${index}`);
      } else {
        remainingTargets.splice(matchIndex, 1);
      }
    });
    return missing;
  }
  if (source !== null && typeof source === "object") {
    if (target === null || Array.isArray(target) || typeof target !== "object") return [path];
    return Object.entries(source).flatMap(([key, sourceEntry]) =>
      sourceOnlyPaths(sourceEntry, target[key], `${path}.${key}`),
    );
  }
  return Object.is(source, target) ? [] : [path];
}

function hashedPaths(integrationKey: string, paths: string[]): string[] {
  return [...new Set(paths.map((path) => sha256(`gorgias-integration-path:v1:${integrationKey}:${path}`).slice(0, 24)))].sort();
}

export function assessMergeIntegrationSafety(
  sourceCustomer: unknown,
  targetCustomer: unknown,
): Readonly<MergeIntegrationPreflight> {
  const sourceIntegrations = integrationMap(sourceCustomer);
  const targetIntegrations = integrationMap(targetCustomer);
  const sharedKeys = [...sourceIntegrations.keys()].filter((key) => targetIntegrations.has(key)).sort();
  const diffs = sharedKeys.flatMap((key) => {
    const source = sourceIntegrations.get(key);
    const target = targetIntegrations.get(key);
    if (source === undefined || target === undefined) return [];
    const sourceOnly = sourceOnlyPaths(source, target);
    const targetOnly = sourceOnlyPaths(target, source);
    if (sourceOnly.length === 0 && targetOnly.length === 0) return [];
    return [{
      integration_key_hash: sha256(`gorgias-integration-key:v1:${key}`),
      source_digest: sha256(stableStringify(source)),
      target_digest: sha256(stableStringify(target)),
      source_only_count: sourceOnly.length,
      target_only_count: targetOnly.length,
      source_only_path_hashes: hashedPaths(key, sourceOnly),
      target_only_path_hashes: hashedPaths(key, targetOnly),
      source_data_loss_risk: sourceOnly.length > 0,
    }];
  });
  const risky = diffs.filter((diff) => diff.source_data_loss_risk);
  const sourceOnlyKeys = [...sourceIntegrations.keys()]
    .filter((key) => !targetIntegrations.has(key))
    .sort();
  const riskySourceOnly = sourceOnlyKeys.filter((key) => {
    const value = sourceIntegrations.get(key);
    return value !== undefined && isMeaningful(value);
  });
  const blockers = risky.map((diff) =>
    `shared integration ${diff.integration_key_hash.slice(0, 16)} has ${diff.source_only_count} source value(s) absent from the target`,
  ).concat(riskySourceOnly.map((key) => {
    const keyHash = sha256(`gorgias-integration-key:v1:${key}`).slice(0, 16);
    const leafCount = meaningfulLeafCount(sourceIntegrations.get(key) ?? null);
    return `source-only integration ${keyHash} has ${leafCount} meaningful value(s) absent from the target`;
  }));
  return deepFreeze({
    ok: blockers.length === 0,
    source_snapshot: sanitizedSnapshotFromMap(sourceCustomer, sourceIntegrations),
    target_snapshot: sanitizedSnapshotFromMap(targetCustomer, targetIntegrations),
    shared_integration_count: sharedKeys.length,
    source_only_integration_count: sourceOnlyKeys.length,
    target_only_integration_count: [...targetIntegrations.keys()].filter((key) => !sourceIntegrations.has(key)).length,
    risky_shared_integration_count: risky.length,
    risky_source_only_integration_count: riskySourceOnly.length,
    diffs,
    blockers,
  });
}

export function verifyMergeIntegrationReadback(
  sourceBefore: unknown,
  targetBefore: unknown,
  targetAfter: unknown,
): Readonly<MergeIntegrationReadback> {
  const postIntegrations = integrationMap(targetAfter);
  const missingSource: string[] = [];
  const missingTarget: string[] = [];
  for (const [key, value] of integrationMap(sourceBefore)) {
    missingSource.push(...hashedPaths(key, sourceOnlyPaths(value, postIntegrations.get(key))));
  }
  for (const [key, value] of integrationMap(targetBefore)) {
    missingTarget.push(...hashedPaths(key, sourceOnlyPaths(value, postIntegrations.get(key))));
  }
  return deepFreeze({
    ok: missingSource.length === 0 && missingTarget.length === 0,
    source_preserved: missingSource.length === 0,
    target_preserved: missingTarget.length === 0,
    missing_source_value_count: missingSource.length,
    missing_target_value_count: missingTarget.length,
    missing_path_hashes: [...new Set([...missingSource, ...missingTarget])].sort(),
  });
}
