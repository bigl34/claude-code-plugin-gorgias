import { createHash } from "node:crypto";

import { type RunCrypto } from "./customer-match-evidence.js";
import {
  type CustomerMatchRecord,
  type IdentityEvidence,
  type MessageMatchRecord,
  type SourcedValue,
} from "./customer-match-records.js";
import {
  type AddressEvidence,
  type EmailEvidence,
  type NameEvidence,
  type PhoneEvidence,
} from "./customer-match-evidence.js";

export type MatchRule = "R1" | "R2" | "R3" | "R4" | "R5" | "R6" | "R7" | "R8";
export type MatchConfidence = "strong_candidate" | "corroborated_candidate" | "possible_match" | "relationship_only" | "conflict";

const CUSTOMER_MATCH_RULE_VERSION = "2.1.0" as const;
const INTERNAL_BUSINESS_EMAIL_DOMAINS = new Set([
  "disputifier.com",
  "your-company.com",
  "your-company.com",
]);

export interface MatchEvidence {
  rule: MatchRule;
  kind: string;
  fingerprint: string;
  degree: number;
  roles: string[];
  provenance: string[];
  requiresShopifyVerification: boolean;
}

export interface CustomerMatchReviewEdge {
  edgeId: string;
  recordIds: [number, number];
  clusterId: string;
  confidence: MatchConfidence;
  rules: MatchRule[];
  evidence: MatchEvidence[];
  blockers: string[];
  relationshipFlags: string[];
  reviewer: {
    disposition: "pending" | "possible_same_person" | "same_household" | "shared_contact_point" | "integration_artifact_suspected" | "rejected" | "blocked";
    reviewedBy?: string;
    reviewedAt?: string;
    unresolvedEvidence?: string[];
  };
}

type AuditPair = [number, number];
export type AuditStratum = "fuzzy_email_near_miss" | "phone_suffix_only" | "address_name_near_miss" | "name_only" | "uniform_random";

export interface CustomerMatchAuditEntry {
  auditId: string;
  recordIds: AuditPair;
  stratum: AuditStratum;
  reviewer: {
    disposition: "pending" | "possible_same_person" | "not_same_person" | "uncertain";
    reviewedBy?: string;
    reviewedAt?: string;
    notes?: string[];
  };
}

export interface CustomerMatchAuditSample {
  ready: boolean;
  perStratum: number;
  sample: CustomerMatchAuditEntry[];
  shortfalls: Record<AuditStratum, number>;
}

export interface CustomerMatchReviewProposal {
  schema: "gorgias-customer-match-review.v2";
  ruleVersion: typeof CUSTOMER_MATCH_RULE_VERSION;
  generatedAt: string;
  scanDigest: string;
  inputDigest: string;
  proposalDigest: string;
  scanComplete: true;
  ruleComplete: true;
  profileCount: number;
  excludedProfileCount: number;
  edgeCount: number;
  ruleCounts: Record<MatchRule, number>;
  edges: CustomerMatchReviewEdge[];
  auditPools: {
    provider_alias_near_miss: AuditPair[];
    fuzzy_email_near_miss: AuditPair[];
    phone_suffix_only: AuditPair[];
    address_name_near_miss: AuditPair[];
    name_only: AuditPair[];
  };
  audit: CustomerMatchAuditSample;
}

type InputRecord = CustomerMatchRecord | MessageMatchRecord | { kind: string };

interface Profile {
  customerId: number;
  createdDatetime?: string;
  updatedDatetime?: string;
  emails: Array<SourcedValue<EmailEvidence>>;
  phones: Array<SourcedValue<PhoneEvidence>>;
  names: Array<SourcedValue<NameEvidence>>;
  addresses: Array<SourcedValue<AddressEvidence>>;
  identities: IdentityEvidence[];
  orderReferences: Array<{
    value: string;
    source: string;
    observedAt?: string;
  }>;
}

interface MutableEdge {
  recordIds: [number, number];
  rules: Set<MatchRule>;
  evidence: Map<string, MatchEvidence>;
  blockers: Set<string>;
  relationshipFlags: Set<string>;
  strongSignals: Set<string>;
  forceRelationship: boolean;
  unsafeContact: boolean;
}

interface IndexedValue<T> {
  customerId: number;
  value: T;
  source: string;
  role: string;
  observedAt?: string;
}

const RELAY_DOMAINS = new Set([
  "privaterelay.appleid.com",
  "relay.firefox.com",
  "simplelogin.com",
  "simplelogin.co",
]);

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function pair(ids: number[]): [number, number] {
  const sorted = [...ids].sort((a, b) => a - b);
  return [sorted[0], sorted[1]];
}

function pairKey(a: number, b: number): string {
  return a < b ? `${a}:${b}` : `${b}:${a}`;
}

function parsePairKey(value: string): [number, number] {
  const [a, b] = value.split(":").map(Number);
  return [a, b];
}

function pairCombinations(ids: Iterable<number>): AuditPair[] {
  const sorted = [...new Set(ids)].sort((a, b) => a - b);
  const pairs: AuditPair[] = [];
  for (let i = 0; i < sorted.length; i += 1) {
    for (let j = i + 1; j < sorted.length; j += 1) pairs.push([sorted[i], sorted[j]]);
  }
  return pairs;
}

function addAuditPair(target: Set<string>, a: number, b: number): void {
  if (a !== b) target.add(pairKey(a, b));
}

function sortedAuditPairs(values: Set<string>): AuditPair[] {
  return [...values].map(parsePairKey).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
}

function profileMap(records: InputRecord[]): Map<number, Profile> {
  const profiles = new Map<number, Profile>();
  const customerRecords = records.filter((record): record is CustomerMatchRecord => record.kind === "customer");
  for (const record of customerRecords) {
    profiles.set(record.customerId, {
      customerId: record.customerId,
      createdDatetime: record.createdDatetime,
      updatedDatetime: record.updatedDatetime,
      emails: [...record.emails],
      phones: [...record.phones],
      names: [...record.names],
      addresses: [...record.addresses],
      identities: [...record.identities],
      orderReferences: [],
    });
  }
  for (const record of records.filter((entry): entry is MessageMatchRecord => entry.kind === "message")) {
    if (!record.positiveEligible || !record.customerId) continue;
    const profile = profiles.get(record.customerId);
    if (!profile) continue;
    profile.emails.push(...record.emails);
    profile.phones.push(...record.phones);
    profile.identities.push(...record.identities);
    profile.orderReferences.push(...record.orderReferences.map((value) => ({
      value,
      source: `message:${record.messageId}.text`,
      ...(record.createdDatetime ? { observedAt: record.createdDatetime } : {}),
    })));
  }
  return profiles;
}

function isInternalBusinessProfile(profile: Profile): boolean {
  return profile.emails.some((item) =>
    item.role !== "historical_sender"
    && INTERNAL_BUSINESS_EMAIL_DOMAINS.has(item.value.domain));
}

function indexSourced<T>(profiles: Map<number, Profile>, select: (profile: Profile) => Array<SourcedValue<T>>, key: (value: T) => string | undefined): Map<string, Array<IndexedValue<T>>> {
  const index = new Map<string, Array<IndexedValue<T>>>();
  for (const profile of profiles.values()) {
    for (const item of select(profile)) {
      const valueKey = key(item.value);
      if (!valueKey) continue;
      const bucket = index.get(valueKey) ?? [];
      bucket.push({ customerId: profile.customerId, value: item.value, source: item.source, role: item.role, observedAt: item.observedAt });
      index.set(valueKey, bucket);
    }
  }
  return index;
}

function identityIndex(profiles: Map<number, Profile>, objectTypes: Set<IdentityEvidence["objectType"]>): Map<string, IdentityEvidence[]> {
  const index = new Map<string, IdentityEvidence[]>();
  for (const profile of profiles.values()) {
    for (const identity of profile.identities) {
      if (!objectTypes.has(identity.objectType)) continue;
      const key = `${identity.namespace}\0${identity.objectType}\0${identity.value}`;
      const bucket = index.get(key) ?? [];
      bucket.push({ ...identity, source: `${profile.customerId}\0${identity.source}` });
      index.set(key, bucket);
    }
  }
  return index;
}

function customerIdFromIdentity(identity: IdentityEvidence): number {
  return Number(identity.source.slice(0, identity.source.indexOf("\0")));
}

function sourceFromIdentity(identity: IdentityEvidence): string {
  return identity.source.slice(identity.source.indexOf("\0") + 1);
}

function ensureEdge(edges: Map<string, MutableEdge>, a: number, b: number): MutableEdge {
  const key = pairKey(a, b);
  let edge = edges.get(key);
  if (!edge) {
    edge = {
      recordIds: pair([a, b]),
      rules: new Set(),
      evidence: new Map(),
      blockers: new Set(),
      relationshipFlags: new Set(),
      strongSignals: new Set(),
      forceRelationship: false,
      unsafeContact: false,
    };
    edges.set(key, edge);
  }
  return edge;
}

function addEvidence(
  edge: MutableEdge,
  crypto: RunCrypto,
  options: {
    rule: MatchRule;
    kind: string;
    rawValue: string;
    degree: number;
    roles?: string[];
    sources?: string[];
    requiresShopifyVerification?: boolean;
    strongSignal?: string;
    relationshipFlag?: string;
    forceRelationship?: boolean;
  },
): void {
  const evidence: MatchEvidence = {
    rule: options.rule,
    kind: options.kind,
    fingerprint: crypto.fingerprint(`${options.rule}:${options.kind}`, options.rawValue),
    degree: options.degree,
    roles: [...new Set(options.roles ?? [])].sort(),
    provenance: [...new Set(options.sources ?? [])].sort(),
    requiresShopifyVerification: options.requiresShopifyVerification === true,
  };
  const evidenceKey = stableStringify(evidence);
  edge.rules.add(options.rule);
  edge.evidence.set(evidenceKey, evidence);
  if (options.strongSignal) edge.strongSignals.add(options.strongSignal);
  if (options.relationshipFlag) edge.relationshipFlags.add(options.relationshipFlag);
  if (options.forceRelationship) edge.forceRelationship = true;
}

function sharedStrings(a: string[], b: string[]): string[] {
  const bSet = new Set(b);
  return [...new Set(a.filter((value) => bSet.has(value)))];
}

function profileIdentityKeys(profile: Profile, objectTypes = new Set<IdentityEvidence["objectType"]>(["customer", "external_customer", "order"])): string[] {
  return profile.identities
    .filter((identity) => objectTypes.has(identity.objectType))
    .map((identity) => `${identity.namespace}\0${identity.objectType}\0${identity.value}`);
}

function maxNameSimilarity(a: Profile, b: Profile): number {
  let max = 0;
  for (const left of a.names) {
    for (const right of b.names) {
      if (left.value.surname !== right.value.surname || left.value.firstInitial !== right.value.firstInitial) continue;
      max = Math.max(max, jaroWinkler(left.value.canonical, right.value.canonical));
    }
  }
  return max;
}

function exactNameShared(a: Profile, b: Profile): boolean {
  const right = new Set(b.names.map((item) => item.value.orderInsensitive));
  return a.names.some((item) => right.has(item.value.orderInsensitive));
}

function strongName(a: Profile, b: Profile): boolean {
  if (exactNameShared(a, b)) return true;
  return maxNameSimilarity(a, b) >= 0.94;
}

function sharedFullAddresses(a: Profile, b: Profile): string[] {
  return sharedStrings(a.addresses.map((item) => item.value.full), b.addresses.map((item) => item.value.full));
}

function exactPhoneShared(a: Profile, b: Profile): boolean {
  return sharedStrings(a.phones.map((item) => item.value.e164), b.phones.map((item) => item.value.e164)).length > 0;
}

function contactRelationshipFlags(
  degree: number,
  entries: Array<IndexedValue<EmailEvidence | PhoneEvidence>>,
  a: Profile,
  b: Profile,
): string[] {
  const flags = new Set<string>();
  if (degree >= 3) flags.add("shared_contact_point");
  if (entries.some((entry) => "roleMailbox" in entry.value && entry.value.roleMailbox)) flags.add("role_contact_point");
  const leftDates = entries.filter((entry) => entry.customerId === a.customerId).map((entry) => entry.observedAt);
  const rightDates = entries.filter((entry) => entry.customerId === b.customerId).map((entry) => entry.observedAt);
  const observedGaps = leftDates.flatMap((left) => rightDates.map((right) => dateGapDays(left, right)));
  const gaps = observedGaps.filter((gap): gap is number => gap !== undefined);
  if (gaps.length !== observedGaps.length) flags.add("ownership_timing_unknown");
  if (!distinctNames(a, b)) return [...flags];
  if (gaps.some((gap) => gap <= 30)) flags.add("concurrent_distinct_names");
  else if (gaps.length > 0 && gaps.every((gap) => gap >= 730)) flags.add("recycled_contact_possible");
  return [...flags];
}

function safeExactPhoneShared(a: Profile, b: Profile, profiles: Map<number, Profile>): boolean {
  for (const value of sharedStrings(a.phones.map((item) => item.value.e164), b.phones.map((item) => item.value.e164))) {
    const entries: Array<IndexedValue<PhoneEvidence>> = [];
    for (const profile of profiles.values()) {
      for (const phone of profile.phones.filter((item) => item.value.e164 === value)) {
        entries.push({ customerId: profile.customerId, value: phone.value, source: phone.source, role: phone.role, observedAt: phone.observedAt });
      }
    }
    const degree = new Set(entries.map((entry) => entry.customerId)).size;
    if (contactRelationshipFlags(degree, entries, a, b).length === 0) return true;
  }
  return false;
}

function hasUnsafeExactContact(a: Profile, b: Profile, profiles: Map<number, Profile>): boolean {
  const sharedValues = [
    ...sharedStrings(a.emails.map((item) => item.value.exact), b.emails.map((item) => item.value.exact))
      .map((value) => ({ kind: "email" as const, value })),
    ...sharedStrings(a.phones.map((item) => item.value.e164), b.phones.map((item) => item.value.e164))
      .map((value) => ({ kind: "phone" as const, value })),
  ];
  return sharedValues.some(({ kind, value }) => {
    const entries: Array<IndexedValue<EmailEvidence | PhoneEvidence>> = [];
    for (const profile of profiles.values()) {
      const values = kind === "email" ? profile.emails : profile.phones;
      for (const item of values) {
        const matches = kind === "email"
          ? (item.value as EmailEvidence).exact === value
          : (item.value as PhoneEvidence).e164 === value;
        if (matches) entries.push({
          customerId: profile.customerId,
          value: item.value,
          source: item.source,
          role: item.role,
          observedAt: item.observedAt,
        });
      }
    }
    const degree = new Set(entries.map((entry) => entry.customerId)).size;
    return contactRelationshipFlags(degree, entries, a, b).length > 0;
  });
}

function corroborates(a: Profile, b: Profile, profiles: Map<number, Profile>): boolean {
  if (safeExactPhoneShared(a, b, profiles)) return true;
  if (sharedStrings(profileIdentityKeys(a), profileIdentityKeys(b)).length > 0) return true;
  if (sharedFullAddresses(a, b).length > 0 && strongName(a, b)) return true;
  return exactNameShared(a, b) && !hasUnsafeExactContact(a, b, profiles);
}

function distinctNames(a: Profile, b: Profile): boolean {
  const right = new Set(b.names.map((item) => item.value.orderInsensitive));
  return !a.names.some((item) => right.has(item.value.orderInsensitive));
}

function dateGapDays(left?: string, right?: string): number | undefined {
  if (!left || !right) return undefined;
  const a = Date.parse(left);
  const b = Date.parse(right);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return undefined;
  return Math.abs(a - b) / 86_400_000;
}

function applyContactRelationshipFlags(edge: MutableEdge, degree: number, entries: Array<IndexedValue<EmailEvidence | PhoneEvidence>>, a: Profile, b: Profile): void {
  for (const flag of contactRelationshipFlags(degree, entries, a, b)) {
    edge.relationshipFlags.add(flag);
    edge.unsafeContact = true;
  }
}

function addExactContactRules(edges: Map<string, MutableEdge>, profiles: Map<number, Profile>, crypto: RunCrypto): void {
  const emailIndex = indexSourced(profiles, (profile) => profile.emails, (value) => value.exact);
  const phoneIndex = indexSourced(profiles, (profile) => profile.phones, (value) => value.e164);
  for (const [value, entries] of [...emailIndex, ...phoneIndex] as Array<[string, Array<IndexedValue<EmailEvidence | PhoneEvidence>>]>) {
    const ids = [...new Set(entries.map((entry) => entry.customerId))];
    if (ids.length < 2) continue;
    for (const [aId, bId] of pairCombinations(ids)) {
      const edge = ensureEdge(edges, aId, bId);
      const kind = "exact" in entries[0].value ? "exact_email" : "exact_phone";
      addEvidence(edge, crypto, {
        rule: "R2",
        kind,
        rawValue: value,
        degree: ids.length,
        roles: entries.filter((entry) => entry.customerId === aId || entry.customerId === bId).map((entry) => entry.role),
        sources: entries.filter((entry) => entry.customerId === aId || entry.customerId === bId).map((entry) => entry.source),
        strongSignal: "exact_contact",
      });
      applyContactRelationshipFlags(edge, ids.length, entries, profiles.get(aId)!, profiles.get(bId)!);
    }
  }
}

function addIdentityRules(edges: Map<string, MutableEdge>, profiles: Map<number, Profile>, crypto: RunCrypto): void {
  const customerIdentities = identityIndex(profiles, new Set(["customer", "external_customer"]));
  for (const [value, entries] of customerIdentities) {
    const ids = [...new Set(entries.map(customerIdFromIdentity))];
    if (ids.length < 2) continue;
    for (const [a, b] of pairCombinations(ids)) {
      const edge = ensureEdge(edges, a, b);
      addEvidence(edge, crypto, {
        rule: "R1",
        kind: "stable_customer_identity",
        rawValue: value,
        degree: ids.length,
        roles: entries.map((entry) => entry.role),
        sources: entries.map(sourceFromIdentity),
        strongSignal: "stable_identity",
      });
    }
  }

  const orders = identityIndex(profiles, new Set(["order"]));
  for (const [value, entries] of orders) {
    const ids = [...new Set(entries.map(customerIdFromIdentity))];
    if (ids.length < 2) continue;
    for (const [a, b] of pairCombinations(ids)) {
      const edge = ensureEdge(edges, a, b);
      addEvidence(edge, crypto, {
        rule: "R3",
        kind: "shopify_order_identity",
        rawValue: value,
        degree: ids.length,
        roles: entries.map((entry) => entry.role),
        sources: entries.map(sourceFromIdentity),
        requiresShopifyVerification: true,
        strongSignal: "order_identity",
      });
    }
  }

  const orderReferences = new Map<string, Array<{ customerId: number; source: string; observedAt?: string }>>();
  for (const profile of profiles.values()) {
    for (const reference of profile.orderReferences) {
      const entries = orderReferences.get(reference.value) ?? [];
      entries.push({
        customerId: profile.customerId,
        source: reference.source,
        ...(reference.observedAt ? { observedAt: reference.observedAt } : {}),
      });
      orderReferences.set(reference.value, entries);
    }
  }
  for (const [reference, entries] of orderReferences) {
    const ids = [...new Set(entries.map((entry) => entry.customerId))];
    if (new Set(ids).size < 2) continue;
    for (const [a, b] of pairCombinations(ids)) {
      const edge = ensureEdge(edges, a, b);
      addEvidence(edge, crypto, {
        rule: "R3",
        kind: "unverified_order_reference",
        rawValue: reference,
        degree: new Set(ids).size,
        sources: entries
          .filter((entry) => entry.customerId === a || entry.customerId === b)
          .map((entry) => entry.source),
        requiresShopifyVerification: true,
      });
    }
  }
}

function addAliasRules(edges: Map<string, MutableEdge>, profiles: Map<number, Profile>, crypto: RunCrypto, audit: Set<string>): void {
  const aliases = indexSourced(profiles, (profile) => profile.emails, (value) => value.providerAlias);
  for (const [value, entries] of aliases) {
    const ids = [...new Set(entries.map((entry) => entry.customerId))];
    if (ids.length < 2) continue;
    for (const [aId, bId] of pairCombinations(ids)) {
      const a = profiles.get(aId)!;
      const b = profiles.get(bId)!;
      if (!corroborates(a, b, profiles)) {
        addAuditPair(audit, aId, bId);
        continue;
      }
      const edge = ensureEdge(edges, aId, bId);
      addEvidence(edge, crypto, {
        rule: "R4",
        kind: "provider_email_alias",
        rawValue: value,
        degree: ids.length,
        roles: entries.map((entry) => entry.role),
        sources: entries.map((entry) => entry.source),
        strongSignal: "provider_alias",
      });
    }
  }
}

function deletionSignatures(value: string): string[] {
  const signatures = new Set<string>([value]);
  for (let index = 0; index < value.length; index += 1) {
    signatures.add(value.slice(0, index) + value.slice(index + 1));
  }
  return [...signatures];
}

export function damerauLevenshtein(a: string, b: string): number {
  const rows = a.length + 1;
  const columns = b.length + 1;
  const matrix = Array.from({ length: rows }, () => Array<number>(columns).fill(0));
  for (let i = 0; i < rows; i += 1) matrix[i][0] = i;
  for (let j = 0; j < columns; j += 1) matrix[0][j] = j;
  for (let i = 1; i < rows; i += 1) {
    for (let j = 1; j < columns; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost,
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        matrix[i][j] = Math.min(matrix[i][j], matrix[i - 2][j - 2] + cost);
      }
    }
  }
  return matrix[a.length][b.length];
}

function fuzzyEligible(email: EmailEvidence): boolean {
  return !email.roleMailbox
    && !email.local.includes('"')
    && !email.domain.split(".").some((part) => part.startsWith("xn--"))
    && !RELAY_DOMAINS.has(email.domain);
}

function addFuzzyEmailRules(edges: Map<string, MutableEdge>, profiles: Map<number, Profile>, crypto: RunCrypto, audit: Set<string>): void {
  const entries: Array<IndexedValue<EmailEvidence>> = [];
  for (const profile of profiles.values()) {
    for (const email of profile.emails) {
      if (fuzzyEligible(email.value)) entries.push({ customerId: profile.customerId, value: email.value, source: email.source, role: email.role, observedAt: email.observedAt });
    }
  }
  const blocks = new Map<string, number[]>();
  entries.forEach((entry, index) => {
    if (entry.value.local.length >= 5) {
      for (const signature of deletionSignatures(entry.value.local)) {
        const key = `local\0${entry.value.domain}\0${signature}`;
        const values = blocks.get(key) ?? [];
        values.push(index);
        blocks.set(key, values);
      }
    }
    if (entry.value.domain.length >= 5) {
      for (const signature of deletionSignatures(entry.value.domain)) {
        const key = `domain\0${entry.value.local}\0${signature}`;
        const values = blocks.get(key) ?? [];
        values.push(index);
        blocks.set(key, values);
      }
    }
  });

  const candidatePairs = new Set<string>();
  for (const indexes of blocks.values()) {
    for (const [leftIndex, rightIndex] of pairCombinations(indexes)) {
      const left = entries[leftIndex];
      const right = entries[rightIndex];
      if (left.customerId !== right.customerId) candidatePairs.add(`${Math.min(leftIndex, rightIndex)}:${Math.max(leftIndex, rightIndex)}`);
    }
  }

  for (const candidate of candidatePairs) {
    const [leftIndex, rightIndex] = candidate.split(":").map(Number);
    const left = entries[leftIndex];
    const right = entries[rightIndex];
    const localMatch = left.value.domain === right.value.domain
      && left.value.local.length >= 5
      && right.value.local.length >= 5
      && damerauLevenshtein(left.value.local, right.value.local) === 1;
    const domainMatch = left.value.local === right.value.local
      && left.value.domain.length >= 5
      && right.value.domain.length >= 5
      && damerauLevenshtein(left.value.domain, right.value.domain) === 1;
    if (!(localMatch || domainMatch)) continue;
    const aId = left.customerId;
    const bId = right.customerId;
    const a = profiles.get(aId)!;
    const b = profiles.get(bId)!;
    if (!corroborates(a, b, profiles)) {
      addAuditPair(audit, aId, bId);
      continue;
    }
    const edge = ensureEdge(edges, aId, bId);
    addEvidence(edge, crypto, {
      rule: "R5",
      kind: localMatch ? "email_local_edit_distance_1" : "email_domain_edit_distance_1",
      rawValue: [left.value.exact, right.value.exact].sort().join("\0"),
      degree: 2,
      roles: [left.role, right.role],
      sources: [left.source, right.source],
      strongSignal: "fuzzy_email",
    });
  }
}

function addPhoneRelationshipRules(edges: Map<string, MutableEdge>, profiles: Map<number, Profile>, crypto: RunCrypto, audit: Set<string>): void {
  const nsn = indexSourced(profiles, (profile) => profile.phones, (value) => value.nationalNumber);
  const last7 = indexSourced(profiles, (profile) => profile.phones, (value) => value.last7);
  for (const [kind, index] of [["national_number", nsn], ["last_7_digits", last7]] as const) {
    for (const [value, entries] of index) {
      const ids = [...new Set(entries.map((entry) => entry.customerId))];
      if (ids.length < 2) continue;
      for (const [a, b] of pairCombinations(ids)) {
        const exact = exactPhoneShared(profiles.get(a)!, profiles.get(b)!);
        if (exact) continue;
        addAuditPair(audit, a, b);
        const edge = ensureEdge(edges, a, b);
        addEvidence(edge, crypto, {
          rule: "R6",
          kind,
          rawValue: value,
          degree: ids.length,
          roles: entries.map((entry) => entry.role),
          sources: entries.map((entry) => entry.source),
          relationshipFlag: "phone_partial_match",
          forceRelationship: !exact,
        });
      }
    }
  }
}

function addAddressRules(edges: Map<string, MutableEdge>, profiles: Map<number, Profile>, crypto: RunCrypto, audit: Set<string>): void {
  const addresses = indexSourced(profiles, (profile) => profile.addresses, (value) => value.full);
  for (const [value, entries] of addresses) {
    const ids = [...new Set(entries.map((entry) => entry.customerId))];
    if (ids.length < 2) continue;
    for (const [aId, bId] of pairCombinations(ids)) {
      const namesStrong = strongName(profiles.get(aId)!, profiles.get(bId)!);
      if (!namesStrong) addAuditPair(audit, aId, bId);
      const edge = ensureEdge(edges, aId, bId);
      addEvidence(edge, crypto, {
        rule: "R7",
        kind: namesStrong ? "full_address_and_strong_name" : "full_address_only",
        rawValue: value,
        degree: ids.length,
        roles: entries.map((entry) => entry.role),
        sources: entries.map((entry) => entry.source),
        strongSignal: namesStrong ? "address_name" : undefined,
        relationshipFlag: namesStrong ? undefined : "same_household",
        forceRelationship: !namesStrong || ids.length > 4,
      });
      if (ids.length > 4) edge.relationshipFlags.add("high_occupancy_address");
    }
  }
}

function addNameRules(edges: Map<string, MutableEdge>, profiles: Map<number, Profile>, crypto: RunCrypto, audit: Set<string>): void {
  const names = indexSourced(profiles, (profile) => profile.names, (value) => value.orderInsensitive);
  for (const [value, entries] of names) {
    const ids = [...new Set(entries.map((entry) => entry.customerId))];
    if (ids.length < 2) continue;
    for (const [a, b] of pairCombinations(ids)) {
      addAuditPair(audit, a, b);
      const edge = ensureEdge(edges, a, b);
      addEvidence(edge, crypto, {
        rule: "R8",
        kind: "exact_normalized_name",
        rawValue: value,
        degree: ids.length,
        roles: entries.map((entry) => entry.role),
        sources: entries.map((entry) => entry.source),
        relationshipFlag: "name_only_evidence",
        forceRelationship: true,
      });
    }
  }
}

function stableIdentityMap(profile: Profile): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  for (const identity of profile.identities.filter((item) => item.objectType === "customer" || item.objectType === "external_customer")) {
    const key = `${identity.namespace}\0${identity.objectType}`;
    const values = map.get(key) ?? new Set<string>();
    values.add(identity.value);
    map.set(key, values);
  }
  return map;
}

function applyIdentityConflicts(edge: MutableEdge, a: Profile, b: Profile): void {
  const left = stableIdentityMap(a);
  const right = stableIdentityMap(b);
  for (const [namespace, leftValues] of left) {
    const rightValues = right.get(namespace);
    if (!rightValues || sharedStrings([...leftValues], [...rightValues]).length > 0) continue;
    edge.blockers.add("conflicting_stable_identity");
    if (namespace.includes("\0customer") && namespace.includes("|shopify|")) {
      edge.blockers.add("shopify_premerge_required");
    }
  }
}

function edgeConfidence(edge: MutableEdge): MatchConfidence {
  if (edge.blockers.size > 0) return "conflict";
  if (edge.rules.has("R1")) return "strong_candidate";
  if (edge.unsafeContact) return "relationship_only";
  if (edge.relationshipFlags.has("high_occupancy_address")) return "relationship_only";
  if (edge.forceRelationship && edge.strongSignals.size === 0) return "relationship_only";
  if (edge.rules.has("R2") && edge.strongSignals.size >= 2) return "strong_candidate";
  if (edge.rules.has("R4") || edge.rules.has("R7")) {
    if (edge.strongSignals.has("address_name") || edge.strongSignals.has("provider_alias")) return "corroborated_candidate";
  }
  if (edge.rules.has("R2") || edge.rules.has("R3") || edge.rules.has("R5")) return "possible_match";
  return "relationship_only";
}

function assignClusters(edges: MutableEdge[], crypto: RunCrypto): Map<number, string> {
  const parent = new Map<number, number>();
  const find = (id: number): number => {
    const current = parent.get(id) ?? id;
    if (current === id) {
      parent.set(id, id);
      return id;
    }
    const root = find(current);
    parent.set(id, root);
    return root;
  };
  const union = (a: number, b: number): void => {
    const aRoot = find(a);
    const bRoot = find(b);
    if (aRoot !== bRoot) parent.set(Math.max(aRoot, bRoot), Math.min(aRoot, bRoot));
  };
  for (const edge of edges) union(edge.recordIds[0], edge.recordIds[1]);
  const members = new Map<number, number[]>();
  for (const id of parent.keys()) {
    const root = find(id);
    const ids = members.get(root) ?? [];
    ids.push(id);
    members.set(root, ids);
  }
  const clusters = new Map<number, string>();
  for (const ids of members.values()) {
    const sorted = ids.sort((a, b) => a - b);
    const clusterId = crypto.fingerprint("cluster-root", String(sorted[0])).slice(0, 16);
    for (const id of sorted) clusters.set(id, clusterId);
  }
  return clusters;
}

function inputDigest(profiles: Map<number, Profile>, crypto: RunCrypto): string {
  const summary = [...profiles.values()].sort((a, b) => a.customerId - b.customerId).map((profile) => ({
    id: profile.customerId,
    emails: profile.emails.map((item) => crypto.fingerprint("input:email", stableStringify(item))).sort(),
    phones: profile.phones.map((item) => crypto.fingerprint("input:phone", stableStringify(item))).sort(),
    names: profile.names.map((item) => crypto.fingerprint("input:name", stableStringify(item))).sort(),
    addresses: profile.addresses.map((item) => crypto.fingerprint("input:address", stableStringify(item))).sort(),
    identities: profile.identities.map((item) => crypto.fingerprint("input:identity", stableStringify(item))).sort(),
    orderReferences: profile.orderReferences.map((item) => crypto.fingerprint(
      "input:order-reference",
      `${item.value}\0${item.source}\0${item.observedAt ?? ""}`,
    )).sort(),
  }));
  return sha256(stableStringify(summary));
}

export function buildCustomerMatchReview(options: {
  records: InputRecord[];
  crypto: RunCrypto;
  generatedAt: string;
  scanDigest: string;
  scanComplete: boolean;
  auditPerStratum?: number;
}): CustomerMatchReviewProposal {
  if (!options.scanComplete) throw new Error("customer match proposal requires a complete scan");
  const allProfiles = profileMap(options.records);
  const profiles = new Map(
    [...allProfiles].filter(([, profile]) => !isInternalBusinessProfile(profile)),
  );
  const excludedProfileCount = allProfiles.size - profiles.size;
  const edges = new Map<string, MutableEdge>();
  const providerAliasNearMiss = new Set<string>();
  const fuzzyEmailNearMiss = new Set<string>();
  const phoneSuffixOnly = new Set<string>();
  const addressNameNearMiss = new Set<string>();
  const nameOnly = new Set<string>();

  addIdentityRules(edges, profiles, options.crypto);
  addExactContactRules(edges, profiles, options.crypto);
  addAliasRules(edges, profiles, options.crypto, providerAliasNearMiss);
  addFuzzyEmailRules(edges, profiles, options.crypto, fuzzyEmailNearMiss);
  addPhoneRelationshipRules(edges, profiles, options.crypto, phoneSuffixOnly);
  addAddressRules(edges, profiles, options.crypto, addressNameNearMiss);
  addNameRules(edges, profiles, options.crypto, nameOnly);

  const mutableEdges = [...edges.values()].sort((a, b) => a.recordIds[0] - b.recordIds[0] || a.recordIds[1] - b.recordIds[1]);
  for (const edge of mutableEdges) {
    applyIdentityConflicts(edge, profiles.get(edge.recordIds[0])!, profiles.get(edge.recordIds[1])!);
  }
  const clusters = assignClusters(mutableEdges, options.crypto);
  const reviewEdges: CustomerMatchReviewEdge[] = mutableEdges.map((edge) => {
    const evidence = [...edge.evidence.values()].sort((a, b) => a.rule.localeCompare(b.rule) || a.kind.localeCompare(b.kind) || a.fingerprint.localeCompare(b.fingerprint));
    const rules = [...edge.rules].sort();
    const immutable = {
      recordIds: edge.recordIds,
      confidence: edgeConfidence(edge),
      rules,
      evidence,
      blockers: [...edge.blockers].sort(),
      relationshipFlags: [...edge.relationshipFlags].sort(),
    };
    return {
      edgeId: sha256(stableStringify(immutable)).slice(0, 16),
      ...immutable,
      clusterId: clusters.get(edge.recordIds[0])!,
      reviewer: { disposition: "pending" },
    };
  });

  const ruleCounts = Object.fromEntries(
    (["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"] as MatchRule[])
      .map((rule) => [rule, reviewEdges.filter((edge) => edge.rules.includes(rule)).length]),
  ) as Record<MatchRule, number>;
  const digestInput = inputDigest(allProfiles, options.crypto);
  const immutableProposal = {
    schema: "gorgias-customer-match-review.v2",
    ruleVersion: CUSTOMER_MATCH_RULE_VERSION,
    scanDigest: options.scanDigest,
    inputDigest: digestInput,
    profileCount: allProfiles.size,
    excludedProfileCount,
    ruleCounts,
    edges: reviewEdges.map(({ reviewer: _reviewer, ...edge }) => edge),
  };
  const auditPools = {
    provider_alias_near_miss: sortedAuditPairs(providerAliasNearMiss),
    fuzzy_email_near_miss: sortedAuditPairs(fuzzyEmailNearMiss),
    phone_suffix_only: sortedAuditPairs(phoneSuffixOnly),
    address_name_near_miss: sortedAuditPairs(addressNameNearMiss),
    name_only: sortedAuditPairs(nameOnly),
  };
  const proposalDigest = sha256(stableStringify(immutableProposal));
  const audit = buildCustomerMatchAuditSample({
    proposalDigest,
    profileIds: [...profiles.keys()],
    edgePairs: reviewEdges.map((edge) => edge.recordIds),
    auditPools,
    perStratum: options.auditPerStratum ?? 60,
  });
  return {
    schema: "gorgias-customer-match-review.v2",
    ruleVersion: CUSTOMER_MATCH_RULE_VERSION,
    generatedAt: options.generatedAt,
    scanDigest: options.scanDigest,
    inputDigest: digestInput,
    proposalDigest,
    scanComplete: true,
    ruleComplete: true,
    profileCount: allProfiles.size,
    excludedProfileCount,
    edgeCount: reviewEdges.length,
    ruleCounts,
    edges: reviewEdges,
    auditPools,
    audit,
  };
}

function seededRandom(seedText: string): () => number {
  let state = Number.parseInt(sha256(seedText).slice(0, 8), 16) || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

function deterministicPairs(values: AuditPair[], seed: string, limit: number): AuditPair[] {
  const unique = new Map<string, AuditPair>();
  for (const value of values) {
    const normalized = pair(value);
    unique.set(pairKey(normalized[0], normalized[1]), normalized);
  }
  return [...unique.values()]
    .sort((a, b) => sha256(`${seed}:${a[0]}:${a[1]}`).localeCompare(sha256(`${seed}:${b[0]}:${b[1]}`)))
    .slice(0, limit);
}

export function buildCustomerMatchAuditSample(options: {
  proposalDigest: string;
  profileIds: number[];
  edgePairs: AuditPair[];
  auditPools: CustomerMatchReviewProposal["auditPools"];
  perStratum?: number;
}): CustomerMatchAuditSample {
  const perStratum = options.perStratum ?? 60;
  const pools: Record<Exclude<AuditStratum, "uniform_random">, AuditPair[]> = {
    fuzzy_email_near_miss: [
      ...options.auditPools.provider_alias_near_miss,
      ...options.auditPools.fuzzy_email_near_miss,
    ],
    phone_suffix_only: options.auditPools.phone_suffix_only,
    address_name_near_miss: options.auditPools.address_name_near_miss,
    name_only: options.auditPools.name_only,
  };
  const sampleByStratum = new Map<AuditStratum, AuditPair[]>();
  for (const [stratum, values] of Object.entries(pools) as Array<[Exclude<AuditStratum, "uniform_random">, AuditPair[]]>) {
    sampleByStratum.set(stratum, deterministicPairs(values, `${options.proposalDigest}:${stratum}`, perStratum));
  }

  const ids = [...new Set(options.profileIds)].sort((a, b) => a - b);
  const excluded = new Set(options.edgePairs.map(([a, b]) => pairKey(a, b)));
  for (const pairs of sampleByStratum.values()) {
    for (const [a, b] of pairs) excluded.add(pairKey(a, b));
  }
  const random = seededRandom(`${options.proposalDigest}:uniform_random`);
  const uniform = new Map<string, AuditPair>();
  const maximumPairs = ids.length * (ids.length - 1) / 2;
  const target = Math.min(perStratum, Math.max(0, maximumPairs - excluded.size));
  const maxAttempts = Math.max(1_000, target * 2_000);
  for (let attempt = 0; uniform.size < target && attempt < maxAttempts; attempt += 1) {
    if (ids.length < 2) break;
    const a = ids[Math.floor(random() * ids.length)];
    const b = ids[Math.floor(random() * ids.length)];
    if (a === b) continue;
    const key = pairKey(a, b);
    if (excluded.has(key) || uniform.has(key)) continue;
    uniform.set(key, pair([a, b]));
  }
  sampleByStratum.set("uniform_random", [...uniform.values()].sort((a, b) => a[0] - b[0] || a[1] - b[1]));

  const strata: AuditStratum[] = [
    "fuzzy_email_near_miss",
    "phone_suffix_only",
    "address_name_near_miss",
    "name_only",
    "uniform_random",
  ];
  const shortfalls = Object.fromEntries(strata.map((stratum) => [
    stratum,
    Math.max(0, perStratum - (sampleByStratum.get(stratum)?.length ?? 0)),
  ])) as Record<AuditStratum, number>;
  const sample = strata.flatMap((stratum) => (sampleByStratum.get(stratum) ?? []).map((recordIds) => ({
    auditId: sha256(`${options.proposalDigest}:${stratum}:${recordIds[0]}:${recordIds[1]}`).slice(0, 16),
    recordIds,
    stratum,
    reviewer: { disposition: "pending" as const },
  })));
  return {
    ready: Object.values(shortfalls).every((value) => value === 0),
    perStratum,
    sample,
    shortfalls,
  };
}

function jaroWinkler(a: string, b: string): number {
  if (a === b) return 1;
  if (!a.length || !b.length) return 0;
  const range = Math.max(0, Math.floor(Math.max(a.length, b.length) / 2) - 1);
  const aMatches = Array<boolean>(a.length).fill(false);
  const bMatches = Array<boolean>(b.length).fill(false);
  let matches = 0;
  for (let i = 0; i < a.length; i += 1) {
    const start = Math.max(0, i - range);
    const end = Math.min(i + range + 1, b.length);
    for (let j = start; j < end; j += 1) {
      if (bMatches[j] || a[i] !== b[j]) continue;
      aMatches[i] = true;
      bMatches[j] = true;
      matches += 1;
      break;
    }
  }
  if (matches === 0) return 0;
  const aChars = a.split("").filter((_char, index) => aMatches[index]);
  const bChars = b.split("").filter((_char, index) => bMatches[index]);
  let transpositions = 0;
  for (let i = 0; i < aChars.length; i += 1) if (aChars[i] !== bChars[i]) transpositions += 1;
  const jaro = (
    matches / a.length
    + matches / b.length
    + (matches - transpositions / 2) / matches
  ) / 3;
  let prefix = 0;
  while (prefix < Math.min(4, a.length, b.length) && a[prefix] === b[prefix]) prefix += 1;
  return jaro + prefix * 0.1 * (1 - jaro);
}
