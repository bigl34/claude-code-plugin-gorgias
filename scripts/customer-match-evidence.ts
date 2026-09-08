import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { domainToASCII } from "node:url";
import { parsePhoneNumberFromString, type CountryCode } from "libphonenumber-js";

const ROLE_MAILBOXES = new Set([
  "info",
  "support",
  "sales",
  "admin",
  "order",
  "orders",
  "account",
  "accounts",
  "hello",
  "contact",
  "office",
  "team",
  "help",
  "warehouse",
  "return",
  "returns",
  "service",
]);

const HONORIFICS = new Set(["mr", "mrs", "ms", "miss", "dr", "sir", "dame", "prof", "professor"]);
const STAGE_AAD = Buffer.from("gorgias-customer-match-stage.v1", "utf8");
const GCM_AUTH_TAG_LENGTH_BYTES = 16;

export interface EmailEvidence {
  exact: string;
  local: string;
  domain: string;
  providerAlias?: string;
  roleMailbox: boolean;
}

export interface PhoneEvidence {
  e164: string;
  nationalNumber: string;
  last7: string;
  country?: string;
  extension?: string;
}

export interface NameEvidence {
  canonical: string;
  orderInsensitive: string;
  tokens: string[];
  surname: string;
  firstInitial: string;
}

export interface AddressEvidence {
  full: string;
  postcode?: string;
  countryCode?: string;
  role: string;
}

export interface RunCrypto {
  keyId: string;
  encryptionKey: Buffer;
  fingerprint(domain: string, value: string): string;
}

interface SealedRecord {
  schema: "gorgias-customer-match-stage-record.v1";
  iv: string;
  ciphertext: string;
  tag: string;
}

function canonicalText(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function readString(record: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) return value;
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
  }
  return undefined;
}

export function normaliseEmailEvidence(value: unknown): EmailEvidence | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().normalize("NFKC").toLowerCase();
  const at = trimmed.lastIndexOf("@");
  if (at <= 0 || at === trimmed.length - 1 || trimmed.indexOf("@") !== at) return null;
  const local = trimmed.slice(0, at);
  const asciiDomain = domainToASCII(trimmed.slice(at + 1));
  if (!asciiDomain || !asciiDomain.includes(".") || /\s/.test(local)) return null;

  const roleLocal = local.split("+", 1)[0];
  const evidence: EmailEvidence = {
    exact: `${local}@${asciiDomain}`,
    local,
    domain: asciiDomain,
    roleMailbox: ROLE_MAILBOXES.has(roleLocal),
  };

  if (asciiDomain === "gmail.com" || asciiDomain === "googlemail.com") {
    const aliasLocal = roleLocal.replace(/\./g, "");
    if (aliasLocal) evidence.providerAlias = `${aliasLocal}@gmail.com`;
  }
  return evidence;
}

export function normalisePhoneEvidence(value: unknown, defaultCountry: string): PhoneEvidence | null {
  if (typeof value !== "string") return null;
  const extensionMatch = value.match(/(?:ext\.?|extension|x)\s*(\d+)\s*$/i);
  const extension = extensionMatch?.[1];
  let cleaned = extensionMatch ? value.slice(0, extensionMatch.index).trim() : value.trim();
  cleaned = cleaned.replace(/^00/, "+").replace(/^(\+\d{1,3})\s*\(0\)/, "$1");
  const parsed = parsePhoneNumberFromString(cleaned, defaultCountry.toUpperCase() as CountryCode);
  if (!parsed?.isPossible()) return null;
  const nationalNumber = parsed.nationalNumber;
  return {
    e164: parsed.number,
    nationalNumber,
    last7: nationalNumber.slice(-7),
    country: parsed.country,
    ...(extension ? { extension } : {}),
  };
}

export function normaliseNameEvidence(value: unknown): NameEvidence | null {
  if (typeof value !== "string") return null;
  const tokens = canonicalText(value).split(" ").filter((token) => token && !HONORIFICS.has(token));
  if (tokens.length === 0) return null;
  return {
    canonical: tokens.join(" "),
    orderInsensitive: [...tokens].sort().join(" "),
    tokens,
    surname: tokens[tokens.length - 1],
    firstInitial: tokens[0].slice(0, 1),
  };
}

export function normaliseAddressEvidence(value: unknown, role: string): AddressEvidence | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const address1 = readString(record, ["address1", "address_1", "line1", "street"]);
  const address2 = readString(record, ["address2", "address_2", "line2"]);
  const city = readString(record, ["city", "town"]);
  const postcodeRaw = readString(record, ["zip", "zipcode", "postal_code", "postcode"]);
  const countryRaw = readString(record, ["country_code", "countryCode", "country"]);
  if (!address1 || !postcodeRaw) return null;
  const countryCode = countryRaw ? canonicalText(countryRaw).replace(/\s/g, "") : undefined;
  const parts = [address2, address1, city, postcodeRaw, countryCode]
    .map((part) => part ? canonicalText(part) : "")
    .filter(Boolean);
  if (parts.length < 2) return null;
  return {
    full: parts.join("|"),
    ...(postcodeRaw ? { postcode: canonicalText(postcodeRaw).replace(/\s/g, "") } : {}),
    ...(countryCode ? { countryCode } : {}),
    role,
  };
}

export function createRunCrypto(key: Buffer): RunCrypto {
  if (key.length !== 32) throw new Error("customer match run key must be exactly 32 bytes");
  const encryptionKey = Buffer.from(hkdfSync("sha256", key, Buffer.alloc(0), "gorgias-customer-match-encryption-v1", 32));
  const hmacKey = Buffer.from(hkdfSync("sha256", key, Buffer.alloc(0), "gorgias-customer-match-hmac-v1", 32));
  return {
    keyId: createHash("sha256").update(key).digest("hex").slice(0, 16),
    encryptionKey,
    fingerprint(domain: string, value: string): string {
      return createHmac("sha256", hmacKey).update(`${domain}\0${value}`, "utf8").digest("hex");
    },
  };
}

export function sealEncryptedRecord(crypto: RunCrypto, value: unknown): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", crypto.encryptionKey, iv, {
    authTagLength: GCM_AUTH_TAG_LENGTH_BYTES,
  });
  cipher.setAAD(STAGE_AAD);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  const record: SealedRecord = {
    schema: "gorgias-customer-match-stage-record.v1",
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
  return JSON.stringify(record);
}

export function openEncryptedRecord<T = unknown>(crypto: RunCrypto, sealed: string): T {
  const record = JSON.parse(sealed) as SealedRecord;
  if (record.schema !== "gorgias-customer-match-stage-record.v1") {
    throw new Error("unsupported customer match stage record schema");
  }
  const tag = Buffer.from(record.tag, "base64");
  if (tag.length !== GCM_AUTH_TAG_LENGTH_BYTES) {
    throw new Error("invalid customer match stage record auth tag length");
  }
  const decipher = createDecipheriv("aes-256-gcm", crypto.encryptionKey, Buffer.from(record.iv, "base64"), {
    authTagLength: GCM_AUTH_TAG_LENGTH_BYTES,
  });
  decipher.setAAD(STAGE_AAD);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
  return JSON.parse(plaintext) as T;
}

export function loadRunKey(path: string): Buffer {
  const existing = readFileSync(path);
  if (existing.length !== 32) throw new Error("existing customer match run key has invalid length");
  chmodSync(path, 0o600);
  return existing;
}

export function loadOrCreateRunKey(path: string): Buffer {
  try {
    return loadRunKey(path);
  } catch (error) {
    const code = error && typeof error === "object" ? (error as { code?: unknown }).code : undefined;
    if (code !== "ENOENT") throw error;
  }

  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const key = randomBytes(32);
  try {
    writeFileSync(path, key, { flag: "wx", mode: 0o600 });
    return key;
  } catch (error) {
    const code = error && typeof error === "object" ? (error as { code?: unknown }).code : undefined;
    if (code !== "EEXIST") throw error;
    return loadRunKey(path);
  }
}
