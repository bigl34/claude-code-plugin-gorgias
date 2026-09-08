import {
  normaliseAddressEvidence,
  normaliseEmailEvidence,
  normaliseNameEvidence,
  normalisePhoneEvidence,
  type AddressEvidence,
  type EmailEvidence,
  type NameEvidence,
  type PhoneEvidence,
} from "./customer-match-evidence.js";

export interface SourcedValue<T> {
  value: T;
  source: string;
  role: string;
  observedAt?: string;
}

export interface IdentityEvidence {
  namespace: string;
  integrationId: string;
  integrationType: string;
  shopDomain: string;
  objectType: "customer" | "order" | "external_customer" | "channel";
  value: string;
  role: string;
  source: string;
  observedAt?: string;
}

export interface CustomerMatchRecord {
  kind: "customer";
  customerId: number;
  createdDatetime?: string;
  updatedDatetime?: string;
  emails: Array<SourcedValue<EmailEvidence>>;
  phones: Array<SourcedValue<PhoneEvidence>>;
  names: Array<SourcedValue<NameEvidence>>;
  addresses: Array<SourcedValue<AddressEvidence>>;
  identities: IdentityEvidence[];
}

export interface MessageMatchRecord {
  kind: "message";
  messageId: number;
  ticketId: number;
  customerId?: number;
  createdDatetime?: string;
  positiveEligible: boolean;
  quarantineReasons: string[];
  emails: Array<SourcedValue<EmailEvidence>>;
  phones: Array<SourcedValue<PhoneEvidence>>;
  identities: IdentityEvidence[];
  orderReferences: string[];
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function readString(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

function readField(record: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = readString(record[key]);
    if (value) return value;
  }
  return undefined;
}

function addEmail(
  items: Array<SourcedValue<EmailEvidence>>,
  raw: unknown,
  source: string,
  role: string,
  observedAt?: string,
): void {
  const value = normaliseEmailEvidence(raw);
  if (!value) return;
  if (items.some((item) => item.value.exact === value.exact && item.source === source && item.role === role)) return;
  items.push({ value, source, role, ...(observedAt ? { observedAt } : {}) });
}

function addPhone(
  items: Array<SourcedValue<PhoneEvidence>>,
  raw: unknown,
  source: string,
  role: string,
  defaultCountry: string,
  observedAt?: string,
): void {
  const value = normalisePhoneEvidence(raw, defaultCountry);
  if (!value) return;
  if (items.some((item) => item.value.e164 === value.e164 && item.source === source && item.role === role)) return;
  items.push({ value, source, role, ...(observedAt ? { observedAt } : {}) });
}

function addName(
  items: Array<SourcedValue<NameEvidence>>,
  raw: unknown,
  source: string,
  role: string,
  observedAt?: string,
): void {
  const value = normaliseNameEvidence(raw);
  if (!value) return;
  if (items.some((item) => item.value.canonical === value.canonical && item.source === source && item.role === role)) return;
  items.push({ value, source, role, ...(observedAt ? { observedAt } : {}) });
}

function addAddress(
  items: Array<SourcedValue<AddressEvidence>>,
  raw: unknown,
  source: string,
  role: string,
  observedAt?: string,
): void {
  const value = normaliseAddressEvidence(raw, role);
  if (!value) return;
  if (items.some((item) => item.value.full === value.full && item.role === role)) return;
  items.push({ value, source, role, ...(observedAt ? { observedAt } : {}) });
}

function integrationNamespace(integrationId: string, integration: Record<string, unknown>): {
  namespace: string;
  integrationType: string;
  shopDomain: string;
} {
  const integrationType = (readField(integration, ["__integration_type__", "type", "provider"]) ?? "unknown").toLowerCase();
  const shop = asRecord(integration.shop);
  const shopDomain = (readField(integration, ["shop_domain", "shopDomain", "myshopify_domain"])
    ?? readField(shop, ["domain", "myshopify_domain"])
    ?? "unknown-shop").toLowerCase();
  return {
    namespace: `${integrationId}|${integrationType}|${shopDomain}`,
    integrationType,
    shopDomain,
  };
}

function pushIdentity(
  identities: IdentityEvidence[],
  base: Omit<IdentityEvidence, "value">,
  raw: unknown,
): void {
  const value = readString(raw);
  if (!value) return;
  const identity: IdentityEvidence = { ...base, value };
  if (identities.some((item) =>
    item.namespace === identity.namespace
    && item.objectType === identity.objectType
    && item.value === identity.value
    && item.role === identity.role)) return;
  identities.push(identity);
}

function collectFallbackDataIdentities(
  identities: IdentityEvidence[],
  value: unknown,
  observedAt?: string,
  path: string[] = ["data"],
): void {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectFallbackDataIdentities(
      identities,
      item,
      observedAt,
      [...path, `[${index}]`],
    ));
    return;
  }

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const childPath = [...path, key];
    const source = `customer.${childPath.join(".").replace(/\.\[/g, "[")}`;
    const namespacePath = path.filter((segment) => !segment.startsWith("[")).join(".") || "data";
    const text = readString(child);
    if (text && (/shopify.*customer.*id|customer.*shopify.*id/i.test(key) || /^gid:\/\/shopify\/Customer\//i.test(text))) {
      pushIdentity(identities, {
        namespace: "fallback|shopify|customer",
        integrationId: "fallback",
        integrationType: "shopify",
        shopDomain: "unknown-shop",
        objectType: "customer",
        role: "owner",
        source,
        ...(observedAt ? { observedAt } : {}),
      }, text);
    }
    if (text && /^external_?id$/i.test(key)) {
      pushIdentity(identities, {
        namespace: `fallback|external|${namespacePath}`,
        integrationId: "fallback",
        integrationType: "external",
        shopDomain: "none",
        objectType: "external_customer",
        role: "owner",
        source,
        ...(observedAt ? { observedAt } : {}),
      }, text);
    }
    collectFallbackDataIdentities(identities, child, observedAt, childPath);
  }
}

function combinedName(record: Record<string, unknown>): string | undefined {
  const explicit = readString(record.name);
  if (explicit) return explicit;
  const combined = [readString(record.first_name ?? record.firstname), readString(record.last_name ?? record.lastname)]
    .filter(Boolean)
    .join(" ");
  return combined || undefined;
}

export function extractCustomerMatchRecord(customer: unknown, options: { defaultCountry: string }): CustomerMatchRecord {
  const record = asRecord(customer);
  const customerId = Number(record.id);
  if (!Number.isInteger(customerId) || customerId < 1) throw new Error("customer match record requires a numeric customer id");
  const createdDatetime = readString(record.created_datetime);
  const updatedDatetime = readString(record.updated_datetime);
  const observedAt = updatedDatetime ?? createdDatetime;
  const emails: Array<SourcedValue<EmailEvidence>> = [];
  const phones: Array<SourcedValue<PhoneEvidence>> = [];
  const names: Array<SourcedValue<NameEvidence>> = [];
  const addresses: Array<SourcedValue<AddressEvidence>> = [];
  const identities: IdentityEvidence[] = [];

  addEmail(emails, record.email, "customer.email", "current", observedAt);
  addPhone(phones, record.phone, "customer.phone", "current", options.defaultCountry, observedAt);
  addName(names, combinedName(record), "customer.name", "current", observedAt);
  pushIdentity(identities, {
    namespace: "gorgias|customer|external",
    integrationId: "gorgias",
    integrationType: "gorgias",
    shopDomain: "none",
    objectType: "external_customer",
    role: "customer",
    source: "customer.external_id",
    ...(observedAt ? { observedAt } : {}),
  }, record.external_id);
  collectFallbackDataIdentities(identities, record.data, observedAt);

  for (const [index, channelValue] of (Array.isArray(record.channels) ? record.channels : []).entries()) {
    const channel = asRecord(channelValue);
    const type = (readString(channel.type) ?? "unknown").toLowerCase();
    const address = readField(channel, ["address", "email", "phone"]);
    const source = `customer.channels[${index}]`;
    if (type === "email") addEmail(emails, address, source, "current", observedAt);
    if (type === "phone" || type === "sms") addPhone(phones, address, source, "current", options.defaultCountry, observedAt);
    if (address && type !== "email" && type !== "phone" && type !== "sms") {
      pushIdentity(identities, {
        namespace: `gorgias|channel|${type}`,
        integrationId: "gorgias",
        integrationType: type,
        shopDomain: "none",
        objectType: "channel",
        role: "current",
        source,
        ...(observedAt ? { observedAt } : {}),
      }, address);
    }
  }

  const integrations = asRecord(record.integrations ?? record.integration_data ?? record.data);
  for (const [integrationId, integrationValue] of Object.entries(integrations)) {
    const integration = asRecord(integrationValue);
    const { namespace, integrationType, shopDomain } = integrationNamespace(integrationId, integration);
    const customerData = asRecord(integration.customer);
    const customerSource = `integration:${integrationId}.customer`;
    const identityBase = {
      namespace,
      integrationId,
      integrationType,
      shopDomain,
      source: customerSource,
      ...(observedAt ? { observedAt } : {}),
    };
    pushIdentity(identities, {
      ...identityBase,
      objectType: "customer",
      role: "owner",
    }, customerData.id ?? customerData.customer_id);
    pushIdentity(identities, {
      ...identityBase,
      objectType: "external_customer",
      role: "owner",
    }, integration.external_id ?? customerData.external_id);
    addEmail(emails, customerData.email, `${customerSource}.email`, "shopify_customer", observedAt);
    addPhone(phones, customerData.phone, `${customerSource}.phone`, "shopify_customer", options.defaultCountry, observedAt);
    addName(names, combinedName(customerData), `${customerSource}.name`, "shopify_customer", observedAt);
    addAddress(addresses, customerData.default_address, `${customerSource}.default_address`, "shopify_customer_default", observedAt);
    for (const [addressIndex, address] of (Array.isArray(customerData.addresses) ? customerData.addresses : []).entries()) {
      addAddress(addresses, address, `${customerSource}.addresses[${addressIndex}]`, "shopify_customer_address", observedAt);
    }

    for (const [orderIndex, orderValue] of (Array.isArray(integration.orders) ? integration.orders : []).entries()) {
      const order = asRecord(orderValue);
      const orderSource = `integration:${integrationId}.orders[${orderIndex}]`;
      pushIdentity(identities, {
        namespace,
        integrationId,
        integrationType,
        shopDomain,
        objectType: "order",
        role: "purchaser",
        source: orderSource,
        ...(readString(order.created_at) ? { observedAt: readString(order.created_at) } : {}),
      }, order.id ?? order.order_id);
      addEmail(emails, order.contact_email ?? order.email, `${orderSource}.contact_email`, "order_purchaser", readString(order.created_at));
      addPhone(phones, order.phone, `${orderSource}.phone`, "order_purchaser", options.defaultCountry, readString(order.created_at));
      addAddress(addresses, order.billing_address, `${orderSource}.billing_address`, "billing", readString(order.created_at));
      addAddress(addresses, order.shipping_address, `${orderSource}.shipping_address`, "shipping", readString(order.created_at));
    }
  }

  return {
    kind: "customer",
    customerId,
    ...(createdDatetime ? { createdDatetime } : {}),
    ...(updatedDatetime ? { updatedDatetime } : {}),
    emails,
    phones,
    names,
    addresses,
    identities,
  };
}

function sourceFrom(record: Record<string, unknown>): Record<string, unknown> {
  const source = asRecord(record.source);
  return asRecord(source.from ?? source.sender);
}

function orderReferences(text: string | undefined): string[] {
  if (!text) return [];
  const values = new Set<string>();
  const pattern = /(?:\border\s*#?\s*|#)(\d{4,8})\b/gi;
  for (const match of text.matchAll(pattern)) values.add(match[1]);
  return [...values].sort();
}

export function extractMessageMatchRecord(
  message: unknown,
  options: { customerId?: number; spam: boolean; trashed?: boolean; defaultCountry: string },
): MessageMatchRecord {
  const record = asRecord(message);
  const messageId = Number(record.id);
  const ticketId = Number(record.ticket_id);
  if (!Number.isInteger(messageId) || !Number.isInteger(ticketId)) {
    throw new Error("message match record requires numeric message and ticket ids");
  }
  const quarantineReasons: string[] = [];
  if (record.from_agent === true) quarantineReasons.push("agent_message");
  if (record.public === false) quarantineReasons.push("internal_message");
  if (options.spam) quarantineReasons.push("spam_ticket");
  if (options.trashed) quarantineReasons.push("trashed_ticket");
  if (!options.customerId) quarantineReasons.push("unmapped_customer");
  const positiveEligible = quarantineReasons.length === 0;
  const emails: Array<SourcedValue<EmailEvidence>> = [];
  const phones: Array<SourcedValue<PhoneEvidence>> = [];
  const identities: IdentityEvidence[] = [];
  const createdDatetime = readString(record.created_datetime);

  if (positiveEligible) {
    const sources = [
      { value: asRecord(record.sender), source: "message.sender" },
      { value: sourceFrom(record), source: "message.source.from" },
      { value: asRecord(record.auth_customer_identity), source: "message.auth_customer_identity" },
    ];
    const channel = (readString(record.channel) ?? "unknown").toLowerCase();
    const integrationId = readString(record.integration_id) ?? "unknown";
    for (const source of sources) {
      const address = readField(source.value, ["address", "email", "phone"]);
      addEmail(emails, source.value.email ?? (channel === "email" ? address : undefined), source.source, "historical_sender", createdDatetime);
      addPhone(phones, source.value.phone ?? ((channel === "phone" || channel === "sms") ? address : undefined), source.source, "historical_sender", options.defaultCountry, createdDatetime);
      if (address && !normaliseEmailEvidence(address) && !normalisePhoneEvidence(address, options.defaultCountry)) {
        pushIdentity(identities, {
          namespace: `${integrationId}|message|${channel}`,
          integrationId,
          integrationType: channel,
          shopDomain: "none",
          objectType: "channel",
          role: "historical_sender",
          source: source.source,
          ...(createdDatetime ? { observedAt: createdDatetime } : {}),
        }, address);
      }
    }
  }

  return {
    kind: "message",
    messageId,
    ticketId,
    ...(options.customerId ? { customerId: options.customerId } : {}),
    ...(createdDatetime ? { createdDatetime } : {}),
    positiveEligible,
    quarantineReasons,
    emails,
    phones,
    identities,
    orderReferences: positiveEligible
      ? orderReferences(readString(record.stripped_text) ?? readString(record.body_text))
      : [],
  };
}
