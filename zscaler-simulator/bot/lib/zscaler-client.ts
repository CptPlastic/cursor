export type ZscalerOperation =
  | "zia.urlLookup"
  | "zia.listUrlFilteringRules"
  | "zia.listUrlCategories"
  | "zia.listDlpDictionaries"
  | "zpa.listApplicationSegments"
  | "zpa.listAccessPolicyRules";

export type ZscalerConfig = {
  clientId: string;
  clientSecret: string;
  vanityDomain: string;
  cloud: string | null;
  customerId: string | null;
};

export type ConfigResult =
  | { ok: true; config: ZscalerConfig }
  | { ok: false; missing: boolean; error: string };

export type JsonValue =
  | null
  | string
  | number
  | boolean
  | JsonValue[]
  | { [key: string]: JsonValue };

export type ZscalerCallResult = {
  configured: boolean;
  operation: ZscalerOperation;
  ok: boolean;
  status: number | null;
  data: JsonValue;
  truncated: boolean;
  error: string | null;
};

const CLOUDS = new Set([
  "zscaler",
  "zscalerone",
  "zscalertwo",
  "zscalerthree",
  "zscloud",
  "zscalerbeta",
  "zscalerten",
  "zspreview",
  "beta",
]);

const VANITY = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const WINDOW_MS = 60_000;
const MAX_CALLS = 20;
const BODY_LIMIT = 80_000;

const callTimes: number[] = [];
let cachedToken: { key: string; token: string; exp: number } | null = null;

export function loadConfig(env: NodeJS.ProcessEnv): ConfigResult {
  const clientId = env.ZSCALER_CLIENT_ID?.trim() ?? "";
  const clientSecret = env.ZSCALER_CLIENT_SECRET?.trim() ?? "";
  const vanityDomain = env.ZSCALER_VANITY_DOMAIN?.trim().toLowerCase() ?? "";
  if (clientId === "" || clientSecret === "" || vanityDomain === "") {
    return {
      ok: false,
      missing: true,
      error: "Zscaler credentials are not configured. Set ZSCALER_CLIENT_ID, ZSCALER_CLIENT_SECRET, and ZSCALER_VANITY_DOMAIN.",
    };
  }
  if (!VANITY.test(vanityDomain)) {
    return { ok: false, missing: false, error: "ZSCALER_VANITY_DOMAIN must be one hostname label, such as acme." };
  }
  const cloudRaw = env.ZSCALER_CLOUD?.trim().toLowerCase() ?? "";
  if (cloudRaw !== "" && cloudRaw !== "production" && !CLOUDS.has(cloudRaw)) {
    return { ok: false, missing: false, error: "ZSCALER_CLOUD is not a supported Zscaler cloud name." };
  }
  const customerId = env.ZSCALER_CUSTOMER_ID?.trim() ?? "";
  if (customerId !== "" && !/^[0-9]+$/.test(customerId)) {
    return { ok: false, missing: false, error: "ZSCALER_CUSTOMER_ID must be numeric." };
  }
  return {
    ok: true,
    config: {
      clientId,
      clientSecret,
      vanityDomain,
      cloud: cloudRaw === "" || cloudRaw === "production" ? null : cloudRaw,
      customerId: customerId === "" ? null : customerId,
    },
  };
}

function apiOrigin(cloud: string | null): string {
  if (cloud === null) return "https://api.zsapi.net";
  if (cloud === "beta") return "https://api.beta.zsapi.net";
  return `https://api.${cloud}.zsapi.net`;
}

function assertOfficial(url: string): void {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") throw new Error("Refusing a non-HTTPS Zscaler URL.");
  const host = parsed.hostname;
  const official = host === "api.zsapi.net"
    || host === "api.beta.zsapi.net"
    || /^api\.(?:zscaler|zscalerone|zscalertwo|zscalerthree|zscloud|zscalerbeta|zscalerten|zspreview)\.zsapi\.net$/.test(host)
    || /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.zslogin\.net$/.test(host);
  if (!official) throw new Error("Refusing a host outside the Zscaler OneAPI allowlist.");
}

function takeRateSlot(): boolean {
  const now = Date.now();
  while (callTimes.length > 0 && (callTimes[0] ?? 0) <= now - WINDOW_MS) callTimes.shift();
  if (callTimes.length >= MAX_CALLS) return false;
  callTimes.push(now);
  return true;
}

function asJson(value: unknown): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (Array.isArray(value)) return value.map(asJson);
  if (typeof value === "object") {
    const out: { [key: string]: JsonValue } = {};
    for (const [key, entry] of Object.entries(value)) out[key] = asJson(entry);
    return out;
  }
  return null;
}

function clip(data: unknown, secret: string): { data: JsonValue; truncated: boolean } {
  let text: string;
  try {
    text = JSON.stringify(data) ?? "null";
  } catch {
    return { data: null, truncated: false };
  }
  text = text.split(secret).join("[redacted]");
  if (text.length <= BODY_LIMIT) {
    try {
      return { data: asJson(JSON.parse(text) as unknown), truncated: false };
    } catch {
      return { data: { preview: text.slice(0, 500) }, truncated: false };
    }
  }
  return { data: { preview: text.slice(0, BODY_LIMIT) }, truncated: true };
}

async function accessToken(config: ZscalerConfig): Promise<string> {
  const key = `${config.vanityDomain}:${config.clientId}`;
  if (cachedToken !== null && cachedToken.key === key && cachedToken.exp > Date.now() + 30_000) {
    return cachedToken.token;
  }
  const url = `https://${config.vanityDomain}.zslogin.net/oauth2/v1/token`;
  assertOfficial(url);
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: config.clientId,
      client_secret: config.clientSecret,
      audience: "https://api.zscaler.com",
    }),
    signal: AbortSignal.timeout(15_000),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Zscaler token request failed with HTTP ${response.status}.`);
  }
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== "object" || parsed === null || !("access_token" in parsed)) {
    throw new Error("Zscaler token response did not include an access token.");
  }
  const token = (parsed as { access_token?: unknown }).access_token;
  const expiresIn = (parsed as { expires_in?: unknown }).expires_in;
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("Zscaler token response did not include an access token.");
  }
  const lifetime = typeof expiresIn === "number" ? expiresIn : 300;
  cachedToken = { key, token, exp: Date.now() + lifetime * 1000 };
  return token;
}

function requestFor(config: ZscalerConfig, operation: ZscalerOperation, urls: string[] | undefined): { url: string; method: "GET" | "POST"; body?: string } {
  const origin = apiOrigin(config.cloud);
  if (operation === "zia.urlLookup") {
    return { url: `${origin}/zia/api/v1/urlLookup`, method: "POST", body: JSON.stringify(urls ?? []) };
  }
  if (operation === "zia.listUrlFilteringRules") {
    return { url: `${origin}/zia/api/v1/urlFilteringRules`, method: "GET" };
  }
  if (operation === "zia.listUrlCategories") {
    return { url: `${origin}/zia/api/v1/urlCategories`, method: "GET" };
  }
  if (operation === "zia.listDlpDictionaries") {
    return { url: `${origin}/zia/api/v1/dlpDictionaries`, method: "GET" };
  }
  if (config.customerId === null) {
    throw new Error("ZPA reads need ZSCALER_CUSTOMER_ID.");
  }
  const customerId = config.customerId;
  if (operation === "zpa.listApplicationSegments") {
    return { url: `${origin}/zpa/mgmtconfig/v1/admin/customers/${customerId}/application`, method: "GET" };
  }
  return {
    url: `${origin}/zpa/mgmtconfig/v1/admin/customers/${customerId}/policySet/rules?policyType=ACCESS_POLICY`,
    method: "GET",
  };
}

export async function callZscaler(
  env: NodeJS.ProcessEnv,
  operation: ZscalerOperation,
  urls?: string[],
): Promise<ZscalerCallResult> {
  const loaded = loadConfig(env);
  if (!loaded.ok) {
    return {
      configured: false,
      operation,
      ok: false,
      status: null,
      data: null,
      truncated: false,
      error: loaded.error,
    };
  }
  if (!takeRateSlot()) {
    return {
      configured: true,
      operation,
      ok: false,
      status: 429,
      data: null,
      truncated: false,
      error: "Local rate limit reached. Wait a minute before another Zscaler API call.",
    };
  }
  try {
    const request = requestFor(loaded.config, operation, urls);
    assertOfficial(request.url);
    const token = await accessToken(loaded.config);
    const response = await fetch(request.url, {
      method: request.method,
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        ...(request.body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: request.body,
      signal: AbortSignal.timeout(15_000),
    });
    const text = await response.text();
    const redacted = text.split(loaded.config.clientSecret).join("[redacted]");
    let data: JsonValue = null;
    if (redacted.length > 0) {
      try {
        data = asJson(JSON.parse(redacted) as unknown);
      } catch {
        data = { preview: redacted.slice(0, 500) };
      }
    }
    const clipped = clip(data, loaded.config.clientSecret);
    if (!response.ok) {
      return {
        configured: true,
        operation,
        ok: false,
        status: response.status,
        data: clipped.data,
        truncated: clipped.truncated,
        error: `Zscaler returned HTTP ${response.status}.`,
      };
    }
    return {
      configured: true,
      operation,
      ok: true,
      status: response.status,
      data: clipped.data,
      truncated: clipped.truncated,
      error: null,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Zscaler request failed.";
    return {
      configured: true,
      operation,
      ok: false,
      status: null,
      data: null,
      truncated: false,
      error: message.split(loaded.config.clientSecret).join("[redacted]"),
    };
  }
}
