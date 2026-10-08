export type WebAction = "ALLOW" | "BLOCK" | "CAUTION" | "ISOLATE";

export type AccessAction = "ALLOW" | "BLOCK";

export type WebRule = {
  id: string;
  name: string;
  order: number;
  action: WebAction;
  categories: string[];
  hosts: string[];
};

export type WebDecision = {
  action: WebAction;
  host: string;
  categories: string[];
  categorySource: "mock" | "zscaler";
  rulesSource: "mock" | "zscaler";
  matchedRule: { id: string; name: string; order: number } | null;
  reason: string;
  warning: string | null;
};

export type AppSegment = {
  name: string;
  hosts: string[];
  requiredGroups: string[];
  requireManaged: boolean;
  requireMfa: boolean;
};

export type AccessDecision = {
  action: AccessAction;
  application: string;
  segment: string | null;
  segmentSource: "mock" | "zscaler" | "none";
  postureSource: "local";
  reason: string;
  checks: {
    identity: boolean;
    group: boolean;
    managedDevice: boolean;
    mfa: boolean;
  };
  warning: string | null;
};

export type DlpMatch = {
  dictionary: string;
  severity: "low" | "high";
  count: number;
};

export type DlpDecision = {
  action: AccessAction;
  source: "local-dictionaries";
  matches: DlpMatch[];
  reason: string;
};

const MOCK_HOSTS: Record<string, string[]> = {
  "malware.example.test": ["MALWARE"],
  "phishing.example.test": ["PHISHING"],
  "vpn.example.test": ["ANONYMIZER"],
  "facebook.com": ["SOCIAL_NETWORKING"],
  "youtube.com": ["STREAMING_MEDIA"],
  "dropbox.com": ["FILE_SHARE"],
  "news.example.test": ["NEWS_AND_MEDIA"],
  "intranet.example.test": ["CUSTOM_BUSINESS"],
};

export const MOCK_WEB_RULES: WebRule[] = [
  {
    id: "allow-intranet",
    name: "Allow intranet",
    order: 1,
    action: "ALLOW",
    categories: ["CUSTOM_BUSINESS"],
    hosts: ["intranet.example.test"],
  },
  {
    id: "block-threats",
    name: "Block security threats",
    order: 2,
    action: "BLOCK",
    categories: ["MALWARE", "PHISHING", "BOTNET", "ANONYMIZER", "CRYPTOMINING"],
    hosts: [],
  },
  {
    id: "block-liability",
    name: "Block adult content and gambling",
    order: 3,
    action: "BLOCK",
    categories: ["ADULT_CONTENT", "GAMBLING"],
    hosts: [],
  },
  {
    id: "caution-social",
    name: "Caution social networking and streaming",
    order: 4,
    action: "CAUTION",
    categories: ["SOCIAL_NETWORKING", "STREAMING_MEDIA"],
    hosts: [],
  },
  {
    id: "isolate-fileshare",
    name: "Isolate file sharing",
    order: 5,
    action: "ISOLATE",
    categories: ["FILE_SHARE"],
    hosts: [],
  },
  {
    id: "allow-business",
    name: "Allow news and business",
    order: 6,
    action: "ALLOW",
    categories: ["NEWS_AND_MEDIA", "BUSINESS_AND_ECONOMY"],
    hosts: [],
  },
  {
    id: "caution-unknown",
    name: "Caution uncategorized",
    order: 100,
    action: "CAUTION",
    categories: ["UNKNOWN"],
    hosts: [],
  },
];

export const MOCK_APP_SEGMENTS: AppSegment[] = [
  {
    name: "Payroll",
    hosts: ["payroll.internal"],
    requiredGroups: ["Finance"],
    requireManaged: true,
    requireMfa: true,
  },
  {
    name: "Wiki",
    hosts: ["wiki.internal"],
    requiredGroups: [],
    requireManaged: false,
    requireMfa: false,
  },
  {
    name: "Admin SSH",
    hosts: ["ssh.admin.internal"],
    requiredGroups: ["NetOps"],
    requireManaged: true,
    requireMfa: true,
  },
];

export function hostFromInput(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > 1024 || trimmed.includes("@") || /\s/.test(trimmed)) {
    return null;
  }
  let host = trimmed;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      return null;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    if (parsed.username !== "" || parsed.password !== "") return null;
    host = parsed.hostname;
  } else {
    host = trimmed.split("/")[0] ?? "";
    host = host.replace(/:\d+$/, "");
  }
  host = host.toLowerCase().replace(/\.$/, "");
  if (!/^[a-z0-9.-]+$/.test(host) || host.startsWith(".") || host.includes("..")) return null;
  return host;
}

export function isFixtureHost(host: string): boolean {
  return host.endsWith(".test") || host.endsWith(".example") || host.endsWith(".invalid");
}

export function mockCategories(host: string): string[] {
  let cursor = host;
  while (cursor.length > 0) {
    const found = MOCK_HOSTS[cursor];
    if (found !== undefined) return [...found];
    const dot = cursor.indexOf(".");
    if (dot === -1) break;
    cursor = cursor.slice(dot + 1);
  }
  return ["UNKNOWN"];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isWebAction(value: string): value is WebAction {
  return value === "ALLOW" || value === "BLOCK" || value === "CAUTION" || value === "ISOLATE";
}

function normCategory(value: string): string {
  return value.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

export function categoriesFromLookup(data: unknown): string[] | null {
  if (!Array.isArray(data) || data.length === 0) return null;
  const row = data.find(isRecord);
  if (row === undefined) return null;
  const bags = [row.urlClassifications, row.urlClassificationsWithSecurityAlert, row.categories];
  const categories: string[] = [];
  for (const bag of bags) {
    if (!Array.isArray(bag)) continue;
    for (const entry of bag) {
      if (typeof entry === "string") categories.push(entry);
      else if (isRecord(entry) && typeof entry.name === "string") categories.push(entry.name);
    }
  }
  const unique = [...new Set(categories.map((item) => item.trim()).filter((item) => item.length > 0))];
  return unique.length > 0 ? unique : ["UNKNOWN"];
}

export function rulesFromApi(data: unknown): WebRule[] | null {
  if (!Array.isArray(data)) return null;
  const rules: WebRule[] = [];
  for (const item of data) {
    if (!isRecord(item) || typeof item.action !== "string") continue;
    const action = item.action.toUpperCase();
    if (!isWebAction(action)) continue;
    const state = typeof item.state === "string" ? item.state.toUpperCase() : "ENABLED";
    if (state === "DISABLED") continue;
    const categories = Array.isArray(item.urlCategories)
      ? item.urlCategories.filter((entry): entry is string => typeof entry === "string")
      : [];
    const order = typeof item.order === "number" ? item.order : typeof item.rank === "number" ? item.rank : 1000;
    const id = item.id === undefined ? `rule-${order}` : String(item.id);
    const name = typeof item.name === "string" && item.name.length > 0 ? item.name : id;
    rules.push({ id, name, order, action, categories, hosts: [] });
  }
  if (rules.length === 0) return null;
  return rules.sort((left, right) => left.order - right.order);
}

function hostMatches(host: string, patterns: string[]): boolean {
  return patterns.some((pattern) => host === pattern || host.endsWith(`.${pattern}`));
}

function categoriesMatch(ruleCategories: string[], got: string[]): boolean {
  const gotSet = new Set(got.map(normCategory));
  return ruleCategories.some((category) => {
    const normalized = normCategory(category);
    return normalized === "ANY" || gotSet.has(normalized);
  });
}

export function decideWeb(host: string, categories: string[], rules: WebRule[]): {
  action: WebAction;
  matchedRule: { id: string; name: string; order: number } | null;
  reason: string;
} {
  const ordered = [...rules].sort((left, right) => left.order - right.order);
  for (const rule of ordered) {
    if (rule.hosts.length > 0 && !hostMatches(host, rule.hosts)) continue;
    if (rule.categories.length > 0 && !categoriesMatch(rule.categories, categories)) continue;
    if (rule.hosts.length === 0 && rule.categories.length === 0) continue;
    return {
      action: rule.action,
      matchedRule: { id: rule.id, name: rule.name, order: rule.order },
      reason: `Matched ${rule.name}.`,
    };
  }
  return {
    action: "CAUTION",
    matchedRule: null,
    reason: "No rule matched. Unmatched destinations stay at caution.",
  };
}

export function segmentsFromApi(data: unknown): { name: string; hosts: string[] }[] {
  const list = Array.isArray(data)
    ? data
    : isRecord(data) && Array.isArray(data.list)
      ? data.list
      : [];
  const segments: { name: string; hosts: string[] }[] = [];
  for (const item of list) {
    if (!isRecord(item)) continue;
    const enabled = item.enabled;
    if (enabled === false || enabled === "false") continue;
    const hosts: string[] = [];
    const push = (value: unknown) => {
      if (typeof value !== "string") return;
      const host = hostFromInput(value);
      if (host !== null) hosts.push(host);
    };
    if (Array.isArray(item.domainNames)) {
      for (const domain of item.domainNames) push(domain);
    }
    push(item.domain);
    if (hosts.length === 0 || typeof item.name !== "string") continue;
    segments.push({ name: item.name, hosts });
  }
  return segments;
}

function sameGroup(left: string, right: string): boolean {
  return left.trim().toLowerCase() === right.trim().toLowerCase();
}

export function findLocalSegment(application: string): AppSegment | undefined {
  const trimmed = application.trim();
  const host = hostFromInput(trimmed);
  return MOCK_APP_SEGMENTS.find((segment) => {
    if (segment.name.toLowerCase() === trimmed.toLowerCase()) return true;
    if (host === null) return false;
    return hostMatches(host, segment.hosts);
  });
}

export function decideAccess(input: {
  user: string;
  groups: string[];
  application: string;
  managedDevice: boolean;
  mfa: boolean;
  liveSegments: { name: string; hosts: string[] }[];
  liveWarning: string | null;
}): AccessDecision {
  const application = input.application.trim();
  const local = findLocalSegment(application);
  if (local !== undefined) {
    const identity = input.user.trim().length > 0;
    const group = local.requiredGroups.length === 0
      || local.requiredGroups.some((required) => input.groups.some((group) => sameGroup(group, required)));
    const managedDevice = !local.requireManaged || input.managedDevice;
    const mfa = !local.requireMfa || input.mfa;
    const allowed = identity && group && managedDevice && mfa;
    const failed = [
      identity ? null : "identity",
      group ? null : "group",
      managedDevice ? null : "managed device",
      mfa ? null : "MFA",
    ].filter((item): item is string => item !== null);
    return {
      action: allowed ? "ALLOW" : "BLOCK",
      application,
      segment: local.name,
      segmentSource: "mock",
      postureSource: "local",
      reason: allowed
        ? `${local.name} posture checks passed.`
        : `${local.name} blocked: ${failed.join(", ")} required.`,
      checks: { identity, group, managedDevice, mfa },
      warning: null,
    };
  }

  const host = hostFromInput(application);
  const live = input.liveSegments.find((segment) => {
    if (segment.name.toLowerCase() === application.toLowerCase()) return true;
    if (host === null) return false;
    return hostMatches(host, segment.hosts);
  });
  if (live !== undefined) {
    return {
      action: "BLOCK",
      application,
      segment: live.name,
      segmentSource: "zscaler",
      postureSource: "local",
      reason: "The tenant has this application segment. Access stays blocked until a local posture rule allows it.",
      checks: { identity: input.user.trim().length > 0, group: false, managedDevice: input.managedDevice, mfa: input.mfa },
      warning: input.liveWarning,
    };
  }

  return {
    action: "BLOCK",
    application,
    segment: null,
    segmentSource: "none",
    postureSource: "local",
    reason: "No application segment matched. Private access defaults to deny.",
    checks: {
      identity: input.user.trim().length > 0,
      group: false,
      managedDevice: input.managedDevice,
      mfa: input.mfa,
    },
    warning: input.liveWarning,
  };
}

function countPattern(text: string, pattern: RegExp): number {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const global = new RegExp(pattern.source, flags);
  return text.match(global)?.length ?? 0;
}

function luhnValid(digits: string): boolean {
  let sum = 0;
  let alternate = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = digits.charCodeAt(index) - 48;
    if (alternate) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

function countCardNumbers(text: string): number {
  const candidates = text.match(/\b(?:\d[ -]?){12,18}\d\b/g) ?? [];
  let count = 0;
  for (const candidate of candidates) {
    const digits = candidate.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19) continue;
    if (/^(\d)\1+$/.test(digits)) continue;
    if (luhnValid(digits)) count += 1;
  }
  return count;
}

export function classifyText(text: string): DlpDecision {
  const sample = text.slice(0, 20_000);
  const matches = [
    { dictionary: "US social security number", severity: "high" as const, count: countPattern(sample, /\b\d{3}-\d{2}-\d{4}\b/) },
    { dictionary: "payment card number", severity: "high" as const, count: countCardNumbers(sample) },
    { dictionary: "cloud access key", severity: "high" as const, count: countPattern(sample, /\bAKIA[0-9A-Z]{16}\b/) },
    { dictionary: "private key", severity: "high" as const, count: countPattern(sample, /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/) },
    { dictionary: "credential assignment", severity: "high" as const, count: countPattern(sample, /(?:password|passwd|secret)\s*[:=]\s*\S+/i) },
    { dictionary: "email address", severity: "low" as const, count: countPattern(sample, /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i) },
  ].filter((match) => match.count > 0);
  const blocked = matches.some((match) => match.severity === "high");
  return {
    action: blocked ? "BLOCK" : "ALLOW",
    source: "local-dictionaries",
    matches,
    reason: blocked
      ? "High-severity dictionary matched. Recommended action is block."
      : "No high-severity dictionary matched.",
  };
}
