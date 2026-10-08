import { hostFromInput } from "./policy.js";

export type ZpaSegment = {
  id: string;
  name: string;
  enabled: boolean;
  hosts: string[];
  segmentGroupId: string | null;
  tcpPorts: string[];
  udpPorts: string[];
};

export type ZpaOperand = {
  type: string;
  lhs: string | null;
  rhs: string | null;
  values: string[];
};

export type ZpaCondition = {
  operator: "AND" | "OR";
  operands: ZpaOperand[];
};

export type ZpaPolicy = {
  id: string;
  name: string;
  order: number;
  action: string;
  enabled: boolean;
  conditions: ZpaCondition[];
};

export type ZpaIntegrationMap = {
  source: "mock" | "zscaler";
  complete: boolean;
  segmentCount: number;
  policyCount: number;
  segments: Array<ZpaSegment & {
    policyIds: string[];
    policyNames: string[];
  }>;
  policies: Array<{
    id: string;
    name: string;
    order: number;
    action: string;
    enabled: boolean;
    segmentIds: string[];
    segmentGroupIds: string[];
    identityValues: string[];
    postureProfileIds: string[];
    unsupportedCriteria: string[];
  }>;
  uncoveredSegmentIds: string[];
  orphanPolicyTargets: string[];
  warnings: string[];
};

export type IntegratedAccessDecision = {
  action: "ALLOW" | "BLOCK";
  application: string;
  segment: string | null;
  segmentSource: "zscaler" | "none";
  policySource: "zscaler";
  matchedPolicy: { id: string; name: string; order: number; action: string } | null;
  evaluatedPolicies: number;
  unresolvedCriteria: string[];
  reason: string;
  warning: string | null;
};

const MOCK_SEGMENTS: ZpaSegment[] = [
  {
    id: "mock-payroll",
    name: "Payroll",
    enabled: true,
    hosts: ["payroll.internal"],
    segmentGroupId: "mock-finance-apps",
    tcpPorts: ["443", "443"],
    udpPorts: [],
  },
  {
    id: "mock-wiki",
    name: "Wiki",
    enabled: true,
    hosts: ["wiki.internal"],
    segmentGroupId: "mock-business-apps",
    tcpPorts: ["443", "443"],
    udpPorts: [],
  },
  {
    id: "mock-admin-ssh",
    name: "Admin SSH",
    enabled: true,
    hosts: ["ssh.admin.internal"],
    segmentGroupId: "mock-admin-apps",
    tcpPorts: ["22", "22"],
    udpPorts: [],
  },
];

const MOCK_POLICIES: ZpaPolicy[] = [
  {
    id: "mock-finance-payroll",
    name: "Finance can use payroll",
    order: 1,
    action: "ALLOW",
    enabled: true,
    conditions: [
      {
        operator: "OR",
        operands: [{ type: "APP", lhs: "id", rhs: "mock-payroll", values: ["mock-payroll"] }],
      },
      {
        operator: "OR",
        operands: [{ type: "SCIM_GROUP", lhs: "group", rhs: "Finance", values: ["Finance"] }],
      },
      {
        operator: "OR",
        operands: [{ type: "POSTURE", lhs: "id", rhs: "managed", values: ["managed"] }],
      },
    ],
  },
  {
    id: "mock-wiki-all",
    name: "Authenticated users can use the wiki",
    order: 2,
    action: "ALLOW",
    enabled: true,
    conditions: [
      {
        operator: "OR",
        operands: [{ type: "APP", lhs: "id", rhs: "mock-wiki", values: ["mock-wiki"] }],
      },
    ],
  },
  {
    id: "mock-netops-ssh",
    name: "NetOps can use admin SSH",
    order: 3,
    action: "ALLOW",
    enabled: true,
    conditions: [
      {
        operator: "OR",
        operands: [{ type: "APP_GROUP", lhs: "id", rhs: "mock-admin-apps", values: ["mock-admin-apps"] }],
      },
      {
        operator: "OR",
        operands: [{ type: "SAML", lhs: "group", rhs: "NetOps", values: ["NetOps"] }],
      },
      {
        operator: "OR",
        operands: [{ type: "POSTURE", lhs: "id", rhs: "managed", values: ["managed"] }],
      },
    ],
  },
  {
    id: "mock-default-deny",
    name: "Default deny",
    order: 999,
    action: "DENY",
    enabled: true,
    conditions: [],
  },
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function collection(data: unknown): unknown[] {
  if (Array.isArray(data)) return data;
  if (!isRecord(data)) return [];
  for (const key of ["list", "items", "data", "results"]) {
    if (Array.isArray(data[key])) return data[key];
  }
  return [];
}

function text(value: unknown): string | null {
  if (typeof value === "string" && value.trim() !== "") return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

function field(record: Record<string, unknown>, ...keys: string[]): string | null {
  for (const key of keys) {
    const found = text(record[key]);
    if (found !== null) return found;
  }
  return null;
}

function boolField(record: Record<string, unknown>, defaultValue: boolean, ...keys: string[]): boolean {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "boolean") return value;
    if (typeof value === "string") {
      if (value.toLowerCase() === "true" || value.toUpperCase() === "ENABLED") return true;
      if (value.toLowerCase() === "false" || value.toUpperCase() === "DISABLED") return false;
    }
  }
  return defaultValue;
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    const one = text(value);
    return one === null ? [] : [one];
  }
  const values: string[] = [];
  for (const item of value) {
    const direct = text(item);
    if (direct !== null) {
      values.push(direct);
      continue;
    }
    if (isRecord(item)) {
      const nested = field(item, "id", "value", "rhs", "name");
      if (nested !== null) values.push(nested);
    }
  }
  return [...new Set(values)];
}

function nestedId(record: Record<string, unknown>, ...keys: string[]): string | null {
  for (const key of keys) {
    const value = record[key];
    const direct = text(value);
    if (direct !== null) return direct;
    if (isRecord(value)) {
      const id = field(value, "id", "value");
      if (id !== null) return id;
    }
  }
  return null;
}

function totalPages(data: unknown): number {
  if (!isRecord(data)) return 1;
  const value = data.totalPages ?? data.total_pages;
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number(value) : 1;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 1;
}

function allPagesFetched(data: unknown): boolean {
  if (!isRecord(data)) return true;
  const pages = totalPages(data);
  const raw = data.fetchedPages ?? data.fetched_pages;
  if (raw === undefined) return pages <= 1;
  const fetched = typeof raw === "number" ? raw : typeof raw === "string" ? Number(raw) : 0;
  return Number.isFinite(fetched) && fetched >= pages;
}

export function normalizeSegments(data: unknown): { segments: ZpaSegment[]; complete: boolean } {
  const segments: ZpaSegment[] = [];
  for (const item of collection(data)) {
    if (!isRecord(item)) continue;
    const id = field(item, "id", "applicationId", "application_id");
    const name = field(item, "name");
    if (id === null || name === null) continue;
    const hosts = stringList(item.domainNames ?? item.domain_names)
      .map((value) => hostFromInput(value))
      .filter((value): value is string => value !== null);
    segments.push({
      id,
      name,
      enabled: boolField(item, true, "enabled", "state"),
      hosts: [...new Set(hosts)],
      segmentGroupId: nestedId(item, "segmentGroupId", "segment_group_id", "segmentGroupDTO", "segmentGroup"),
      tcpPorts: stringList(item.tcpPortRanges ?? item.tcp_port_ranges),
      udpPorts: stringList(item.udpPortRanges ?? item.udp_port_ranges),
    });
  }
  return { segments, complete: allPagesFetched(data) };
}

function operandValues(record: Record<string, unknown>): string[] {
  const values = stringList(record.values);
  const entry = record.entryValues ?? record.entry_values;
  if (isRecord(entry)) {
    values.push(...stringList(entry.values));
    const rhs = field(entry, "rhs", "value");
    if (rhs !== null) values.push(rhs);
  }
  const rhs = field(record, "rhs");
  if (rhs !== null) values.push(rhs);
  return [...new Set(values)];
}

function normalizeOperand(value: unknown): ZpaOperand | null {
  if (!isRecord(value)) return null;
  const entry = isRecord(value.entryValues)
    ? value.entryValues
    : isRecord(value.entry_values)
      ? value.entry_values
      : null;
  const type = field(value, "objectType", "object_type", "type")?.toUpperCase() ?? null;
  if (type === null) return null;
  return {
    type,
    lhs: field(value, "lhs") ?? (entry === null ? null : field(entry, "lhs")),
    rhs: field(value, "rhs") ?? (entry === null ? null : field(entry, "rhs")),
    values: operandValues(value),
  };
}

export function normalizePolicies(data: unknown): { policies: ZpaPolicy[]; complete: boolean } {
  const policies: ZpaPolicy[] = [];
  for (const item of collection(data)) {
    if (!isRecord(item)) continue;
    const id = field(item, "id", "ruleId", "rule_id");
    const name = field(item, "name");
    if (id === null || name === null) continue;
    const rawConditions = Array.isArray(item.conditions) ? item.conditions : [];
    const conditions: ZpaCondition[] = [];
    for (const rawCondition of rawConditions) {
      if (!isRecord(rawCondition)) continue;
      const operands = (Array.isArray(rawCondition.operands) ? rawCondition.operands : [])
        .map(normalizeOperand)
        .filter((operand): operand is ZpaOperand => operand !== null);
      if (operands.length === 0) continue;
      conditions.push({
        operator: field(rawCondition, "operator")?.toUpperCase() === "AND" ? "AND" : "OR",
        operands,
      });
    }
    const orderText = field(item, "ruleOrder", "rule_order", "order", "priority");
    const parsedOrder = orderText === null ? Number.NaN : Number(orderText);
    policies.push({
      id,
      name,
      order: Number.isFinite(parsedOrder) ? parsedOrder : 1000,
      action: field(item, "action")?.toUpperCase() ?? "DENY",
      enabled: boolField(item, true, "enabled", "state"),
      conditions,
    });
  }
  return {
    policies: policies.sort((left, right) => left.order - right.order),
    complete: allPagesFetched(data),
  };
}

function valuesFor(operand: ZpaOperand): string[] {
  const values = [...operand.values];
  if (operand.rhs !== null) values.push(operand.rhs);
  return [...new Set(values)];
}

function policyTargets(policy: ZpaPolicy, type: "APP" | "APP_GROUP"): string[] {
  return [...new Set(policy.conditions.flatMap((condition) =>
    condition.operands
      .filter((operand) => operand.type === type)
      .flatMap(valuesFor)
  ))];
}

function policyValues(policy: ZpaPolicy, types: string[]): string[] {
  return [...new Set(policy.conditions.flatMap((condition) =>
    condition.operands
      .filter((operand) => types.includes(operand.type))
      .flatMap(valuesFor)
  ))];
}

export function buildIntegrationMap(
  source: "mock" | "zscaler",
  segments: ZpaSegment[],
  policies: ZpaPolicy[],
  complete: boolean,
  warnings: string[] = [],
): ZpaIntegrationMap {
  const enabledSegments = segments.filter((segment) => segment.enabled);
  const enabledPolicies = policies.filter((policy) => policy.enabled);
  const segmentIds = new Set(enabledSegments.map((segment) => segment.id));
  const segmentGroupIds = new Set(
    enabledSegments
      .map((segment) => segment.segmentGroupId)
      .filter((id): id is string => id !== null),
  );
  const policySummary = enabledPolicies.map((policy) => {
    const unsupportedCriteria = [...new Set(policy.conditions.flatMap((condition) =>
      condition.operands
        .map((operand) => operand.type)
        .filter((type) => ![
          "APP",
          "APP_GROUP",
          "SAML",
          "SAML_GROUP",
          "SCIM",
          "SCIM_GROUP",
          "POSTURE",
          "PLATFORM",
          "CLIENT_TYPE",
        ].includes(type))
    ))];
    return {
      id: policy.id,
      name: policy.name,
      order: policy.order,
      action: policy.action,
      enabled: policy.enabled,
      segmentIds: policyTargets(policy, "APP"),
      segmentGroupIds: policyTargets(policy, "APP_GROUP"),
      identityValues: policyValues(policy, ["SAML", "SAML_GROUP", "SCIM", "SCIM_GROUP"]),
      postureProfileIds: policyValues(policy, ["POSTURE"]),
      unsupportedCriteria,
    };
  });
  const broadPolicyIds = new Set(
    policySummary
      .filter((policy) => policy.segmentIds.length === 0 && policy.segmentGroupIds.length === 0)
      .map((policy) => policy.id),
  );
  const mappedSegments = enabledSegments.map((segment) => {
    const linked = policySummary.filter((policy) =>
      broadPolicyIds.has(policy.id)
      || policy.segmentIds.includes(segment.id)
      || (segment.segmentGroupId !== null && policy.segmentGroupIds.includes(segment.segmentGroupId))
    );
    return {
      ...segment,
      policyIds: linked.map((policy) => policy.id),
      policyNames: linked.map((policy) => policy.name),
    };
  });
  const orphanPolicyTargets = [...new Set(policySummary.flatMap((policy) => [
    ...policy.segmentIds.filter((id) => !segmentIds.has(id)),
    ...policy.segmentGroupIds.filter((id) => !segmentGroupIds.has(id)),
  ]))];
  return {
    source,
    complete,
    segmentCount: enabledSegments.length,
    policyCount: enabledPolicies.length,
    segments: mappedSegments,
    policies: policySummary,
    uncoveredSegmentIds: mappedSegments
      .filter((segment) => segment.policyIds.length === 0)
      .map((segment) => segment.id),
    orphanPolicyTargets,
    warnings,
  };
}

export function mockIntegrationMap(): ZpaIntegrationMap {
  return buildIntegrationMap("mock", MOCK_SEGMENTS, MOCK_POLICIES, true);
}

function same(left: string, right: string): boolean {
  return left.trim().toLowerCase() === right.trim().toLowerCase();
}

function hostMatches(host: string, patterns: string[]): boolean {
  return patterns.some((pattern) => host === pattern || host.endsWith(`.${pattern}`));
}

function findSegment(application: string, segments: ZpaSegment[]): ZpaSegment | null {
  const host = hostFromInput(application);
  return segments.find((segment) =>
    same(segment.name, application)
    || (host !== null && hostMatches(host, segment.hosts))
  ) ?? null;
}

type OperandResult = { matched: boolean; unresolved: string | null };

function evaluateOperand(
  operand: ZpaOperand,
  input: {
    segment: ZpaSegment;
    user: string;
    groups: string[];
    postureProfileIds: string[];
    managedDevice: boolean;
    platform: string | null;
    clientType: string | null;
  },
): OperandResult {
  const values = valuesFor(operand);
  if (operand.type === "APP") {
    return { matched: values.includes(input.segment.id), unresolved: null };
  }
  if (operand.type === "APP_GROUP") {
    return {
      matched: input.segment.segmentGroupId !== null && values.includes(input.segment.segmentGroupId),
      unresolved: null,
    };
  }
  if (["SAML", "SAML_GROUP", "SCIM", "SCIM_GROUP"].includes(operand.type)) {
    const identity = [input.user, ...input.groups];
    return { matched: values.some((value) => identity.some((candidate) => same(value, candidate))), unresolved: null };
  }
  if (operand.type === "POSTURE") {
    const matched = values.some((value) =>
      input.postureProfileIds.includes(value)
      || (input.managedDevice && same(value, "managed"))
    );
    return {
      matched,
      unresolved: matched || input.postureProfileIds.length > 0 || input.managedDevice
        ? null
        : "POSTURE",
    };
  }
  if (operand.type === "PLATFORM") {
    if (input.platform === null) return { matched: false, unresolved: "PLATFORM" };
    const platform = input.platform;
    return {
      matched: values.some((value) => same(value, platform))
        || (operand.lhs !== null && same(operand.lhs, platform) && values.some((value) => same(value, "true"))),
      unresolved: null,
    };
  }
  if (operand.type === "CLIENT_TYPE") {
    if (input.clientType === null) return { matched: false, unresolved: "CLIENT_TYPE" };
    const clientType = input.clientType;
    return { matched: values.some((value) => same(value, clientType)), unresolved: null };
  }
  return { matched: false, unresolved: operand.type };
}

export function evaluateIntegratedAccess(input: {
  application: string;
  user: string;
  groups: string[];
  managedDevice: boolean;
  postureProfileIds: string[];
  platform: string | null;
  clientType: string | null;
  segments: ZpaSegment[];
  policies: ZpaPolicy[];
  warning: string | null;
}): IntegratedAccessDecision {
  const segment = findSegment(input.application, input.segments.filter((candidate) => candidate.enabled));
  if (segment === null) {
    return {
      action: "BLOCK",
      application: input.application,
      segment: null,
      segmentSource: "none",
      policySource: "zscaler",
      matchedPolicy: null,
      evaluatedPolicies: 0,
      unresolvedCriteria: [],
      reason: "No enabled application segment matched. Private access defaults to deny.",
      warning: input.warning,
    };
  }

  const unresolved = new Set<string>();
  let evaluatedPolicies = 0;
  for (const policy of [...input.policies].filter((candidate) => candidate.enabled).sort((a, b) => a.order - b.order)) {
    evaluatedPolicies += 1;
    let policyMatched = true;
    for (const condition of policy.conditions) {
      const results = condition.operands.map((operand) => evaluateOperand(operand, { ...input, segment }));
      for (const result of results) {
        if (result.unresolved !== null) unresolved.add(result.unresolved);
      }
      const conditionMatched = condition.operator === "AND"
        ? results.every((result) => result.matched)
        : results.some((result) => result.matched);
      if (!conditionMatched) {
        policyMatched = false;
        break;
      }
    }
    if (!policyMatched) continue;
    const allowed = policy.action === "ALLOW";
    return {
      action: allowed ? "ALLOW" : "BLOCK",
      application: input.application,
      segment: segment.name,
      segmentSource: "zscaler",
      policySource: "zscaler",
      matchedPolicy: {
        id: policy.id,
        name: policy.name,
        order: policy.order,
        action: policy.action,
      },
      evaluatedPolicies,
      unresolvedCriteria: [...unresolved],
      reason: allowed
        ? `Matched live access policy ${policy.name}.`
        : `Matched live policy ${policy.name}; action ${policy.action} is enforced as block.`,
      warning: input.warning,
    };
  }
  return {
    action: "BLOCK",
    application: input.application,
    segment: segment.name,
    segmentSource: "zscaler",
    policySource: "zscaler",
    matchedPolicy: null,
    evaluatedPolicies,
    unresolvedCriteria: [...unresolved],
    reason: unresolved.size > 0
      ? "No policy could be fully evaluated with the supplied attributes. Private access defaults to deny."
      : "No access policy matched. Private access defaults to deny.",
    warning: input.warning,
  };
}
