import { defineTool } from "@cursor/bdk/tools";
import { z } from "zod";
import {
  buildIntegrationMap,
  mockIntegrationMap,
  normalizePolicies,
  normalizeSegments,
  type ZpaIntegrationMap,
} from "../lib/zpa-integration.js";
import { callZscalerPaginated, loadConfig } from "../lib/zscaler-client.js";

const INTEGRATION_READ_LIMIT = 2_000_000;

export default defineTool({
  description: "Build a normalized, read-only map of ZPA application segments to access policies. Useful for integration discovery, exports, coverage checks, and orphan-target checks.",
  effect: "read",
  inputSchema: z.object({
    source: z.enum(["auto", "mock", "live"]).optional().describe(
      "auto uses the tenant when ZPA credentials exist, otherwise the built-in integration fixture.",
    ),
  }),
  async execute({ source }): Promise<ZpaIntegrationMap | { error: string }> {
    const selected = source ?? "auto";
    if (selected === "mock") return mockIntegrationMap();

    const loaded = loadConfig(process.env);
    if (!loaded.ok || loaded.config.customerId === null) {
      if (selected === "live") {
        return {
          error: loaded.ok
            ? "Live ZPA inventory requires ZSCALER_CUSTOMER_ID."
            : loaded.error,
        };
      }
      const mock = mockIntegrationMap();
      return {
        ...mock,
        warnings: [
          ...mock.warnings,
          "ZPA credentials or customer ID are absent; returned the built-in integration fixture.",
        ],
      };
    }

    const [segmentResult, policyResult] = await Promise.all([
      callZscalerPaginated(process.env, "zpa.listApplicationSegments", INTEGRATION_READ_LIMIT),
      callZscalerPaginated(process.env, "zpa.listAccessPolicyRules", INTEGRATION_READ_LIMIT),
    ]);
    const normalizedSegments = segmentResult.ok
      ? normalizeSegments(segmentResult.data)
      : { segments: [], complete: false };
    const normalizedPolicies = policyResult.ok
      ? normalizePolicies(policyResult.data)
      : { policies: [], complete: false };
    const warnings = [
      ...(segmentResult.error === null ? [] : [`Application segments: ${segmentResult.error}`]),
      ...(policyResult.error === null ? [] : [`Access policies: ${policyResult.error}`]),
      ...(segmentResult.truncated ? ["Application-segment response exceeded the integration read limit."] : []),
      ...(policyResult.truncated ? ["Access-policy response exceeded the integration read limit."] : []),
      ...(!normalizedSegments.complete ? ["Application-segment response has additional pages."] : []),
      ...(!normalizedPolicies.complete ? ["Access-policy response has additional pages."] : []),
    ];
    return buildIntegrationMap(
      "zscaler",
      normalizedSegments.segments,
      normalizedPolicies.policies,
      segmentResult.ok
        && policyResult.ok
        && !segmentResult.truncated
        && !policyResult.truncated
        && normalizedSegments.complete
        && normalizedPolicies.complete,
      warnings,
    );
  },
});
