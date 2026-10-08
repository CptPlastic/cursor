import { defineTool } from "@cursor/bdk/tools";
import { z } from "zod";
import { decideAccess, findLocalSegment, type AccessDecision } from "../lib/policy.js";
import {
  evaluateIntegratedAccess,
  normalizePolicies,
  normalizeSegments,
  type IntegratedAccessDecision,
} from "../lib/zpa-integration.js";
import { callZscalerPaginated, loadConfig } from "../lib/zscaler-client.js";

export default defineTool({
  description: "Decide ALLOW or BLOCK for a private application. Known demo segments use local posture rules; other applications use live ZPA app segments and top-down access policies when configured.",
  effect: "read",
  inputSchema: z.object({
    user: z.string().min(1).max(200),
    application: z.string().min(1).max(253).describe("Application hostname or segment name."),
    groups: z.array(z.string().min(1).max(80)).max(20).optional(),
    managedDevice: z.boolean().optional(),
    mfa: z.boolean().optional(),
    postureProfileIds: z.array(z.string().min(1).max(100)).max(20).optional().describe(
      "Live ZPA posture-profile IDs satisfied by the device.",
    ),
    platform: z.string().min(1).max(40).optional().describe("Platform value used by a live PLATFORM criterion."),
    clientType: z.string().min(1).max(100).optional().describe("ZPA client type used by a live CLIENT_TYPE criterion."),
  }),
  async execute({
    user,
    application,
    groups,
    managedDevice,
    mfa,
    postureProfileIds,
    platform,
    clientType,
  }): Promise<AccessDecision | IntegratedAccessDecision> {
    const loaded = loadConfig(process.env);
    const local = findLocalSegment(application);
    if (local === undefined && loaded.ok && loaded.config.customerId !== null) {
      const [segmentResult, policyResult] = await Promise.all([
        callZscalerPaginated(process.env, "zpa.listApplicationSegments"),
        callZscalerPaginated(process.env, "zpa.listAccessPolicyRules"),
      ]);
      const normalizedSegments = segmentResult.ok
        ? normalizeSegments(segmentResult.data)
        : { segments: [], complete: false };
      const normalizedPolicies = policyResult.ok
        ? normalizePolicies(policyResult.data)
        : { policies: [], complete: false };
      const warnings = [
        segmentResult.error,
        policyResult.error,
        normalizedSegments.complete ? null : "Application-segment response has additional pages.",
        normalizedPolicies.complete ? null : "Access-policy response has additional pages.",
        segmentResult.truncated ? "Application-segment response was truncated." : null,
        policyResult.truncated ? "Access-policy response was truncated." : null,
      ].filter((warning): warning is string => warning !== null);
      return evaluateIntegratedAccess({
        user,
        application,
        groups: groups ?? [],
        managedDevice: managedDevice ?? false,
        postureProfileIds: postureProfileIds ?? [],
        platform: platform ?? null,
        clientType: clientType ?? null,
        segments: normalizedSegments.segments,
        policies: normalizedPolicies.policies,
        warning: warnings.length === 0 ? null : warnings.join(" "),
      });
    }

    let liveWarning: string | null = null;
    if (local === undefined && loaded.ok && loaded.config.customerId === null) {
      liveWarning = "Live ZPA evaluation requires ZSCALER_CUSTOMER_ID.";
    }
    return decideAccess({
      user,
      groups: groups ?? [],
      application,
      managedDevice: managedDevice ?? false,
      mfa: mfa ?? false,
      liveSegments: [],
      liveWarning,
    });
  },
});
