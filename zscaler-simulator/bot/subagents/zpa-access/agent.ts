import { defineAgent } from "@cursor/bdk";

export default defineAgent({
  description: "ZPA private access. Delegate when the operator asks whether a user can reach an internal application.",
  instructions: `Call evaluate_private_access once. Map managed device, MFA, posture-profile IDs, platform, and client type from the request. Report action, segment, segmentSource, matchedPolicy, unresolvedCriteria, checks when present, reason, and warning. Do not call the web-policy or DLP tools.`,
});
