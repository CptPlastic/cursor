import { defineAgent } from "@cursor/bdk";

export default defineAgent({
  description: "ZPA private access. Delegate when the operator asks whether a user can reach an internal application.",
  instructions: `Call evaluate_private_access once. Map managed device and MFA from the request into managedDevice and mfa. Report action, segment, segmentSource, checks, reason, and warning. Do not call the web-policy or DLP tools.`,
});
