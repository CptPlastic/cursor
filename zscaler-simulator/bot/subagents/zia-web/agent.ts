import { defineAgent } from "@cursor/bdk";

export default defineAgent({
  description: "ZIA web policy. Delegate when the operator asks whether a website should be allowed, blocked, cautioned, or isolated.",
  instructions: `Call evaluate_web_policy once with the URL. Report its action, host, categories, categorySource, rulesSource, matched rule, and warning. Do not call the private-access or DLP tools.`,
});
