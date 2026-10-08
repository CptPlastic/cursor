import { defineAgent } from "@cursor/bdk";

export default defineAgent({
  description: "DLP inspector. Delegate when the operator pastes text and wants a sensitive-data decision.",
  instructions: `Call classify_sensitive_data once with the pasted text. Report action, matched dictionary names, severity, counts, and reason. Do not repeat the sensitive values and do not call the web or private-access tools.`,
});
