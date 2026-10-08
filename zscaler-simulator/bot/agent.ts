import { defineAgent } from "@cursor/bdk";

export default defineAgent({
  name: "Zscaler simulator",
  description: "Simulates ZIA web policy, ZPA private access, and DLP decisions, and reads a configured Zscaler tenant through OneAPI.",
  model: {
    id: "grok-4.5",
    params: [
      { id: "effort", value: "high" },
      { id: "fast", value: "true" },
    ],
  },
  tools: ["task"],
  local: { sandbox: true },
  hosting: {
    egressDomains: ["api.zsapi.net", "*.zsapi.net", "*.zslogin.net"],
    secretNames: [
      "ZSCALER_CLIENT_ID",
      "ZSCALER_CLIENT_SECRET",
      "ZSCALER_VANITY_DOMAIN",
      "ZSCALER_CLOUD",
      "ZSCALER_CUSTOMER_ID",
    ],
  },
});
