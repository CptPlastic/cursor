import { defineTool } from "@cursor/bdk/tools";
import { z } from "zod";
import {
  MOCK_WEB_RULES,
  categoriesFromLookup,
  decideWeb,
  hostFromInput,
  isFixtureHost,
  mockCategories,
  rulesFromApi,
  type WebDecision,
} from "../lib/policy.js";
import { callZscaler, loadConfig } from "../lib/zscaler-client.js";

export default defineTool({
  description: "Decide ALLOW, BLOCK, CAUTION, or ISOLATE for one web URL using ZIA-style rules. Uses the built-in catalog for fixture hosts and the Zscaler API when credentials are configured.",
  effect: "read",
  inputSchema: z.object({
    url: z.string().min(1).max(1024).describe("Absolute http(s) URL or hostname."),
    preferLive: z.boolean().optional().describe("When false, stay on the built-in catalog even if credentials exist."),
  }),
  async execute({ url, preferLive }): Promise<WebDecision | { error: string }> {
    const host = hostFromInput(url);
    if (host === null) return { error: "Provide an http or https URL, or a hostname, without embedded credentials." };
    const liveRequested = preferLive !== false && !isFixtureHost(host);
    const loaded = loadConfig(process.env);
    let categories = mockCategories(host);
    let rules = MOCK_WEB_RULES;
    let categorySource: WebDecision["categorySource"] = "mock";
    let rulesSource: WebDecision["rulesSource"] = "mock";
    let warning: string | null = null;

    if (liveRequested && loaded.ok) {
      const [lookup, ruleList] = await Promise.all([
        callZscaler(process.env, "zia.urlLookup", [host]),
        callZscaler(process.env, "zia.listUrlFilteringRules"),
      ]);
      const liveCategories = lookup.ok ? categoriesFromLookup(lookup.data) : null;
      if (liveCategories !== null) {
        categories = liveCategories;
        categorySource = "zscaler";
      } else {
        warning = lookup.error ?? "URL lookup did not return categories. Built-in categories were used.";
      }
      const liveRules = ruleList.ok ? rulesFromApi(ruleList.data) : null;
      if (liveRules !== null) {
        rules = liveRules;
        rulesSource = "zscaler";
      } else if (categorySource === "zscaler") {
        warning = ruleList.error ?? "URL filtering rules were not usable. Built-in rules were applied to live categories.";
      }
    } else if (liveRequested && !loaded.ok && !loaded.missing) {
      warning = loaded.error;
    }

    const decision = decideWeb(host, categories, rules);
    return {
      action: decision.action,
      host,
      categories,
      categorySource,
      rulesSource,
      matchedRule: decision.matchedRule,
      reason: decision.reason,
      warning,
    };
  },
});
