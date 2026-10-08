import { defineTool } from "@cursor/bdk/tools";
import { z } from "zod";
import { hostFromInput } from "../lib/policy.js";
import { callZscaler, type ZscalerCallResult, type ZscalerOperation } from "../lib/zscaler-client.js";

const operations = [
  "zia.urlLookup",
  "zia.listUrlFilteringRules",
  "zia.listUrlCategories",
  "zia.listDlpDictionaries",
  "zpa.listApplicationSegments",
  "zpa.listAccessPolicyRules",
] as const satisfies readonly ZscalerOperation[];

export default defineTool({
  description: "Read an allowlisted Zscaler OneAPI endpoint. URL lookup is the only POST. Policy changes and activation are not available.",
  effect: "read",
  inputSchema: z.object({
    operation: z.enum(operations),
    urls: z.array(z.string().min(1).max(1024)).min(1).max(20).optional(),
  }),
  async execute({ operation, urls }): Promise<ZscalerCallResult | { error: string }> {
    if (operation === "zia.urlLookup") {
      if (urls === undefined) return { error: "zia.urlLookup requires urls." };
      const hosts: string[] = [];
      for (const url of urls) {
        const host = hostFromInput(url);
        if (host === null) return { error: `Not a usable URL or hostname: ${url}` };
        hosts.push(host);
      }
      return callZscaler(process.env, operation, hosts);
    }
    return callZscaler(process.env, operation);
  },
});
