import { defineTool } from "@cursor/bdk/tools";
import { z } from "zod";
import { classifyText, type DlpDecision } from "../lib/policy.js";

export default defineTool({
  description: "Classify operator-submitted text with local DLP dictionaries and recommend ALLOW or BLOCK. Counts matches without repeating the sensitive values.",
  effect: "read",
  inputSchema: z.object({
    text: z.string().min(1).max(20_000).describe("Text the operator pasted for classification."),
  }),
  async execute({ text }): Promise<DlpDecision> {
    return classifyText(text);
  },
});
