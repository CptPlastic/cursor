import { defineTool } from "@cursor/bdk/tools";
import { z } from "zod";
import { decideAccess, findLocalSegment, segmentsFromApi, type AccessDecision } from "../lib/policy.js";
import { callZscaler, loadConfig } from "../lib/zscaler-client.js";

export default defineTool({
  description: "Decide ALLOW or BLOCK for a private application using ZPA-style posture checks. Known demo segments are local. Other segments can be read from Zscaler and still default to deny.",
  effect: "read",
  inputSchema: z.object({
    user: z.string().min(1).max(200),
    application: z.string().min(1).max(253).describe("Application hostname or segment name."),
    groups: z.array(z.string().min(1).max(80)).max(20).optional(),
    managedDevice: z.boolean().optional(),
    mfa: z.boolean().optional(),
  }),
  async execute({ user, application, groups, managedDevice, mfa }): Promise<AccessDecision> {
    const loaded = loadConfig(process.env);
    let liveSegments: { name: string; hosts: string[] }[] = [];
    let liveWarning: string | null = null;
    if (loaded.ok && loaded.config.customerId !== null && findLocalSegment(application) === undefined) {
      const listed = await callZscaler(process.env, "zpa.listApplicationSegments");
      if (listed.ok) liveSegments = segmentsFromApi(listed.data);
      else liveWarning = listed.error;
    }
    return decideAccess({
      user,
      groups: groups ?? [],
      application,
      managedDevice: managedDevice ?? false,
      mfa: mfa ?? false,
      liveSegments,
      liveWarning,
    });
  },
});
