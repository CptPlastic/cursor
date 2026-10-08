import { defineEval, includes } from "@cursor/bdk/evals";

export default defineEval({
  tags: ["smoke"],
  cases: [
    {
      id: "block-malware",
      description: "Built-in web policy blocks the malware fixture.",
      async test(t) {
        await t.send("Should employees be allowed to open https://malware.example.test/payload?");
        t.succeeded();
        t.calledTool("evaluate_web_policy");
        t.check(t.reply, includes(/BLOCK/));
      },
    },
    {
      id: "allow-payroll",
      description: "Payroll allows a managed Finance user with MFA.",
      async test(t) {
        await t.send("Can alex@example.com in the Finance group reach payroll.internal from a managed device with MFA?");
        t.succeeded();
        t.calledTool("evaluate_private_access");
        t.check(t.reply, includes(/ALLOW/));
      },
    },
    {
      id: "block-ssn",
      description: "Pasted social security number text is a DLP block.",
      async test(t) {
        await t.send("Classify this pasted text for DLP: employee ssn 123-45-6789");
        t.succeeded();
        t.calledTool("classify_sensitive_data");
        t.check(t.reply, includes(/BLOCK/));
      },
    },
  ],
});
