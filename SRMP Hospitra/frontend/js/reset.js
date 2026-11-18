// Controlled data reset (used by Threat Monitoring and Reports & Audit).
import { api } from "./core/api.js";
import { h } from "./core/dom.js";
import { bus, loadReferenceData } from "./core/state.js";
import { confirmDialog, toast, toastError, withBusy } from "./core/ui.js";

export async function resetData(button) {
  const ok = await confirmDialog({
    title: "Reset all data?",
    message: h("div", { class: "stack" },
      h("p", {}, "This permanently deletes ALL Hospitra records — assets, risks, events, detections, incidents and the audit log — and reseeds the original dataset. User accounts are kept."),
      h("p", { class: "muted" }, "A single “data.reset” audit entry will record the operation.")),
    confirmLabel: "Reset and reseed",
    danger: true,
    requireText: "RESET",
  });
  if (!ok) return false;
  return withBusy(button, async () => {
    try {
      const res = await api.post("/simulation/reset", { confirm: "RESET" });
      await loadReferenceData();
      toast({ type: "success", title: "Data reset", message: `Reseeded ${res.created.assets} assets, ${res.created.risks} risks and ${res.created.baseline_events + (res.created.historical_events || 0)} events.` });
      bus.emit("data-changed", { entity: "all" });
      return true;
    } catch (err) {
      toastError(err, "Reset failed");
      return false;
    }
  });
}
