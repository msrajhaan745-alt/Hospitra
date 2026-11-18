// Chart.js theming and helpers (Chart.js is vendored locally: /vendor/chart.umd.js).

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

export const SEVERITY_ORDER = ["Low", "Moderate", "High", "Critical"];

export function severityColours() {
  return {
    Low: css("--sev-low"),
    Moderate: css("--sev-moderate"),
    High: css("--sev-high"),
    Critical: css("--sev-critical"),
  };
}

export function themeColours() {
  return {
    text: css("--text"),
    muted: css("--text-muted"),
    dim: css("--text-dim"),
    grid: css("--border"),
    accent: css("--accent"),
    ok: css("--ok"),
    warn: css("--warn"),
    danger: css("--danger"),
    info: css("--info"),
    neutral: css("--neutral"),
    panel: css("--panel"),
  };
}

let configured = false;

function configure() {
  if (configured || !window.Chart) return;
  const c = themeColours();
  const { Chart } = window;
  Chart.defaults.color = c.muted;
  Chart.defaults.borderColor = c.grid;
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.font.size = 11.5;
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.plugins.legend.labels.boxHeight = 10;
  Chart.defaults.plugins.tooltip.backgroundColor = "#06101b";
  Chart.defaults.plugins.tooltip.borderColor = css("--border-strong");
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.maintainAspectRatio = false;
  Chart.defaults.animation.duration = 350;
  configured = true;
}

/** Create a chart; returns null (and the caller shows a fallback) if Chart.js failed to load. */
export function makeChart(canvas, config) {
  if (!window.Chart) return null;
  configure();
  return new window.Chart(canvas, config);
}

export const chartAvailable = () => Boolean(window.Chart);
