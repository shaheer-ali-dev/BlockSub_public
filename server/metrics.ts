const counters: Record<string, number> = {};
const gauges: Record<string, number> = {};
const timings: Record<string, number[]> = {};

export function inc(name: string, by = 1) {
  counters[name] = (counters[name] || 0) + by;
}

export function gauge(name: string, value: number) {
  gauges[name] = value;
}

export function timing(name: string, ms: number) {
  if (!timings[name]) timings[name] = [];
  timings[name].push(ms);
}

export function snapshot() {
  const avgTimings: Record<string, number> = {};
  for (const k of Object.keys(timings)) {
    const arr = timings[k];
    const sum = arr.reduce((a,b) => a+b, 0);
    avgTimings[k] = arr.length ? sum/arr.length : 0;
  }
  return { counters: { ...counters }, gauges: { ...gauges }, avgTimings };
}

export default { inc, gauge, timing, snapshot };
