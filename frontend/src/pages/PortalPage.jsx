import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { TOOLS, api, readJson } from "../api";
import { useAuth } from "../auth";

export function PortalPage() {
  const { user } = useAuth();
  const [scans, setScans] = useState([]);
  const [open, setOpen] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [repo, setRepo] = useState("");
  const [tools, setTools] = useState(["semgrep", "checkov"]);

  const canStart = user?.role === "admin" || user?.role === "developer";
  const allowed = TOOLS.filter((tool) => user?.access?.[tool.id]);

  async function load() {
    const scanResponse = await api("/api/scans?summary=1");
    setScans(await readJson(scanResponse));
  }

  useEffect(() => {
    let timer;
    async function tick() {
      try {
        await load();
      } catch (err) {
        setError(err.message);
      }
      timer = setTimeout(tick, 5000);
    }
    tick();
    return () => clearTimeout(timer);
  }, []);

  const groups = useMemo(() => {
    const map = new Map();
    for (const scan of scans) {
      const key = projectKey(scan.repo);
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(scan);
    }
    return [...map.entries()];
  }, [scans]);

  const totals = scans.reduce(
    (sum, scan) => {
      sum.count += 1;
      sum.findings += scan.finding_count || 0;
      sum.critical += scan.severity?.critical || 0;
      return sum;
    },
    { count: 0, findings: 0, critical: 0 },
  );

  async function start(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await readJson(
        await api("/api/scans", {
          method: "POST",
          body: JSON.stringify({ repo, tools }),
        }),
      );
      setRepo("");
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-black">گزارش‌های من</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          {user?.role === "admin"
            ? "مدیر همهٔ بررسی‌ها را می‌بیند."
            : "فقط بررسی‌هایی که خودت شروع کرده‌ای، برای ابزارهای مجاز، اینجاست."}
        </p>
      </div>
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <Stat label="بررسی‌ها" value={totals.count} />
        <Stat label="یافته‌ها" value={totals.findings} />
        <Stat label="بحرانی" value={totals.critical} />
      </section>
      {error && <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-200">{error}</div>}
      {canStart && (
        <form className="panel grid gap-3 p-4 lg:grid-cols-[1fr_auto] lg:items-end" onSubmit={start}>
          <label className="text-sm">
            آدرس مخزن Git
            <input
              className="field mt-1"
              dir="ltr"
              required
              placeholder="https://github.com/org/repo.git"
              value={repo}
              onChange={(event) => setRepo(event.target.value)}
            />
          </label>
          <div className="flex flex-wrap items-center gap-3">
            {allowed.map((tool) => (
              <label key={tool.id} className="text-sm">
                <input
                  className="me-1"
                  type="checkbox"
                  checked={tools.includes(tool.id)}
                  onChange={(event) =>
                    setTools((current) =>
                      event.target.checked
                        ? [...current, tool.id]
                        : current.filter((item) => item !== tool.id),
                    )
                  }
                />
                {tool.label}
              </label>
            ))}
            <button className="btn-primary" disabled={busy}>{busy ? "در حال شروع" : "شروع بررسی"}</button>
          </div>
        </form>
      )}
      <section className="panel divide-y divide-slate-100 dark:divide-white/5">
        {groups.length === 0 && <p className="p-5 text-sm text-slate-500">هنوز بررسی‌ای برای این حساب نیست.</p>}
        {groups.map(([name, items]) => {
          const expanded = open === name || (open === "" && name === groups[0][0]);
          return (
            <div key={name}>
              <button
                className="flex w-full items-center justify-between gap-3 px-4 py-3 text-right"
                onClick={() => setOpen(expanded ? "_" : name)}
              >
                <span>
                  <span className="me-2 text-slate-400">{expanded ? "▾" : "◂"}</span>
                  <span className="font-semibold">{name}</span>
                </span>
                <span className="text-xs text-slate-500">{items.length} بررسی</span>
              </button>
              {expanded && (
                <div className="space-y-2 px-4 pb-4">
                  {items.map((scan) => (
                    <Link
                      key={scan.id}
                      to={`/scans/${scan.id}`}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-slate-50 px-3 py-2 text-sm hover:bg-teal-500/10 dark:bg-white/5"
                    >
                      <span>{statusLabel(scan.status)} · {scan.finding_count} مورد</span>
                      <span className="text-xs text-slate-500" dir="ltr">{scan.created_at}</span>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </section>
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <article className="panel p-4">
      <div className="text-sm text-slate-500 dark:text-slate-400">{label}</div>
      <div className="mt-2 text-3xl font-black tracking-tight">{value}</div>
    </article>
  );
}

function projectKey(repo) {
  return String(repo || "بدون نام")
    .replace(/\.git\/?$/i, "")
    .replace(/\/$/, "")
    .split("/")
    .filter(Boolean)
    .slice(-1)[0];
}

function statusLabel(status) {
  if (status === "done") return "تمام شد";
  if (status === "running") return "در حال اجرا";
  if (status === "failed") return "ناموفق";
  return status || "نامشخص";
}
