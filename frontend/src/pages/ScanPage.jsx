import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api, readJson } from "../api";

export function ScanPage() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState("");
  const [tool, setTool] = useState("all");

  useEffect(() => {
    api(`/api/scans/${scanId}`)
      .then(readJson)
      .then(setScan)
      .catch((err) => setError(err.message));
  }, [scanId]);

  if (error) {
    return <p className="text-rose-600">{error}</p>;
  }
  if (!scan) {
    return <p className="text-slate-500">در حال خواندن گزارش…</p>;
  }
  const findings = (scan.findings || []).filter((row) => tool === "all" || row.tool === tool);

  return (
    <div className="space-y-5">
      <Link to="/portal" className="text-sm text-teal-700 dark:text-teal-300">بازگشت به گزارش‌ها</Link>
      <header className="panel p-5">
        <h1 className="text-2xl font-black" dir="ltr">{scan.repo}</h1>
        <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
          {scan.finding_count} یافته · {scan.created_at}
          {scan.owner ? ` · ${scan.owner}` : ""}
        </p>
        {scan.sonar && (
          <p className="mt-3 text-sm">
            Quality Gate: {scan.sonar.quality_gate || "—"} · آسیب‌پذیری {scan.sonar.vulnerabilities} · باگ {scan.sonar.bugs}
          </p>
        )}
        {scan.error && <p className="mt-3 whitespace-pre-wrap text-sm text-rose-600">{scan.error}</p>}
      </header>
      <div className="flex flex-wrap gap-2">
        {["all", ...(scan.tools || [])].map((item) => (
          <button key={item} className={tool === item ? "btn-primary" : "btn-ghost"} onClick={() => setTool(item)}>
            {item === "all" ? "همه" : item}
          </button>
        ))}
      </div>
      <div className="panel overflow-x-auto">
        <table className="w-full min-w-[680px] text-sm">
          <thead className="text-slate-500">
            <tr>
              {["ابزار", "شدت", "قانون", "مسیر"].map((heading) => (
                <th key={heading} className="px-4 py-3 text-right font-medium">{heading}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.slice(0, 200).map((row, index) => (
              <tr key={`${row.check}-${index}`} className="border-t border-slate-100 dark:border-white/5">
                <td className="px-4 py-3">{row.tool}</td>
                <td className="px-4 py-3">{row.severity}</td>
                <td className="px-4 py-3">{row.check}</td>
                <td className="px-4 py-3" dir="ltr">{row.path}{row.line ? `:${row.line}` : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
