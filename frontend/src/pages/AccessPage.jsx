import { useEffect, useState } from "react";

import { ROLE_LABEL, TOOLS, api, readJson } from "../api";

export function AccessPage() {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    api("/api/users")
      .then(readJson)
      .then(setUsers)
      .catch((err) => setError(err.message));
  }, []);

  async function toggle(user, tool) {
    if (user.role === "admin") return;
    const access = { ...user.access, [tool]: !user.access[tool] };
    setError("");
    setNotice("");
    try {
      const saved = await readJson(
        await api(`/api/users/${user.id}`, {
          method: "PATCH",
          body: JSON.stringify({
            username: user.username,
            email: user.email,
            role: user.role,
            disabled: user.disabled,
            access,
          }),
        }),
      );
      setUsers((current) => current.map((item) => (item.id === saved.id ? saved : item)));
      setNotice(`دسترسی ${user.username} ذخیره شد.`);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-black">تخصیص دسترسی</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          مدیر همیشه به هر سه ابزار دسترسی دارد. برای بقیه، دیدن گزارش و شروع بررسی فقط روی ابزارهای روشن ممکن است.
        </p>
      </div>
      {error && <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-200">{error}</div>}
      {notice && <div className="rounded-xl border border-teal-500/30 bg-teal-500/10 px-3 py-2 text-sm text-teal-800 dark:text-teal-100">{notice}</div>}
      <div className="grid gap-4">
        {users.map((user) => (
          <article key={user.id} className="panel flex flex-col gap-4 p-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="font-bold">{user.username}</div>
              <div className="text-sm text-slate-500 dark:text-slate-400">
                {ROLE_LABEL[user.role]} · {user.email}
              </div>
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              {TOOLS.map((tool) => {
                const on = user.role === "admin" || user.access[tool.id];
                return (
                  <button
                    key={tool.id}
                    type="button"
                    disabled={user.role === "admin"}
                    onClick={() => toggle(user, tool.id)}
                    className={`rounded-xl border px-3 py-3 text-right text-sm transition ${
                      on
                        ? "border-teal-500/40 bg-teal-500/15"
                        : "border-slate-200 dark:border-white/10"
                    }`}
                  >
                    <div className="font-semibold">{tool.label}</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">{on ? "باز" : "بسته"} · {tool.hint}</div>
                  </button>
                );
              })}
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}
