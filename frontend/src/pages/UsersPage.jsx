import { useEffect, useMemo, useState } from "react";

import { ROLE_LABEL, TOOLS, api, readJson } from "../api";

const EMPTY = {
  username: "",
  email: "",
  password: "",
  role: "viewer",
  disabled: false,
  access: { semgrep: true, checkov: true, sonar: false },
};

export function UsersPage() {
  const [users, setUsers] = useState([]);
  const [query, setQuery] = useState("");
  const [role, setRole] = useState("all");
  const [form, setForm] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    const response = await api("/api/users");
    setUsers(await readJson(response));
  }

  useEffect(() => {
    load().catch((err) => setError(err.message));
  }, []);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return users.filter((user) => {
      const matchesRole = role === "all" || user.role === role;
      const haystack = `${user.username} ${user.email}`.toLowerCase();
      return matchesRole && (!needle || haystack.includes(needle));
    });
  }, [users, query, role]);

  function patchForm(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function save(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const payload = {
      username: form.username,
      email: form.email,
      role: form.role,
      disabled: form.disabled,
      access: form.access,
    };
    if (form.password) payload.password = form.password;
    try {
      const response = await api(form.id ? `/api/users/${form.id}` : "/api/users", {
        method: form.id ? "PATCH" : "POST",
        body: JSON.stringify(payload),
      });
      await readJson(response);
      setForm(null);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(user) {
    if (!window.confirm(`کاربر ${user.username} حذف شود؟`)) return;
    setError("");
    try {
      await readJson(await api(`/api/users/${user.id}`, { method: "DELETE" }));
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-black">مدیریت کاربران</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">جستجو، فیلتر، ویرایش و حذف حساب‌ها</p>
        </div>
        <button className="btn-primary" onClick={() => { setError(""); setForm({ ...EMPTY, access: { ...EMPTY.access } }); }}>
          کاربر جدید
        </button>
      </div>
      {error && <Callout>{error}</Callout>}
      <div className="panel flex flex-col gap-3 p-4 sm:flex-row">
        <input
          className="field"
          placeholder="جستجو در نام کاربری یا ایمیل"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <select className="field sm:max-w-48" value={role} onChange={(event) => setRole(event.target.value)}>
          <option value="all">همه نقش‌ها</option>
          <option value="admin">مدیر</option>
          <option value="developer">توسعه‌دهنده</option>
          <option value="viewer">بیننده</option>
        </select>
      </div>
      <div className="panel overflow-x-auto">
        <table className="w-full min-w-[720px] text-sm">
          <thead className="text-slate-500 dark:text-slate-400">
            <tr>
              {["نام کاربری", "ایمیل", "نقش", "وضعیت", "ابزارها", ""].map((heading) => (
                <th key={heading} className="px-4 py-3 text-right font-medium">{heading}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((user) => (
              <tr key={user.id} className="border-t border-slate-100 dark:border-white/5">
                <td className="px-4 py-3 font-semibold">{user.username}</td>
                <td className="px-4 py-3" dir="ltr">{user.email}</td>
                <td className="px-4 py-3">{ROLE_LABEL[user.role]}</td>
                <td className="px-4 py-3">{user.disabled ? "غیرفعال" : "فعال"}</td>
                <td className="px-4 py-3">{TOOLS.filter((tool) => user.access[tool.id]).map((tool) => tool.label).join("، ") || "—"}</td>
                <td className="px-4 py-3">
                  <div className="flex justify-end gap-2">
                    <button className="btn-ghost" onClick={() => setForm({ ...user, password: "" })}>ویرایش</button>
                    <button className="btn-danger" onClick={() => remove(user)}>حذف</button>
                  </div>
                </td>
              </tr>
            ))}
            {visible.length === 0 && (
              <tr>
                <td className="px-4 py-8 text-slate-500" colSpan={6}>کاربری با این فیلتر نیست.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {form && (
        <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/60 p-4">
          <form className="panel max-h-[90vh] w-full max-w-lg overflow-y-auto p-6" onSubmit={save}>
            <h2 className="text-xl font-black">{form.id ? "ویرایش کاربر" : "کاربر جدید"}</h2>
            <div className="mt-4 space-y-3">
              <label className="block text-sm">
                نام کاربری
                <input className="field mt-1" dir="ltr" required maxLength={64} value={form.username} onChange={(event) => patchForm("username", event.target.value)} />
              </label>
              <label className="block text-sm">
                ایمیل
                <input className="field mt-1" dir="ltr" type="email" required maxLength={254} value={form.email} onChange={(event) => patchForm("email", event.target.value)} />
              </label>
              <label className="block text-sm">
                رمز عبور {form.id ? "(خالی یعنی بدون تغییر)" : ""}
                <input className="field mt-1" dir="ltr" type="password" required={!form.id} minLength={form.id ? undefined : 12} maxLength={128} value={form.password} onChange={(event) => patchForm("password", event.target.value)} />
              </label>
              <label className="block text-sm">
                سطح دسترسی
                <select className="field mt-1" value={form.role} onChange={(event) => patchForm("role", event.target.value)}>
                  <option value="admin">مدیر</option>
                  <option value="developer">توسعه‌دهنده</option>
                  <option value="viewer">بیننده</option>
                </select>
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={form.disabled} onChange={(event) => patchForm("disabled", event.target.checked)} />
                حساب غیرفعال باشد
              </label>
              <div className="grid gap-2 sm:grid-cols-3">
                {TOOLS.map((tool) => (
                  <label key={tool.id} className="rounded-xl border border-slate-200 p-3 text-sm dark:border-white/10">
                    <input
                      type="checkbox"
                      className="me-2"
                      checked={form.role === "admin" || form.access[tool.id]}
                      disabled={form.role === "admin"}
                      onChange={(event) =>
                        setForm((current) => ({
                          ...current,
                          access: { ...current.access, [tool.id]: event.target.checked },
                        }))
                      }
                    />
                    {tool.label}
                  </label>
                ))}
              </div>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className="btn-ghost" onClick={() => setForm(null)}>انصراف</button>
              <button className="btn-primary" disabled={busy}>{busy ? "در حال ذخیره" : "ذخیره"}</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

function Callout({ children }) {
  return (
    <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-200">
      {children}
    </div>
  );
}
