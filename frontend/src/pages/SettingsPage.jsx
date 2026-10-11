import { useState } from "react";

import { api, readJson } from "../api";
import { useAuth } from "../auth";
import { useTheme } from "../theme";

export function SettingsPage() {
  const { user } = useAuth();
  const { theme, toggle } = useTheme();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [show, setShow] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await readJson(
        await api("/api/auth/password", {
          method: "POST",
          body: JSON.stringify({
            current_password: currentPassword,
            new_password: newPassword,
          }),
        }),
      );
      setCurrentPassword("");
      setNewPassword("");
      setNotice("رمز عبور عوض شد.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto grid max-w-3xl gap-5">
      <div>
        <h1 className="text-2xl font-black">تنظیمات حساب</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400">{user?.username} · {user?.email || "بدون ایمیل"}</p>
      </div>
      <section className="panel flex items-center justify-between gap-4 p-5">
        <div>
          <h2 className="font-bold">ظاهر</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">انتخاب روی همین مرورگر می‌ماند.</p>
        </div>
        <button className="btn-primary" onClick={toggle}>
          {theme === "dark" ? "حالت روشن" : "حالت تاریک"}
        </button>
      </section>
      <form className="panel space-y-4 p-5" onSubmit={onSubmit}>
        <h2 className="font-bold">تغییر رمز عبور</h2>
        {error && <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-200">{error}</div>}
        {notice && <div className="rounded-xl border border-teal-500/30 bg-teal-500/10 px-3 py-2 text-sm text-teal-800 dark:text-teal-100">{notice}</div>}
        <label className="block text-sm">
          رمز فعلی
          <input className="field mt-1" dir="ltr" type={show ? "text" : "password"} required maxLength={128} value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} />
        </label>
        <label className="block text-sm">
          رمز تازه
          <input className="field mt-1" dir="ltr" type={show ? "text" : "password"} required minLength={12} maxLength={128} value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
        </label>
        <div className="flex flex-wrap gap-2">
          <button type="button" className="btn-ghost" onClick={() => setShow((value) => !value)}>
            {show ? "پنهان کردن رمز" : "نمایش رمز"}
          </button>
          <button className="btn-primary" disabled={busy}>{busy ? "در حال ذخیره" : "ذخیره رمز"}</button>
        </div>
      </form>
    </div>
  );
}
