import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { useAuth } from "../auth";
import { useTheme } from "../theme";

export function LoginPage() {
  const { login } = useAuth();
  const { theme, toggle } = useTheme();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const user = await login(username.trim(), password);
      navigate(user.role === "admin" ? "/users" : "/portal");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-screen bg-slate-950 text-white lg:grid-cols-2">
      <section className="relative hidden overflow-hidden bg-[radial-gradient(circle_at_20%_20%,rgba(45,212,191,0.35),transparent_36%),linear-gradient(160deg,#042f2e,#020617)] p-12 lg:block">
        <div className="max-w-md">
          <p className="text-sm text-teal-200">پلتفرم بررسی امنیت</p>
          <h1 className="mt-3 text-4xl font-black leading-tight">
            دید زنده روی اسکن‌ها، یافته‌ها و دسترسی تیم
          </h1>
          <p className="mt-4 text-slate-300">
            Semgrep، Checkov و SonarQube از یک داشبورد. هر کاربر فقط گزارش ابزارهایی را می‌بیند که برایش باز شده است.
          </p>
        </div>
        <div className="mt-12 grid max-w-lg grid-cols-3 gap-3">
          {["Semgrep", "Checkov", "SonarQube"].map((name) => (
            <div key={name} className="rounded-2xl border border-white/10 bg-white/5 p-4">
              <div className="text-xs text-slate-400">ابزار</div>
              <div className="mt-2 font-semibold">{name}</div>
            </div>
          ))}
        </div>
      </section>
      <section className="flex items-center justify-center bg-slate-100 p-6 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
        <form className="panel w-full max-w-md p-6 sm:p-8" onSubmit={onSubmit}>
          <div className="mb-6 flex items-start justify-between gap-3">
            <div>
              <h2 className="text-2xl font-black">ورود به کنسول</h2>
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                برای دیدن گزارش‌ها وارد شو.
              </p>
            </div>
            <button type="button" className="btn-ghost" onClick={toggle}>
              {theme === "dark" ? "روشن" : "تاریک"}
            </button>
          </div>
          {error && (
            <div className="mb-4 rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-200">
              {error}
            </div>
          )}
          <label className="mb-4 block text-sm">
            <span className="mb-1.5 block text-slate-500 dark:text-slate-400">نام کاربری</span>
            <input
              className="field"
              dir="ltr"
              autoComplete="username"
              maxLength={64}
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
          </label>
          <label className="mb-5 block text-sm">
            <span className="mb-1.5 block text-slate-500 dark:text-slate-400">رمز عبور</span>
            <span className="flex gap-2">
              <input
                className="field"
                dir="ltr"
                type={show ? "text" : "password"}
                autoComplete="current-password"
                maxLength={128}
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
              <button type="button" className="btn-ghost shrink-0" onClick={() => setShow((v) => !v)}>
                {show ? "پنهان" : "نمایش"}
              </button>
            </span>
          </label>
          <button className="btn-primary w-full" disabled={busy}>
            {busy ? "در حال ورود" : "ورود"}
          </button>
        </form>
      </section>
    </div>
  );
}
