import { useState } from "react";
import { NavLink } from "react-router-dom";

import { ROLE_LABEL } from "../api";
import { useAuth } from "../auth";
import { useTheme } from "../theme";

const LINKS = [
  { to: "/portal", label: "گزارش‌ها", admin: false },
  { to: "/users", label: "کاربران", admin: true },
  { to: "/access", label: "دسترسی ابزارها", admin: true },
  { to: "/settings", label: "تنظیمات", admin: false },
];

export function Shell({ children }) {
  const { user, logout } = useAuth();
  const { theme, toggle } = useTheme();
  const [open, setOpen] = useState(false);
  const links = LINKS.filter((link) => !link.admin || user?.role === "admin");

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,rgba(45,212,191,0.16),transparent_32%),linear-gradient(180deg,#f8fafc,#e2e8f0)] text-slate-900 dark:bg-[radial-gradient(circle_at_top_left,rgba(45,212,191,0.18),transparent_28%),linear-gradient(180deg,#020617,#0f172a)] dark:text-slate-100">
      <div className="mx-auto grid min-h-screen max-w-[1500px] lg:grid-cols-[260px_1fr]">
        <aside
          className={`${open ? "translate-x-0" : "translate-x-full"} fixed inset-y-0 right-0 z-30 w-72 border-l border-slate-200/80 bg-white/95 p-5 transition dark:border-white/10 dark:bg-slate-950/95 lg:relative lg:w-auto lg:translate-x-0 lg:border-l-0 lg:border-e lg:bg-transparent`}
        >
          <div className="mb-8 flex items-center gap-3">
            <span className="grid h-11 w-11 place-items-center rounded-2xl bg-teal-500 text-lg font-black text-slate-950">
              س
            </span>
            <div>
              <div className="text-sm text-slate-500 dark:text-slate-400">مانیتورینگ امنیت</div>
              <strong className="text-lg">کنسول امنیت</strong>
            </div>
          </div>
          <nav className="space-y-1">
            {links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                onClick={() => setOpen(false)}
                className={({ isActive }) =>
                  `block rounded-xl px-3 py-2.5 text-sm font-medium transition ${
                    isActive
                      ? "bg-teal-500 text-slate-950"
                      : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-white/5"
                  }`
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
          <div className="absolute bottom-5 left-5 right-5 rounded-2xl border border-slate-200 p-3 dark:border-white/10 lg:left-5 lg:right-5">
            <div className="text-sm font-semibold">{user?.username}</div>
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {ROLE_LABEL[user?.role] || user?.role}
            </div>
          </div>
        </aside>
        {open && (
          <button
            className="fixed inset-0 z-20 bg-slate-950/50 lg:hidden"
            aria-label="بستن فهرست"
            onClick={() => setOpen(false)}
          />
        )}
        <div className="min-w-0">
          <header className="flex items-center justify-between gap-3 px-4 py-4 sm:px-6">
            <button className="btn-ghost lg:hidden" onClick={() => setOpen(true)}>
              فهرست
            </button>
            <div className="ms-auto flex items-center gap-2">
              <button className="btn-ghost" onClick={toggle}>
                {theme === "dark" ? "حالت روشن" : "حالت تاریک"}
              </button>
              <button className="btn-ghost" onClick={logout}>
                خروج
              </button>
            </div>
          </header>
          <main className="px-4 pb-10 sm:px-6">{children}</main>
        </div>
      </div>
    </div>
  );
}
