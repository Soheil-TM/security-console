import { NavLink, Outlet } from "react-router-dom";

import { hasCap, useAuth } from "../auth";

const LINKS = [
  { to: "/portal", label: "پورتال" },
  { to: "/settings", label: "تنظیمات" },
  { to: "/users", label: "کاربران", cap: "users.manage" },
  { to: "/access", label: "دسترسی ابزارها", cap: "tool_access.manage" },
];

export function Shell() {
  const { user, logout } = useAuth();
  const links = LINKS.filter((link) => !link.cap || hasCap(user, link.cap));

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white/80 backdrop-blur dark:border-slate-800 dark:bg-slate-950/80">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div className="font-black">Security Console</div>
          <nav className="flex flex-wrap gap-2 text-sm">
            {links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                className={({ isActive }) =>
                  `rounded-lg px-3 py-1.5 ${isActive ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900" : "text-slate-600 dark:text-slate-300"}`
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
          <button className="btn-secondary" onClick={() => logout()}>
            خروج ({user?.username})
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
