import { Navigate, Outlet, Route, Routes } from "react-router-dom";

import { useAuth } from "./auth";
import { Shell } from "./components/Shell";
import { AccessPage } from "./pages/AccessPage";
import { LoginPage } from "./pages/LoginPage";
import { PortalPage } from "./pages/PortalPage";
import { ScanPage } from "./pages/ScanPage";
import { SettingsPage } from "./pages/SettingsPage";
import { UsersPage } from "./pages/UsersPage";

export default function App() {
  const { user, ready } = useAuth();
  if (!ready) {
    return (
      <div className="grid min-h-screen place-items-center bg-slate-950 text-slate-300">
        در حال بررسی نشست…
      </div>
    );
  }

  return (
    <Routes>
      <Route
        path="/login"
        element={user ? <Navigate to={home(user)} replace /> : <LoginPage />}
      />
      <Route element={<Private user={user} />}>
        <Route path="/portal" element={<PortalPage />} />
        <Route path="/scans/:scanId" element={<ScanPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route
          path="/users"
          element={user?.role === "admin" ? <UsersPage /> : <Navigate to="/portal" replace />}
        />
        <Route
          path="/access"
          element={user?.role === "admin" ? <AccessPage /> : <Navigate to="/portal" replace />}
        />
        <Route path="*" element={<Navigate to={user ? home(user) : "/login"} replace />} />
      </Route>
    </Routes>
  );
}

function Private({ user }) {
  if (!user) return <Navigate to="/login" replace />;
  return (
    <Shell>
      <Outlet />
    </Shell>
  );
}

function home(user) {
  return user.role === "admin" ? "/users" : "/portal";
}
