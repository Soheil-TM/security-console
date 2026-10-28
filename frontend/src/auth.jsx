import { createContext, useContext, useEffect, useState } from "react";

import { api, readJson } from "./api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function boot() {
      try {
        let response = await api("/api/auth/me");
        if (response.status === 401) {
          const refreshed = await api("/api/auth/refresh", { method: "POST" });
          if (refreshed.ok) response = await api("/api/auth/me");
        }
        if (!cancelled && response.ok) setUser(await response.json());
      } finally {
        if (!cancelled) setReady(true);
      }
    }
    boot();
    return () => {
      cancelled = true;
    };
  }, []);

  async function login(username, password) {
    const response = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    const body = await readJson(response);
    setUser(body);
    return body;
  }

  async function logout() {
    await api("/api/auth/logout", { method: "POST" });
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, ready, login, logout, setUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}

export function hasCap(user, capability) {
  if (!user) return false;
  if (user.role === "super_admin") return true;
  const caps = user.capabilities;
  return Array.isArray(caps) && caps.includes(capability);
}

export function isElevated(user) {
  return Boolean(user && (user.role === "super_admin" || user.role === "admin"));
}

export function toolsLocked(userOrRole) {
  const role = typeof userOrRole === "string" ? userOrRole : userOrRole?.role;
  return role === "super_admin" || role === "admin";
}
