export function csrfToken() {
  const row = document.cookie
    .split("; ")
    .find((item) => item.startsWith("csrf_token="));
  return row ? decodeURIComponent(row.split("=").slice(1).join("=")) : "";
}

export async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  const method = options.method || "GET";
  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken();

  const run = () =>
    fetch(path, { ...options, method, headers, credentials: "same-origin" });

  let response = await run();
  if (response.status === 401 && !path.startsWith("/api/auth/")) {
    const refreshed = await fetch("/api/auth/refresh", {
      method: "POST",
      credentials: "same-origin",
    });
    if (refreshed.ok) {
      headers["X-CSRF-Token"] = csrfToken();
      response = await run();
    }
  }
  return response;
}

export async function readJson(response) {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.error || "درخواست انجام نشد.");
    error.status = response.status;
    throw error;
  }
  return body;
}

export const ROLE_LABEL = {
  admin: "مدیر",
  developer: "توسعه‌دهنده",
  viewer: "بیننده",
};

export const TOOLS = [
  { id: "semgrep", label: "Semgrep", hint: "الگوی آسیب‌پذیری در کد" },
  { id: "checkov", label: "Checkov", hint: "فایل‌های زیرساخت" },
  { id: "sonar", label: "SonarQube", hint: "Quality Gate" },
];
