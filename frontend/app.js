// Same-origin base (frontend served by backend)
window.API = "";

function getToken() {
  return localStorage.getItem("token") || "";
}

function getUser() {
  try { return JSON.parse(localStorage.getItem("user") || "null"); } catch { return null; }
}

function requireLoginOrRedirect() {
  const token = getToken();
  if (!token) {
    window.location.replace("login.html");
    return false;
  }
  return true;
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = options.headers ? { ...options.headers } : {};
  if (token) headers.Authorization = `Bearer ${token}`;
  return fetch(`${window.API}${path}`, { ...options, headers });
}

async function logoutAndRedirect() {
  try { await apiFetch("/api/auth/logout", { method: "POST" }); } catch {}
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  window.location.replace("login.html");
}

function setNavUser() {
  const user = getUser();
  const el = document.getElementById("navUser");
  const creatorLink = document.getElementById("navCreator");
  if (!el) return;

  if (!user) {
    el.innerHTML = `<span class="muted">Guest</span>`;
    if (creatorLink) creatorLink.classList.add("d-none");
    return;
  }

  el.innerHTML = `<span class="muted">${user.email}</span> <span class="badge text-bg-dark ms-2">${user.role}</span>`;
  if (creatorLink) {
    if (user.role === "creator") creatorLink.classList.remove("d-none");
    else creatorLink.classList.add("d-none");
  }
}
