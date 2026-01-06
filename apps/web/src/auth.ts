export function getToken() {
  return null;
}

export function setToken(token: string) {
  void token;
}

export function clearToken() {
}

export async function apiFetch(input: RequestInfo, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});
  return fetch(input, { ...init, headers, credentials: "include" });
}
