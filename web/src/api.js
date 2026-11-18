const prefix = window.location.pathname.replace(/\/$/, '');
let csrf = null;

export function setCsrf(value) { csrf = value; }

export async function api(path, options = {}) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (options.signal?.aborted) abort();
  options.signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => controller.abort(), 35000);
  try {
    const response = await fetch(`${prefix}/api${path}`, {
      method: options.method || 'GET', credentials: 'same-origin', signal: controller.signal,
      headers: { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401 && path !== '/auth/login') window.dispatchEvent(new Event('ftm-session-ended'));
      const error = new Error(typeof data.detail === 'string' ? data.detail : 'Не удалось выполнить запрос');
      error.status = response.status;
      throw error;
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Сервер отвечает дольше обычного. Попробуйте ещё раз');
    throw error;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', abort);
  }
}
