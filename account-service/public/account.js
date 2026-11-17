const statusBox = document.querySelector('#service-status');
const registerFields = document.querySelector('#register-fields');
const loginFields = document.querySelector('#login-fields');
const signedInPanel = document.querySelector('#signed-in-panel');
let csrfToken = '';

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');
  if (options.body !== undefined) headers.set('Content-Type', 'application/json');
  if (csrfToken) headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || data.error || `Request failed (${response.status})`);
  return data;
}

function show(formId, message, isError = true) {
  const target = document.querySelector(`#${formId}`);
  if (!target) return;
  target.textContent = message;
  target.style.color = isError ? 'var(--amber)' : 'var(--signal)';
}

function formValues(form) {
  return Object.fromEntries(new FormData(form).entries());
}

async function refreshAccount() {
  try {
    const data = await request('/api/account');
    document.querySelector('#account-summary').textContent = `${data.account.displayName} · ${data.account.email}`;
    document.querySelector('#consent-analytics').checked = Boolean(data.consents?.analyticsOptIn);
    document.querySelector('#consent-diagnostics').checked = Boolean(data.consents?.diagnosticsOptIn);
    signedInPanel.hidden = false;
    document.querySelector('#register-form').hidden = true;
    document.querySelector('#login-form').hidden = true;
  } catch (error) {
    signedInPanel.hidden = true;
  }
}

async function bootstrap() {
  try {
    const status = await request('/api/status');
    const csrf = await request('/api/auth/csrf');
    csrfToken = csrf.csrfToken || '';
    if (!status.accountsEnabled) {
      statusBox.innerHTML = '<p><strong>New registrations and optional data collection are paused.</strong> Retention and hosting backup requirements must be verified first. Existing account holders can sign in to review/export/delete their data or withdraw optional consent. Do not create a new account in this Preview.</p>';
      registerFields.disabled = true;
      document.querySelector('#register-form').hidden = true;
    } else {
      statusBox.innerHTML = '<p><strong>Account service is active.</strong> Optional analytics and diagnostics remain off unless you choose them below. See the <a href="/privacy">Privacy Policy</a> for fields and retention.</p>';
      registerFields.disabled = false;
    }
    loginFields.disabled = false;
    await refreshAccount();
  } catch (error) {
    statusBox.textContent = 'Account service status could not be verified. Sign-up and sign-in are unavailable; do not enter personal data.';
  }
}

document.querySelector('#register-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const values = formValues(form);
  try {
    const data = await request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email: values.email,
        displayName: values.displayName,
        password: values.password,
        termsAccepted: form.elements.termsAccepted.checked,
        privacyAcknowledged: form.elements.privacyAcknowledged.checked,
        analyticsOptIn: form.elements.analyticsOptIn.checked,
        diagnosticsOptIn: form.elements.diagnosticsOptIn.checked,
        client: 'web'
      })
    });
    csrfToken = data.csrfToken || csrfToken;
    show('register-status', 'Account created.', false);
    form.reset();
    await refreshAccount();
  } catch (error) { show('register-status', error.message); }
});

document.querySelector('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const values = formValues(event.currentTarget);
  try {
    const data = await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ email: values.email, password: values.password, client: 'web' }) });
    csrfToken = data.csrfToken || csrfToken;
    show('login-status', 'Signed in.', false);
    event.currentTarget.reset();
    await refreshAccount();
  } catch (error) { show('login-status', error.message); }
});

document.querySelector('#save-consent').addEventListener('click', async () => {
  try {
    const data = await request('/api/account/consent', {
      method: 'PATCH',
      body: JSON.stringify({ analyticsOptIn: document.querySelector('#consent-analytics').checked, diagnosticsOptIn: document.querySelector('#consent-diagnostics').checked })
    });
    show('consent-status', data.message || 'Choices saved. Turning a choice off deletes its previously collected optional records.', false);
  } catch (error) { show('consent-status', error.message); }
});

document.querySelector('#export-account').addEventListener('click', async () => {
  try {
    const data = await request('/api/account/export');
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'godark-account-export.json';
    link.click();
    URL.revokeObjectURL(url);
  } catch (error) { show('consent-status', error.message); }
});

document.querySelector('#sign-out').addEventListener('click', async () => {
  try { await request('/api/auth/logout', { method: 'POST', body: '{}' }); }
  finally { csrfToken = ''; window.location.reload(); }
});

document.querySelector('#delete-account').addEventListener('click', async () => {
  const password = document.querySelector('#delete-password').value;
  if (!password || !window.confirm('Delete this GoDark account and its account-linked optional telemetry? This cannot be undone.')) return;
  try {
    await request('/api/account', { method: 'DELETE', body: JSON.stringify({ password }) });
    csrfToken = '';
    show('delete-status', 'Account deleted.', false);
    window.location.reload();
  } catch (error) { show('delete-status', error.message); }
});

bootstrap();
