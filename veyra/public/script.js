document.addEventListener('DOMContentLoaded', async () => {
  renderDecorations();
  bindAuthFlow();
  bindModalA11y();
  bindDashboardRange();
  bindShipmentActions();
  bindShipmentDetails();
  bindTeamManagement();
  bindIntegrationForms();
  await loadConfig();
  await restoreSession();
  fetchDashboardData();
  loadAdminConsole();
  window.VeyraViews?.onSessionChange();
  announceMailboxResult();
});

// Coming back from Google / Microsoft sign-in: say what happened, then clean the address.
function announceMailboxResult() {
  try {
    const params = new URLSearchParams(window.location.search);
    const result = params.get('mailbox');
    if (!result) return;
    if (result === 'connected') notify('Mailbox connected. New emails from now on are read.', 'ok');
    else notify(`The mailbox was not connected: ${String(params.get('reason') || 'unknown reason').slice(0, 200)}`, 'error');
    window.history.replaceState(null, '', window.location.pathname + window.location.hash);
  } catch (_) { /* not important */ }
}

let dashboardDays = 7;

/* ---------- region settings (units, currency, equipment, sign-up) ---------- */
const DEFAULT_EQUIPMENT = ['Dry Van', 'Tent / Curtainsider', 'Reefer', 'Flatbed', 'LTL', 'Expedited'];
window.VeyraConfig = { weightUnit: 'kg', currency: 'USD', equipment: DEFAULT_EQUIPMENT, registration: 'open' };

async function loadConfig() {
  try {
    const response = await fetch('/api/config');
    if (response.ok) window.VeyraConfig = { ...window.VeyraConfig, ...(await response.json()) };
  } catch (_) {
    // Keep defaults; the API will still validate everything.
  }
  applyConfig();
}

function applyConfig() {
  const config = window.VeyraConfig;
  document.querySelectorAll('[data-weight-unit]').forEach((node) => { node.textContent = config.weightUnit; });
  document.querySelectorAll('[data-currency]').forEach((node) => { node.textContent = config.currency; });
  document.querySelectorAll('select[data-equipment-select]').forEach((select) => {
    const placeholder = createTextElement('option', '', 'Choose equipment');
    placeholder.value = '';
    select.replaceChildren(placeholder, ...config.equipment.map((item) => createTextElement('option', '', item)));
  });
  // Closed sign-up: hide "Create one"; accounts come from an administrator.
  document.getElementById('authToggle')?.classList.toggle('hidden', config.registration === 'closed');
  const messageForm = document.getElementById('messageForm');
  if (messageForm && config.messaging?.language) messageForm.elements.language.value = config.messaging.language;
}

function formatMoney(value, digits = 2) {
  if (value === null || value === undefined || value === '' || Number.isNaN(Number(value))) return '—';
  try {
    return Number(value).toLocaleString('en-US', { style: 'currency', currency: window.VeyraConfig.currency, maximumFractionDigits: digits, minimumFractionDigits: digits });
  } catch (_) {
    return `${Number(value).toLocaleString('en-US', { maximumFractionDigits: digits })} ${window.VeyraConfig.currency}`;
  }
}

function formatEta(value) {
  if (!value) return '';
  const [day, time] = String(value).split('T');
  return `${formatDay(day)}${time ? ` ${time}` : ''}`;
}

// SQLite CURRENT_TIMESTAMP is UTC "YYYY-MM-DD HH:MM:SS"; show it in the viewer's local time.
function formatTimestamp(value) {
  if (!value) return '';
  const date = new Date(`${String(value).replace(' ', 'T')}Z`);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function hasPermission(permission) {
  const permissions = getCurrentPermissions();
  return permissions.includes('*') || permissions.includes(permission);
}

function notify(message, type = 'info') {
  if (window.VeyraViews?.toast) window.VeyraViews.toast(message, type === 'error' ? 'error' : type === 'info' ? 'info' : 'ok');
  else window.alert(message);
}

function isSignedIn() {
  try {
    return Boolean(JSON.parse(localStorage.getItem('veyraUser') || 'null'));
  } catch (_) {
    return false;
  }
}

function formatDay(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ''));
  if (!match) return value || '—';
  return new Date(Date.UTC(+match[1], +match[2] - 1, +match[3])).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
}

// Which channels (SMS / WhatsApp) this company can send with. Needs a signed-in user.
async function loadMessagingStatus(signedIn) {
  window.VeyraConfig.messaging = { ...(window.VeyraConfig.messaging || {}), channels: [] };
  if (!signedIn) return;
  try {
    const response = await fetch('/api/messaging/status', { headers: getAuthHeaders() });
    if (response.ok) window.VeyraConfig.messaging.channels = (await response.json()).channels || [];
  } catch (_) {
    // Sending simply stays off.
  }
}

async function restoreSession() {
  // Older builds kept a token in localStorage; sessions now live in an HttpOnly cookie only.
  localStorage.removeItem('veyraToken');
  const topButton = document.getElementById('loginTrigger');
  const logoutButton = document.getElementById('logoutTrigger');
  try {
    const response = await fetch('/api/me', { headers: getAuthHeaders() });
    if (!response.ok) {
      localStorage.removeItem('veyraUser');
      await loadMessagingStatus(false);
      if (topButton) { topButton.textContent = 'Login'; topButton.disabled = false; }
      if (logoutButton) logoutButton.classList.add('hidden');
      document.getElementById('adminPanel')?.classList.add('hidden');
      document.querySelector('.stats-grid')?.classList.add('hidden');
      document.querySelector('.chart-row')?.classList.add('hidden');
      applyUserChrome(null);
      return null;
    }

    const result = await response.json();
    const user = result.user;
    localStorage.setItem('veyraUser', JSON.stringify(user));
    await loadMessagingStatus(true);
    applyUserChrome(user);
    if (!topButton || !user?.name) return user;
    topButton.textContent = `Hi, ${user.name.split(' ')[0]}`;
    topButton.disabled = true; // signed in: shown as a greeting, not a control
    if (logoutButton) logoutButton.classList.remove('hidden');
    return user;
  } catch (error) {
    localStorage.removeItem('veyraUser');
    if (topButton) { topButton.textContent = 'Login'; topButton.disabled = false; }
    if (logoutButton) logoutButton.classList.add('hidden');
    document.getElementById('adminPanel')?.classList.add('hidden');
    applyUserChrome(null);
    return null;
  }
}

function getInitials(name) {
  return String(name || '')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part.charAt(0).toUpperCase())
    .join('') || '?';
}

function applyUserChrome(user) {
  const initials = user ? getInitials(user.name) : '?';
  const roleLabels = { admin: 'Administrator', operations: 'Operations Manager', operator: 'Operator' };
  const set = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };
  set('sidebarAvatar', initials);
  set('topAvatar', initials);
  set('sidebarUserName', user?.name || 'Guest');
  set('sidebarUserRole', user ? [roleLabels[user.role] || user.role, user.tenantName].filter(Boolean).join(' · ') : 'Sign in to continue');
  document.querySelectorAll('.prompt-meta').forEach((el) => { el.textContent = user ? initials : 'AC'; });
  document.getElementById('signedOutNote')?.classList.toggle('hidden', Boolean(user));
  if (!user) document.getElementById('navApprovalsBadge')?.classList.add('hidden');
}

function renderDecorations() {
  // Deterministic pseudo-random dots for the hero globe and tracking map.
  let seed = 7;
  const rand = () => {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  };
  const ns = 'http://www.w3.org/2000/svg';
  const globeDots = document.getElementById('globeDots');
  if (globeDots) {
    for (let i = 0; i < 260; i += 1) {
      const angle = rand() * Math.PI * 2;
      const radius = Math.sqrt(rand()) * 360;
      const dot = document.createElementNS(ns, 'circle');
      dot.setAttribute('cx', (400 + Math.cos(angle) * radius).toFixed(1));
      dot.setAttribute('cy', (400 + Math.sin(angle) * radius).toFixed(1));
      dot.setAttribute('r', (rand() * 1.6 + 0.4).toFixed(2));
      dot.setAttribute('opacity', (rand() * 0.7 + 0.15).toFixed(2));
      globeDots.append(dot);
    }
  }
  const mapDots = document.getElementById('mapDots');
  if (mapDots) {
    for (let i = 0; i < 140; i += 1) {
      const dot = document.createElementNS(ns, 'circle');
      dot.setAttribute('cx', (30 + rand() * 340).toFixed(1));
      dot.setAttribute('cy', (40 + rand() * 170).toFixed(1));
      dot.setAttribute('r', (rand() * 1.2 + 0.3).toFixed(2));
      dot.setAttribute('opacity', (rand() * 0.45 + 0.1).toFixed(2));
      mapDots.append(dot);
    }
  }
}

function getCurrentPermissions() {
  const user = JSON.parse(localStorage.getItem('veyraUser') || 'null');
  if (Array.isArray(user?.permissions)) return user.permissions;
  const rolePermissions = {
    admin: ['*'],
    operations: ['analytics:read', 'dashboard:read', 'carriers:read', 'carriers:write', 'shipments:read', 'shipments:create', 'shipments:status', 'shipments:dispatch', 'shipments:track', 'users:read'],
    operator: ['dashboard:read', 'carriers:read', 'shipments:read', 'shipments:create', 'shipments:track']
  };
  return rolePermissions[user?.role] || [];
}

function bindAuthFlow() {
  const authModal = document.getElementById('authModal');
  const loginTrigger = document.getElementById('loginTrigger');
  const logoutTrigger = document.getElementById('logoutTrigger');
  const closeAuth = document.getElementById('closeAuth');
  const authForm = document.getElementById('authForm');
  const authSwitch = document.getElementById('authSwitch');
  const authTitle = document.getElementById('authTitle');
  const authToggleLabel = document.getElementById('authToggleLabel');
  const authNameField = document.getElementById('authNameField');
  const authInviteField = document.getElementById('authInviteField');

  let isRegister = false;

  const openAuth = () => {
    if (authModal) authModal.classList.remove('hidden');
    document.getElementById('authEmail')?.focus();
  };
  if (loginTrigger) loginTrigger.addEventListener('click', openAuth);
  document.getElementById('getStartedBtn')?.addEventListener('click', (event) => {
    if (isSignedIn()) return; // anchor scrolls to the app
    event.preventDefault();
    openAuth();
    if (!isRegister && window.VeyraConfig.registration !== 'closed') authSwitch?.click();
  });
  document.getElementById('signedOutLogin')?.addEventListener('click', openAuth);

  if (logoutTrigger) {
    logoutTrigger.addEventListener('click', async () => {
      try {
        await fetch('/api/logout', {
          method: 'POST',
          headers: getAuthHeaders()
        });
      } catch (_) {
        // proceed with local cleanup
      }
      localStorage.removeItem('veyraUser');
      await restoreSession();
      const adminPanel = document.getElementById('adminPanel');
      if (adminPanel) adminPanel.classList.add('hidden');
      await fetchDashboardData();
      window.VeyraViews?.onSessionChange();
    });
  }

  if (closeAuth) {
    closeAuth.addEventListener('click', () => {
      if (authModal) authModal.classList.add('hidden');
      if (authForm) authForm.reset();
    });
  }

  if (authModal) {
    authModal.addEventListener('click', (event) => {
      if (event.target === authModal) {
        authModal.classList.add('hidden');
        if (authForm) authForm.reset();
      }
    });
  }

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && authModal) {
      authModal.classList.add('hidden');
      if (authForm) authForm.reset();
    }
  });

  if (authSwitch) {
    authSwitch.addEventListener('click', () => {
      isRegister = !isRegister;
      authTitle.textContent = isRegister ? 'Create an account' : 'Welcome back';
      authToggleLabel.textContent = isRegister ? 'Already have an account?' : 'Need an account?';
      authSwitch.textContent = isRegister ? 'Sign in' : 'Create one';
      const submitButton = authForm?.querySelector('button[type="submit"]');
      if (submitButton) submitButton.textContent = isRegister ? 'Create account' : 'Sign in';
      if (authNameField) {
        authNameField.style.display = isRegister ? 'grid' : 'none';
      }
      if (authInviteField) {
        authInviteField.style.display = isRegister && window.VeyraConfig.registration === 'invite' ? 'grid' : 'none';
      }
    });
  }

  if (authForm) {
    authForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      const email = document.getElementById('authEmail')?.value.trim();
      const password = document.getElementById('authPassword')?.value;
      const name = document.getElementById('authName')?.value.trim();
      const inviteCode = document.getElementById('authInviteCode')?.value.trim();

      if (!email || !password) return;

      const endpoint = isRegister ? '/api/register' : '/api/login';
      const payload = isRegister
        ? { name, email, password, ...(inviteCode ? { inviteCode } : {}) }
        : { email, password };

      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: getAuthHeaders(),
          body: JSON.stringify(payload)
        });

        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.message || 'Authentication failed');
        }

        localStorage.setItem('veyraUser', JSON.stringify(result.user));

        if (authModal) authModal.classList.add('hidden');
        if (authForm) authForm.reset();
        await restoreSession();
        await fetchDashboardData();
        await loadAdminConsole();
        window.VeyraViews?.onSessionChange();
      } catch (error) {
        notify(error.message, 'error');
      }
    });
  }
}

function bindShipmentActions() {
  const createShipmentBtn = document.getElementById('createShipmentBtn');
  const assistBtn = document.querySelector('.assist-btn');
  const modal = document.getElementById('shipmentModal');
  const form = document.getElementById('shipmentForm');
  const closeButton = document.getElementById('closeShipment');
  const message = document.getElementById('shipmentFormMessage');

  // options: { inboxId, missing: [field names to leave empty and flag], emailText }
  const openModal = (prefill, options = {}) => {
    if (!modal || !form) return;
    if (!isSignedIn()) {
      notify('Sign in to create a shipment.', 'info');
      document.getElementById('loginTrigger')?.click();
      return;
    }
    form.reset();
    const today = new Date();
    const delivery = new Date(today);
    delivery.setDate(delivery.getDate() + 1);
    form.elements.pickup.value = today.toISOString().slice(0, 10);
    form.elements.delivery.value = delivery.toISOString().slice(0, 10);
    const values = prefill && typeof prefill === 'object' && !(prefill instanceof Event) ? prefill : {};
    const extra = options && typeof options === 'object' && !(options instanceof Event) ? options : {};
    ['customer', 'customerPhone', 'reference', 'origin', 'destination', 'pickup', 'delivery', 'weight', 'equipment', 'customerRate'].forEach((name) => {
      if (values[name] !== undefined && values[name] !== null && form.elements[name]) form.elements[name].value = String(values[name]);
    });
    if (message) message.textContent = '';
    resetFlowIntake(form);
    // An order that came by email: remember which one, so creating the load closes it.
    window.VeyraPendingInbox = Number.isInteger(extra.inboxId) ? extra.inboxId : null;
    (extra.missing || []).forEach((name) => {
      const field = form.elements[name];
      if (!field) return;
      if (name === 'pickup' || name === 'delivery') field.value = '';
      field.classList.add('needs-input');
    });
    if (extra.emailText) {
      const text = document.getElementById('aiOrderText');
      if (text) text.value = extra.emailText;
    }
    modal.classList.remove('hidden');
    (window.VeyraConfig.ai?.enabled ? document.getElementById('aiOrderText') : form.elements.customer)?.focus();
  };
  window.openShipmentModal = openModal;
  bindFlowIntake(form);

  const closeModal = () => {
    if (modal) modal.classList.add('hidden');
    window.VeyraPendingInbox = null;
  };

  if (createShipmentBtn) createShipmentBtn.addEventListener('click', () => openModal(window.VeyraAssistant?.getDraft()));
  if (assistBtn) assistBtn.addEventListener('click', () => openModal());
  document.querySelectorAll('[data-new-shipment]').forEach((button) => button.addEventListener('click', () => openModal()));
  if (closeButton) closeButton.addEventListener('click', closeModal);
  if (modal) {
    modal.addEventListener('click', (event) => {
      if (event.target === modal) closeModal();
    });
  }
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeModal();
  });

  form?.addEventListener('input', (event) => event.target.classList?.remove('needs-input'));
  if (form) form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const formData = new FormData(form);
    const payload = Object.fromEntries(formData.entries());
    if (Number.isInteger(window.VeyraPendingInbox)) payload.inboxId = window.VeyraPendingInbox;
    const submitButton = form.querySelector('button[type="submit"]');
    if (submitButton) submitButton.disabled = true;
    if (message) message.textContent = 'Creating load...';

    try {
      const response = await fetch('/api/shipments', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(payload)
      });

      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Shipment creation failed');

      form.reset();
      form.querySelectorAll('.needs-input').forEach((node) => node.classList.remove('needs-input'));
      closeModal();
      window.VeyraAssistant?.reset();
      const createdId = result.shipment?.id ? `SHP-${String(result.shipment.id).replace(/^SHP-/, '')}` : 'Shipment';
      if (window.VeyraViews) {
        await window.VeyraViews.refresh();
        window.VeyraViews.toast(`${createdId} created. Move it to Sourcing to find a carrier.`);
      } else {
        await fetchDashboardData();
        await loadAdminConsole();
        notify(`${createdId} created. Move it to Sourcing to find a carrier.`, 'ok');
      }
    } catch (error) {
      if (message) message.textContent = error.message;
    }
    if (submitButton) submitButton.disabled = false;
  });
}

/* ---------- FLOW: order message -> form fields (a person reviews and presses Create) ---------- */
const FLOW_FIELDS = ['customer', 'customerPhone', 'reference', 'origin', 'destination', 'pickup', 'delivery', 'weight', 'equipment', 'customerRate'];
const FLOW_LABELS = { customer: 'customer', origin: 'origin', destination: 'destination', pickup: 'pickup date', delivery: 'delivery date', weight: 'weight', equipment: 'equipment' };

function resetFlowIntake(form) {
  document.getElementById('aiIntake')?.classList.toggle('hidden', !window.VeyraConfig.ai?.enabled);
  const text = document.getElementById('aiOrderText');
  if (text) text.value = '';
  const status = document.getElementById('aiIntakeMessage');
  if (status) status.textContent = '';
  document.getElementById('aiFindings')?.replaceChildren();
  form?.querySelectorAll('.needs-input').forEach((node) => node.classList.remove('needs-input'));
}

function bindFlowIntake(form) {
  const button = document.getElementById('aiIntakeButton');
  const text = document.getElementById('aiOrderText');
  const status = document.getElementById('aiIntakeMessage');
  const findings = document.getElementById('aiFindings');
  if (!button || !text || !form) return;
  button.addEventListener('click', async () => {
    if (!text.value.trim()) {
      status.textContent = 'Paste the customer\'s message first.';
      return;
    }
    button.disabled = true;
    status.textContent = 'FLOW is reading the message…';
    findings.replaceChildren();
    form.querySelectorAll('.needs-input').forEach((node) => node.classList.remove('needs-input'));
    try {
      const response = await fetch('/api/agents/flow/parse', { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ text: text.value }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'FLOW could not read the message');
      FLOW_FIELDS.forEach((name) => {
        const value = result.draft[name];
        if (value !== null && value !== undefined && form.elements[name]) form.elements[name].value = String(value);
      });
      result.missing.forEach((name) => {
        const field = form.elements[name];
        if (!field) return;
        // Clear the default dates: a date the customer never gave must not slip through.
        if (name === 'pickup' || name === 'delivery') field.value = '';
        field.classList.add('needs-input');
      });
      const items = [
        ...result.missing.map((name) => createTextElement('li', 'missing', `Missing: ${FLOW_LABELS[name] || name}. Ask the customer or fill it in.`)),
        ...result.notes.map((note) => createTextElement('li', 'note', note)),
        ...result.questions.map((question) => createTextElement('li', 'question', `Ask the customer: ${question}`))
      ];
      findings.replaceChildren(...items);
      status.textContent = result.missing.length
        ? `Filled what was in the message. ${result.missing.length} field(s) still needed — marked in yellow.`
        : 'All fields filled. Check them, then press Create load.';
    } catch (error) {
      status.textContent = error.message;
    }
    button.disabled = false;
  });
}

function createTextElement(tagName, className, text) {
  const element = document.createElement(tagName);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}

function allowedShipmentStatuses(status) {
  const transitions = {
    New: ['Sourcing', 'Cancelled'],
    // 'Dispatched' is set only by the Dispatch control (carrier + rate required).
    Sourcing: ['Pending Approval', 'Cancelled'],
    'Pending Approval': ['Sourcing', 'Cancelled'],
    Dispatched: ['In Transit', 'Exception', 'Cancelled'],
    'In Transit': ['Delivered', 'Exception'],
    Exception: ['In Transit', 'Cancelled']
  };
  return transitions[status] || [];
}

const TRACKABLE_STATUSES = ['Dispatched', 'In Transit', 'Exception'];

function getAuthHeaders() {
  return { 'Content-Type': 'application/json' };
}

async function loadAdminConsole() {
  const adminPanel = document.getElementById('adminPanel');
  const storedUser = JSON.parse(localStorage.getItem('veyraUser') || 'null');
  const permissions = getCurrentPermissions();

  if (!adminPanel || (!permissions.includes('*') && !permissions.includes('users:read'))) {
    if (adminPanel) adminPanel.classList.add('hidden');
    return;
  }

  adminPanel.classList.remove('hidden');

  const userFilterButtons = document.querySelectorAll('.filter-button[data-filter]');
  const shipmentFilterButtons = document.querySelectorAll('.filter-button[data-shipment-filter]');

  userFilterButtons.forEach((button) => {
    if (button.dataset.bound === 'true') return;
    button.dataset.bound = 'true';
    button.addEventListener('click', () => {
      userFilterButtons.forEach((btn) => btn.classList.toggle('active', btn === button));
      const filter = button.dataset.filter;
      const userList = document.getElementById('userList');
      if (!userList) return;

      userList.querySelectorAll('.admin-row').forEach((row) => {
        const matches = filter === 'all' || row.dataset.role === filter;
        row.style.display = matches ? 'flex' : 'none';
      });
    });
  });

  shipmentFilterButtons.forEach((button) => {
    if (button.dataset.bound === 'true') return;
    button.dataset.bound = 'true';
    button.addEventListener('click', () => {
      shipmentFilterButtons.forEach((btn) => btn.classList.toggle('active', btn === button));
      const filter = button.dataset.shipmentFilter;
      const shipmentList = document.getElementById('shipmentAdminList');
      if (!shipmentList) return;

      shipmentList.querySelectorAll('.shipment-row').forEach((row) => {
        const matches = filter === 'all' || row.dataset.status === filter;
        row.style.display = matches ? 'flex' : 'none';
      });
    });
  });

  try {
    const usersResponse = await fetch('/api/admin/users', {
      headers: getAuthHeaders()
    });
    const usersData = await usersResponse.json();
    if (usersResponse.ok && usersData.users) {
      const userList = document.getElementById('userList');
      const userCountLabel = document.getElementById('userCountLabel');
      if (userList) {
        const canManage = hasPermission('users:write');
        const userRows = usersData.users.map((user) => {
          const role = String(user.role || 'unknown');
          const safeRoleClass = ['admin', 'operations', 'operator'].includes(role) ? role : 'unknown';
          const row = createTextElement('div', `admin-row${user.active === false ? ' is-inactive' : ''}`);
          row.dataset.role = role;
          const userMeta = createTextElement('div', 'user-meta');
          userMeta.append(createTextElement('span', 'user-avatar', (user.name || '').charAt(0).toUpperCase()));
          const identity = document.createElement('div');
          identity.append(
            createTextElement('strong', '', user.name),
            createTextElement('small', '', user.email)
          );
          userMeta.append(identity);
          const controls = createTextElement('div', 'user-controls');
          const isSelf = Number(user.id) === Number(storedUser?.id);
          if (canManage && !isSelf) {
            const roleSelect = document.createElement('select');
            roleSelect.className = 'status-select';
            roleSelect.setAttribute('aria-label', `Role for ${user.name}`);
            [['operator', 'Operator'], ['operations', 'Operations'], ['admin', 'Admin']].forEach(([value, label]) => {
              const option = createTextElement('option', '', label);
              option.value = value;
              roleSelect.append(option);
            });
            roleSelect.value = role;
            roleSelect.addEventListener('change', () => updateTeamMember(user, { role: roleSelect.value }, roleSelect));
            const accessButton = createTextElement('button', 'btn btn-ghost small', user.active === false ? 'Enable' : 'Disable');
            accessButton.type = 'button';
            accessButton.addEventListener('click', () => updateTeamMember(user, { active: user.active === false }, accessButton));
            controls.append(roleSelect, accessButton);
          } else {
            controls.append(createTextElement('span', `user-role ${safeRoleClass}`, role));
          }
          if (user.active === false) controls.prepend(createTextElement('span', 'user-role inactive', 'Disabled'));
          row.append(userMeta, controls);
          return row;
        });
        userList.replaceChildren(...userRows);
      }
      document.getElementById('addUserToggle')?.classList.toggle('hidden', !hasPermission('users:write'));
      loadIntegrationsPanel();
      document.getElementById('companiesBox')?.classList.toggle('hidden', !storedUser?.isPlatformAdmin);
      if (storedUser?.isPlatformAdmin) loadCompaniesPanel();
      if (userCountLabel) userCountLabel.textContent = `${usersData.users.length} users`;
    }

    const shipmentsResponse = await fetch('/api/admin/shipments', {
      headers: getAuthHeaders()
    });
    const shipmentsData = await shipmentsResponse.json();
    if (shipmentsResponse.ok && shipmentsData.shipments) {
      const carriersResponse = await fetch('/api/carriers', { headers: getAuthHeaders() });
      const carriersData = carriersResponse.ok ? await carriersResponse.json() : [];
      const availableCarriers = Array.isArray(carriersData)
        ? carriersData.filter((carrier) => carrier.status === 'Available')
        : [];
      const analyticsResponse = await fetch('/api/analytics', { headers: getAuthHeaders() });
      const analyticsData = analyticsResponse.ok ? await analyticsResponse.json() : null;
      const summaryGrid = document.getElementById('adminSummaryGrid');
      if (summaryGrid) {
        const stats = analyticsData?.stats || {};
        const inTransitCount = analyticsData?.statuses?.['In Transit'] || 0;
        const exceptionCount = stats.exceptions || 0;
        const averageRate = Number(stats.averageRate || 0);
        const bookedRateLabel = averageRate ? formatMoney(averageRate, 0) : '-';

        const metrics = [
          ['Total loads', Number(stats.totalShipments || 0), `${Number(stats.activeShipments || 0)} open`],
          ['In transit', inTransitCount, 'Loads moving now'],
          ['Exception loads', exceptionCount, exceptionCount ? 'Needs operations review' : 'No exceptions'],
          ['Average booked rate', bookedRateLabel, 'Across priced loads']
        ];
        summaryGrid.replaceChildren(...metrics.map(([label, value, note]) => {
          const metric = createTextElement('div', 'mini-metric');
          metric.append(
            createTextElement('span', 'metric-label', label),
            createTextElement('strong', '', value),
            createTextElement('small', '', note)
          );
          return metric;
        }));
      }

      const shipmentList = document.getElementById('shipmentAdminList');
      if (shipmentList) {
        const shipmentRows = shipmentsData.shipments.map((shipment) => {
          const row = createTextElement('div', 'shipment-row');
          row.dataset.status = String(shipment.status || '');
          const shipmentInfo = createTextElement('div', 'shipment-info');
          const shipmentLabel = `${shipment.id || ''}${shipment.reference ? ` · ${shipment.reference}` : ''}`;
          shipmentInfo.append(
            createTextElement('strong', '', shipmentLabel),
            createTextElement('small', '', `${shipment.customer || ''} · ${shipment.origin || ''} → ${shipment.destination || ''}`),
            createTextElement('small', '', `${shipment.weight || ''} · ${shipment.equipment || ''} · Pickup ${shipment.pickup || ''}`)
          );
          if (shipment.carrierName) {
            shipmentInfo.append(createTextElement('small', '', `Carrier: ${shipment.carrierName} · ${formatMoney(shipment.rate)}${shipment.truckPlate ? ` · ${shipment.truckPlate}` : ''}`));
          }
          if (shipment.lastLocation && TRACKABLE_STATUSES.includes(shipment.status)) {
            shipmentInfo.append(createTextElement('small', '', `Now: ${shipment.lastLocation}${shipment.eta ? ` · ETA ${formatEta(shipment.eta)}` : ''}`));
          }

          const shipmentMeta = document.createElement('div');
          shipmentMeta.className = 'shipment-meta';
          const statusClass = String(shipment.status || '').toLowerCase().replace(/\s+/g, '-');
          shipmentMeta.append(createTextElement('span', `status-badge ${statusClass}`, shipment.status));

          const statusOptions = allowedShipmentStatuses(shipment.status);
          if (statusOptions.length) {
            const statusSelect = document.createElement('select');
            statusSelect.className = 'status-select';
            statusSelect.setAttribute('aria-label', `Update status for ${shipment.id}`);
            statusSelect.dataset.shipmentId = shipment.id;
            statusSelect.append(createTextElement('option', '', 'Update status'));
            statusSelect.options[0].value = '';
            statusOptions.forEach((status) => {
              const option = createTextElement('option', '', `Move to ${status}`);
              option.value = status;
              statusSelect.append(option);
            });
            shipmentMeta.append(statusSelect);
          } else {
            shipmentMeta.append(createTextElement('span', 'terminal-status', 'Closed'));
          }

          const detailsButton = createTextElement('button', 'shipment-detail-button', 'Details');
          detailsButton.type = 'button';
          detailsButton.dataset.shipmentId = shipment.id;
          const historyButton = createTextElement('button', 'history-button', 'History');
          historyButton.type = 'button';
          historyButton.dataset.shipmentId = shipment.id;
          shipmentMeta.append(detailsButton, historyButton);

          if (['Sourcing', 'Pending Approval'].includes(shipment.status)) {
            const dispatchControl = document.createElement('div');
            dispatchControl.className = 'dispatch-control';
            const carrierSelect = document.createElement('select');
            carrierSelect.className = 'carrier-select';
            carrierSelect.setAttribute('aria-label', `Select carrier for ${shipment.id}`);
            carrierSelect.disabled = availableCarriers.length === 0;
            const carrierPlaceholder = createTextElement('option', '', availableCarriers.length ? 'Select carrier' : 'No available carriers');
            carrierPlaceholder.value = '';
            carrierSelect.append(carrierPlaceholder);
            availableCarriers.forEach((carrier) => {
              const option = createTextElement('option', '', carrier.name);
              option.value = String(Number(carrier.id));
              carrierSelect.append(option);
            });

            const rateInput = document.createElement('input');
            rateInput.className = 'dispatch-rate';
            rateInput.type = 'number';
            rateInput.min = '1';
            rateInput.step = '0.01';
            rateInput.placeholder = `Rate ${window.VeyraConfig.currency}`;
            rateInput.setAttribute('aria-label', `Rate for ${shipment.id}`);

            const dispatchButton = createTextElement('button', 'dispatch-button', 'Dispatch');
            dispatchButton.type = 'button';
            dispatchButton.dataset.shipmentId = shipment.id;
            dispatchButton.disabled = availableCarriers.length === 0;
            dispatchControl.append(carrierSelect, rateInput, dispatchButton);
            shipmentMeta.append(dispatchControl);
          }

          const history = document.createElement('div');
          history.className = 'shipment-history hidden';
          history.dataset.historyFor = shipment.id;
          row.append(shipmentInfo, shipmentMeta, history);
          return row;
        });

        shipmentList.replaceChildren(...shipmentRows);

        shipmentList.querySelectorAll('.status-select').forEach((select) => {
          select.addEventListener('change', async (event) => {
            if (!event.target.value) return;
            const shipmentId = event.target.dataset.shipmentId;
            const status = event.target.value;

            try {
              const response = await fetch(`/api/admin/shipments/${shipmentId}/status`, {
                method: 'PATCH',
                headers: getAuthHeaders(),
                body: JSON.stringify({ status, note: `Status changed to ${status}` })
              });

              const result = await response.json();
              if (!response.ok) throw new Error(result.message || 'Status update failed');
              await fetchDashboardData();
              await loadAdminConsole();
            } catch (error) {
              notify(error.message, 'error');
              await loadAdminConsole();
            }
          });
        });

        shipmentList.querySelectorAll('.dispatch-button').forEach((button) => {
          button.addEventListener('click', async () => {
            const row = button.closest('.shipment-row');
            const carrierId = row.querySelector('.carrier-select')?.value;
            const rate = Number(row.querySelector('.dispatch-rate')?.value);
            if (!carrierId || !Number.isFinite(rate) || rate <= 0) {
              notify('Select an available carrier and enter a positive rate.', 'error');
              return;
            }
            button.disabled = true;
            try {
              const response = await fetch(`/api/admin/shipments/${button.dataset.shipmentId}/dispatch`, {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({ carrierId: Number(carrierId), rate })
              });
              const result = await response.json();
              if (!response.ok) throw new Error(result.message || 'Dispatch failed');
              await fetchDashboardData();
              await loadAdminConsole();
            } catch (error) {
              notify(error.message, 'error');
              button.disabled = false;
            }
          });
        });

        shipmentList.querySelectorAll('.history-button').forEach((button) => {
          button.addEventListener('click', async () => {
            const history = shipmentList.querySelector(`[data-history-for="${button.dataset.shipmentId}"]`);
            if (!history) return;
            if (!history.classList.contains('hidden')) {
              history.classList.add('hidden');
              return;
            }
            try {
              const response = await fetch(`/api/shipments/${button.dataset.shipmentId}/events`, { headers: getAuthHeaders() });
              const result = await response.json();
              if (!response.ok) throw new Error(result.message || 'History unavailable');
              const eventRows = result.events.map((entry) => {
                const eventRow = document.createElement('div');
                eventRow.className = 'history-event';
                eventRow.append(
                  createTextElement('strong', '', entry.status),
                  createTextElement('span', '', entry.note || ''),
                  createTextElement('time', '', entry.createdAt)
                );
                return eventRow;
              });
              if (!eventRows.length) eventRows.push(createTextElement('span', '', 'No activity recorded yet.'));
              history.replaceChildren(...eventRows);
              history.classList.remove('hidden');
            } catch (error) {
              notify(error.message, 'error');
            }
          });
        });

        shipmentList.querySelectorAll('.shipment-detail-button').forEach((button) => {
          button.addEventListener('click', () => openShipmentDetails(button.dataset.shipmentId));
        });
      }
    }
  } catch (error) {
    console.warn('Admin console unavailable:', error.message);
  }
}

async function updateTeamMember(user, change, control) {
  const describe = change.role ? `change ${user.name}'s role to ${change.role}` : `${change.active ? 'enable' : 'disable'} ${user.name}'s account`;
  if (!window.confirm(`Do you want to ${describe}? They will be signed out.`)) {
    await loadAdminConsole();
    return;
  }
  control.disabled = true;
  try {
    const response = await fetch(`/api/admin/users/${Number(user.id)}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify(change)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || 'Update failed');
    notify(`${user.name} updated.`, 'ok');
  } catch (error) {
    notify(error.message, 'error');
  }
  await loadAdminConsole();
}

/* ---------- Integrations panel ---------- */
function integrationRow(name, on, detail, extra) {
  const row = createTextElement('div', 'admin-row integration-row');
  const meta = createTextElement('div', 'user-meta');
  const text = document.createElement('div');
  text.append(createTextElement('strong', '', name), createTextElement('small', '', detail));
  meta.append(text);
  const controls = createTextElement('div', 'user-controls');
  controls.append(createTextElement('span', `user-role ${on ? 'operations' : 'inactive'}`, on ? 'On' : 'Off'));
  if (extra) controls.append(extra);
  row.append(meta, controls);
  return row;
}

const messagingSourceText = { company: 'your own Twilio account', platform: 'the platform owner\'s Twilio account' };

async function loadIntegrationsPanel() {
  const list = document.getElementById('integrationList');
  if (!list) return;
  try {
    const response = await fetch('/api/integrations/status', { headers: getAuthHeaders() });
    const status = await response.json();
    if (!response.ok) throw new Error(status.message || 'Unavailable');
    const admin = hasPermission('settings:write');
    const button = (label, handler) => {
      const node = createTextElement('button', 'btn btn-ghost small', label);
      node.type = 'button';
      node.addEventListener('click', handler);
      return node;
    };
    const messagingChannels = status.messaging.channels;
    list.replaceChildren(
      integrationRow('AI agents (FLOW, VAULT)', status.ai.enabled,
        status.ai.enabled
          ? `OpenRouter · model: ${status.ai.model || 'account default'} · automatic AI work stops at ${status.nexus.aiDailyLimit} calls a day. Reading CMR files needs a model that can read images or PDFs.`
          : 'Add OPENROUTER_API_KEY to the server settings to read orders and documents with AI.'),
      integrationRow('NEXUS (orchestrator)', status.nexus.enabled,
        status.nexus.enabled ? 'Prepares tasks from emails, bookings and quiet trucks. It never sends, books or changes anything on its own.' : 'Off (NEXUS_ENABLED=false).'),
      integrationRow('Order mailbox (IMAP)', status.mailbox.configured,
        status.mailbox.configured
          ? `${status.mailbox.user} on ${status.mailbox.host} · ${status.mailbox.lastError ? `last check failed: ${status.mailbox.lastError}` : (status.mailbox.lastCheckedAt ? `checked ${formatTimestamp(status.mailbox.lastCheckedAt)}, ${status.mailbox.lastImported || 0} new` : 'not checked yet')} · every ${status.mailbox.pollMinutes} min`
          : 'Connect a mailbox and VEYRA reads orders from it by itself. No forwarding set-up needed.',
        admin ? button(status.mailbox.configured ? 'Change' : 'Connect', () => toggleMailboxForm(status.mailbox)) : null),
      integrationRow('Map (distance, off-route)', status.map.enabled,
        status.map.enabled ? `OpenStreetMap services · a truck more than ${status.map.offRouteKm} km from the road is flagged (needs GPS) · live traffic: ${status.map.traffic ? 'on (TomTom)' : 'off'}` : 'Off. Set GEO_PROVIDER=osm on the server to add road distance and off-route warnings. Place names of loads are then sent to OpenStreetMap services.'),
      integrationRow('SCOUT, ROUTE, PULSE, SENTINEL', true, 'Built in, no key needed: carrier ranking, schedule check, price check and risk watch, all from your own loads.'),
      integrationRow('SMS / WhatsApp (RELAY)', messagingChannels.length > 0,
        messagingChannels.length
          ? `${messagingChannels.join(' + ').toUpperCase()} through ${messagingSourceText[status.messaging.source] || 'Twilio'}${status.messaging.accountHint ? ` (${status.messaging.accountHint})` : ''} · delivery reports (delivered / read): ${status.messaging.deliveryReports ? 'on' : 'off — set PUBLIC_URL on the server'}`
          : 'Drafts work and can be copied. To send from VEYRA, connect your Twilio account.',
        admin ? button(status.messaging.source === 'company' ? 'Change' : 'Connect Twilio', () => toggleMessagingForm(status.messaging)) : null),
      integrationRow('Email inbox', status.inbox.configured,
        status.inbox.configured ? `Orders emailed to your inbox address become tasks; attached files (up to ${status.inbox.maxFiles} per email) go to the load · ${status.inbox.allowedSenders.length ? `${status.inbox.allowedSenders.length} allowed sender(s)` : 'any sender allowed'}` : 'Create an address and point your email provider at it.',
        admin ? button(status.inbox.configured ? 'New address' : 'Create address', createInboxAddress) : null),
      integrationRow('GPS tracking', status.gps.configured,
        status.gps.configured ? `Connected · positions every ${status.gps.minIntervalMinutes} min are saved` : 'Create a token and give it to your GPS provider.',
        admin ? button(status.gps.configured ? 'New GPS token' : 'Create GPS token', createGpsToken) : null)
    );
    document.getElementById('mailboxRemove')?.classList.toggle('hidden', !status.mailbox.configured);
    const providerBox = document.getElementById('mailboxProviders');
    if (providerBox) {
      const choices = [['gmail', 'Connect Gmail'], ['outlook', 'Connect Outlook / Microsoft 365']].map(([name, label]) => {
        if (status.mailbox.providers?.[name]) {
          // A normal link: the browser goes to the provider's consent screen and comes back here.
          return Object.assign(createTextElement('a', 'btn btn-primary small', label), { href: `/api/settings/mail-oauth/${name}/start` });
        }
        const off = createTextElement('span', 'btn btn-ghost small disabled-chip', `${label} · not set up on the server`);
        off.setAttribute('aria-disabled', 'true');
        return off;
      });
      providerBox.replaceChildren(...choices);
    }
    const borderForm = document.getElementById('borderWaitsForm');
    if (borderForm) {
      borderForm.classList.toggle('hidden', !hasPermission('carriers:write'));
      if (hasPermission('carriers:write')) loadBorderWaits();
    }
    const marketForm = document.getElementById('marketRatesForm');
    if (marketForm) {
      marketForm.classList.toggle('hidden', !hasPermission('carriers:write'));
      if (hasPermission('carriers:write')) loadMarketRates();
    }
    const inboxForm = document.getElementById('inboxSettingsForm');
    if (inboxForm) {
      inboxForm.classList.toggle('hidden', !admin || !status.inbox.configured);
      inboxForm.elements.allowedSenders.value = status.inbox.allowedSenders.join(', ');
    }
    const removeButton = document.getElementById('messagingRemove');
    if (removeButton) removeButton.classList.toggle('hidden', status.messaging.source !== 'company');
  } catch (error) {
    list.replaceChildren(createTextElement('p', 'muted', `Integrations unavailable: ${error.message}`));
  }
}

async function loadBorderWaits() {
  const list = document.getElementById('borderWaitList');
  if (!list) return;
  try {
    const response = await fetch('/api/border-waits', { headers: getAuthHeaders() });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || 'Unavailable');
    const rows = result.waits.map((wait) => {
      const row = createTextElement('div', 'market-rate-row');
      const remove = createTextElement('button', 'btn btn-ghost small', 'Remove');
      remove.type = 'button';
      remove.addEventListener('click', async () => {
        await fetch(`/api/border-waits/${Number(wait.id)}`, { method: 'DELETE', headers: getAuthHeaders() });
        loadBorderWaits();
      });
      row.append(createTextElement('span', '', wait.pair.replace('-', ' ↔ ')), createTextElement('strong', '', `${wait.hours} h`), remove);
      return row;
    });
    list.replaceChildren(...(rows.length ? rows : [createTextElement('p', 'muted', 'No border times yet.')]));
  } catch (error) {
    list.replaceChildren(createTextElement('p', 'muted', `Border times unavailable: ${error.message}`));
  }
}

async function loadMarketRates() {
  const list = document.getElementById('marketRateList');
  if (!list) return;
  try {
    const response = await fetch('/api/market-rates', { headers: getAuthHeaders() });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || 'Unavailable');
    const rows = result.rates.map((rate) => {
      const row = createTextElement('div', 'market-rate-row');
      const remove = createTextElement('button', 'btn btn-ghost small', 'Remove');
      remove.type = 'button';
      remove.addEventListener('click', async () => {
        await fetch(`/api/market-rates/${Number(rate.id)}`, { method: 'DELETE', headers: getAuthHeaders() });
        loadMarketRates();
      });
      row.append(createTextElement('span', '', `${rate.origin} → ${rate.destination}${rate.equipment ? ` · ${rate.equipment}` : ''}`), createTextElement('strong', '', formatMoney(rate.rate)), remove);
      return row;
    });
    list.replaceChildren(...(rows.length ? rows : [createTextElement('p', 'muted', 'No market prices yet.')]));
  } catch (error) {
    list.replaceChildren(createTextElement('p', 'muted', `Market prices unavailable: ${error.message}`));
  }
}

function toggleMailboxForm(mailbox) {
  const form = document.getElementById('mailboxForm');
  if (!form) return;
  const open = form.classList.toggle('hidden') === false;
  if (open) {
    form.elements.host.value = mailbox.host || '';
    form.elements.user.value = mailbox.user || '';
    form.elements.mailbox.value = mailbox.mailbox || 'INBOX';
    form.elements.host.focus();
  }
}

function toggleMessagingForm(messagingStatus) {
  const form = document.getElementById('messagingForm');
  if (!form) return;
  const open = form.classList.toggle('hidden') === false;
  if (open) {
    form.elements.smsFrom.value = messagingStatus.smsFrom || '';
    form.elements.whatsappFrom.value = messagingStatus.whatsappFrom || '';
    form.elements.accountSid.focus();
  }
}

async function createInboxAddress() {
  const result = document.getElementById('gpsTokenResult');
  if (!window.confirm('Create a new inbox address? The previous address stops working.')) return;
  try {
    const response = await fetch('/api/settings/inbox/token', { method: 'POST', headers: getAuthHeaders() });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Address could not be created');
    const url = `${window.location.origin}${data.webhookPath}`;
    const copyButton = createTextElement('button', 'btn btn-ghost small', 'Copy address');
    copyButton.type = 'button';
    copyButton.addEventListener('click', () => navigator.clipboard?.writeText(url).then(() => notify('Address copied.', 'ok')).catch(() => {}));
    result.replaceChildren(
      createTextElement('strong', '', 'Your inbox address. It is shown only once.'),
      createTextElement('code', '', url),
      createTextElement('small', '', 'Give it to an email service that can post incoming mail to a web address (a "webhook"): Postmark inbound stream, Mailgun routes ("forward to URL"), or Zapier / Make (trigger: new email, action: webhook POST). Then forward customers\' orders to that service\'s address, or ask customers to write to it.'),
      createTextElement('small', '', 'Tip: set the allowed senders below so strangers cannot use your address.'),
      copyButton
    );
    result.classList.remove('hidden');
    loadIntegrationsPanel();
  } catch (error) {
    notify(error.message, 'error');
  }
}

function bindIntegrationForms() {
  const messagingForm = document.getElementById('messagingForm');
  const messagingMessage = document.getElementById('messagingFormMessage');
  messagingForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submit = messagingForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    messagingMessage.textContent = 'Checking with Twilio…';
    try {
      const body = {
        accountSid: messagingForm.elements.accountSid.value.trim(),
        smsFrom: messagingForm.elements.smsFrom.value.trim(),
        whatsappFrom: messagingForm.elements.whatsappFrom.value.trim()
      };
      if (messagingForm.elements.authToken.value) body.authToken = messagingForm.elements.authToken.value;
      const response = await fetch('/api/settings/messaging', { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Could not save');
      messagingForm.reset();
      messagingForm.classList.add('hidden');
      messagingMessage.textContent = '';
      notify('Twilio account connected. Messages now go through it.', 'ok');
      await loadMessagingStatus(true);
      loadIntegrationsPanel();
    } catch (error) {
      messagingMessage.textContent = error.message;
    }
    submit.disabled = false;
  });
  document.getElementById('messagingRemove')?.addEventListener('click', async () => {
    if (!window.confirm('Remove your Twilio account from VEYRA? Sending will stop.')) return;
    try {
      const response = await fetch('/api/settings/messaging', { method: 'DELETE', headers: getAuthHeaders() });
      if (!response.ok) throw new Error((await response.json()).message || 'Could not remove');
      messagingForm.classList.add('hidden');
      notify('Twilio account removed.', 'ok');
      await loadMessagingStatus(true);
      loadIntegrationsPanel();
    } catch (error) {
      notify(error.message, 'error');
    }
  });

  const borderForm = document.getElementById('borderWaitsForm');
  const borderMessage = document.getElementById('borderWaitsMessage');
  borderForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    borderMessage.textContent = '';
    try {
      const response = await fetch('/api/border-waits', { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ lines: borderForm.elements.lines.value }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Could not save');
      const problems = (result.errors || []).map((entry) => `line ${entry.line}: ${entry.message}`);
      borderMessage.textContent = problems.length ? `Saved ${result.created + result.updated}. Not saved — ${problems.slice(0, 3).join(' ')}` : '';
      if (!problems.length) borderForm.elements.lines.value = '';
      loadBorderWaits();
    } catch (error) {
      borderMessage.textContent = error.message;
    }
  });

  const mailboxForm = document.getElementById('mailboxForm');
  const mailboxMessage = document.getElementById('mailboxMessage');
  mailboxForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    mailboxMessage.textContent = 'Checking the mailbox…';
    const form = mailboxForm.elements;
    try {
      const response = await fetch('/api/settings/imap', {
        method: 'PUT', headers: getAuthHeaders(),
        body: JSON.stringify({ host: form.host.value, port: form.port.value, user: form.user.value, password: form.password.value, mailbox: form.mailbox.value })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Could not save');
      form.password.value = '';
      mailboxMessage.textContent = '';
      mailboxForm.classList.add('hidden');
      notify('Mailbox connected. New emails from now on are read.', 'ok');
      loadIntegrationsPanel();
    } catch (error) {
      mailboxMessage.textContent = error.message;
    }
  });
  document.getElementById('mailboxRemove')?.addEventListener('click', async () => {
    if (!window.confirm('Disconnect the mailbox? VEYRA stops reading it.')) return;
    await fetch('/api/settings/imap', { method: 'DELETE', headers: getAuthHeaders() });
    mailboxForm.classList.add('hidden');
    loadIntegrationsPanel();
  });

  const marketForm = document.getElementById('marketRatesForm');
  const marketMessage = document.getElementById('marketRatesMessage');
  marketForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    marketMessage.textContent = '';
    try {
      const response = await fetch('/api/market-rates', { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ lines: marketForm.elements.lines.value }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Could not save');
      const problems = (result.errors || []).map((entry) => `line ${entry.line}: ${entry.message}`);
      marketMessage.textContent = problems.length ? `Saved ${result.created + result.updated}. Not saved — ${problems.slice(0, 3).join(' ')}` : '';
      if (!problems.length) marketForm.elements.lines.value = '';
      notify(`${result.created} added, ${result.updated} updated.`, problems.length ? 'info' : 'ok');
      loadMarketRates();
    } catch (error) {
      marketMessage.textContent = error.message;
    }
  });

  const inboxForm = document.getElementById('inboxSettingsForm');
  const inboxMessage = document.getElementById('inboxSettingsMessage');
  inboxForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const allowedSenders = inboxForm.elements.allowedSenders.value.split(',').map((entry) => entry.trim()).filter(Boolean);
    inboxMessage.textContent = '';
    try {
      const response = await fetch('/api/settings/inbox', { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify({ allowedSenders }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Could not save');
      notify(allowedSenders.length ? 'Allowed senders saved.' : 'Everyone who knows the address is accepted.', 'ok');
      loadIntegrationsPanel();
    } catch (error) {
      inboxMessage.textContent = error.message;
    }
  });
}

async function createGpsToken() {
  const result = document.getElementById('gpsTokenResult');
  if (!window.confirm('Create a new GPS token? Any previous token stops working.')) return;
  try {
    const response = await fetch('/api/integrations/gps/token', { method: 'POST', headers: getAuthHeaders() });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Token could not be created');
    const url = `${window.location.origin}${data.webhookPath}`;
    const copyButton = createTextElement('button', 'btn btn-ghost small', 'Copy token');
    copyButton.type = 'button';
    copyButton.addEventListener('click', () => navigator.clipboard?.writeText(data.token).then(() => notify('Token copied.', 'ok')).catch(() => {}));
    result.replaceChildren(
      createTextElement('strong', '', 'Give these to your GPS provider. The token is shown only once.'),
      createTextElement('small', '', `Address (POST): ${url}`),
      createTextElement('code', '', data.token),
      createTextElement('small', '', 'Send as header "Authorization: Bearer <token>" (or ?token=<token>). Body: {"positions":[{"truckPlate":"01A123BC","lat":41.3,"lng":69.2,"speed":70}]}'),
      copyButton
    );
    result.classList.remove('hidden');
    loadIntegrationsPanel();
  } catch (error) {
    notify(error.message, 'error');
  }
}

/* ---------- Companies panel (platform owner only) ---------- */
async function loadCompaniesPanel() {
  const list = document.getElementById('companyList');
  if (!list) return;
  try {
    const response = await fetch('/api/platform/tenants', { headers: getAuthHeaders() });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Unavailable');
    list.replaceChildren(...data.tenants.map((tenant) => {
      const row = createTextElement('div', 'admin-row');
      const meta = createTextElement('div', 'user-meta');
      meta.append(createTextElement('span', 'user-avatar', tenant.name.charAt(0).toUpperCase()));
      const text = document.createElement('div');
      text.append(createTextElement('strong', '', tenant.name), createTextElement('small', '', `${tenant.users} users · ${tenant.shipments} loads`));
      meta.append(text);
      row.append(meta);
      return row;
    }));
  } catch (error) {
    list.replaceChildren(createTextElement('p', 'muted', error.message));
  }
}

function bindCompanyManagement() {
  const toggle = document.getElementById('addCompanyToggle');
  const form = document.getElementById('addCompanyForm');
  const message = document.getElementById('addCompanyMessage');
  if (!toggle || !form) return;
  toggle.addEventListener('click', () => {
    const open = form.classList.toggle('hidden') === false;
    toggle.setAttribute('aria-expanded', String(open));
    if (open) form.elements.companyName.focus();
  });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    message.textContent = '';
    try {
      const response = await fetch('/api/platform/tenants', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          companyName: form.elements.companyName.value.trim(),
          adminName: form.elements.adminName.value.trim(),
          adminEmail: form.elements.adminEmail.value.trim(),
          adminPassword: form.elements.adminPassword.value
        })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Could not create the company');
      form.reset();
      form.classList.add('hidden');
      toggle.setAttribute('aria-expanded', 'false');
      notify(`${result.tenant.name} created. ${result.admin.email} can sign in and add their team.`, 'ok');
      loadCompaniesPanel();
    } catch (error) {
      message.textContent = error.message;
    }
    submit.disabled = false;
  });
}

function bindTeamManagement() {
  bindCompanyManagement();
  const toggle = document.getElementById('addUserToggle');
  const form = document.getElementById('addUserForm');
  const message = document.getElementById('addUserMessage');
  if (!toggle || !form) return;
  toggle.addEventListener('click', () => {
    const open = form.classList.toggle('hidden') === false;
    toggle.setAttribute('aria-expanded', String(open));
    if (open) form.elements.name.focus();
  });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    message.textContent = '';
    try {
      const response = await fetch('/api/admin/users', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          name: form.elements.name.value.trim(),
          email: form.elements.email.value.trim(),
          role: form.elements.role.value,
          password: form.elements.password.value
        })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Could not create the account');
      form.reset();
      form.classList.add('hidden');
      toggle.setAttribute('aria-expanded', 'false');
      notify(`${result.user.name} can now sign in with ${result.user.email}. Share the starting password privately.`, 'ok');
      await loadAdminConsole();
    } catch (error) {
      message.textContent = error.message;
    }
    submit.disabled = false;
  });
}

function resetSignedOutDashboard() {
  const tableBody = document.querySelector('.table-block tbody');
  if (tableBody) {
    const row = document.createElement('tr');
    const cell = createTextElement('td', 'empty-cell', 'Sign in to see your shipments.');
    cell.colSpan = 7;
    row.append(cell);
    tableBody.replaceChildren(row);
  }
  ['userList', 'shipmentAdminList', 'adminSummaryGrid'].forEach((id) => document.getElementById(id)?.replaceChildren());
  document.getElementById('adminPanel')?.classList.add('hidden');
  document.querySelector('.stats-grid')?.classList.add('hidden');
  document.querySelector('.chart-row')?.classList.add('hidden');
  const badge = document.getElementById('navApprovalsBadge');
  if (badge) badge.classList.add('hidden');
  window.VeyraAssistant?.reset();
}

async function fetchDashboardData() {
  try {
    const response = await fetch(`/api/dashboard?days=${dashboardDays}`, {
      headers: getAuthHeaders()
    });
    if (response.status === 401) {
      resetSignedOutDashboard();
      return;
    }
    if (!response.ok) {
      throw new Error('Failed to load dashboard data');
    }

    const data = await response.json();
    updateDashboard(data);
  } catch (error) {
    console.warn('Dashboard data not loaded from API:', error.message);
  }
}

function updateDashboard(data) {
  const canReadAnalytics = getCurrentPermissions().includes('*') || getCurrentPermissions().includes('analytics:read');
  const statsGrid = document.querySelector('.stats-grid');
  const chartRow = document.querySelector('.chart-row');
  if (statsGrid) statsGrid.classList.toggle('hidden', !canReadAnalytics || !data?.stats);
  if (chartRow) chartRow.classList.toggle('hidden', !canReadAnalytics || !data?.statuses);

  const statValueEls = document.querySelectorAll('.stat-card .stat-value');
  const statValues = [
    data?.stats?.totalShipments ?? 0,
    data?.stats?.activeShipments ?? 0,
    data?.stats?.completed ?? 0,
    data?.stats?.availableCarriers ?? 0
  ];

  statValueEls.forEach((el, index) => {
    el.textContent = statValues[index];
  });

  const statusList = document.querySelector('.status-list');
  if (statusList && data?.statuses) {
    const statusItems = Array.from(statusList.querySelectorAll('[data-status]'));
    const statusColors = statusItems.map((item) => item.querySelector('.dot')?.style.getPropertyValue('--c').trim() || '#64748b');
    const statusTotal = Object.values(data.statuses).reduce((sum, count) => sum + Number(count || 0), 0);
    const stops = [];
    let offset = 0;

    statusItems.forEach((item, index) => {
      const key = item.dataset.status;
      const value = Number(data.statuses[key] || 0);
      const valueEl = item.querySelector('b');
      if (valueEl) valueEl.textContent = value;
      const nextOffset = statusTotal ? offset + (value / statusTotal) * 100 : offset;
      stops.push(`${statusColors[index]} ${offset}% ${nextOffset}%`);
      offset = nextOffset;
    });

    const statusTotalEl = document.getElementById('statusTotal');
    if (statusTotalEl) statusTotalEl.textContent = statusTotal;
    const donut = document.getElementById('statusDonut');
    if (donut) donut.style.background = statusTotal ? `conic-gradient(${stops.join(', ')})` : 'conic-gradient(#1e293b 0 100%)';

    const badge = document.getElementById('navApprovalsBadge');
    const pending = Number(data.statuses['Pending Approval'] || 0);
    if (badge) {
      badge.textContent = pending;
      badge.classList.toggle('hidden', pending === 0);
    }
  }

  if (Array.isArray(data?.weeklyVolume)) {
    const rawMax = Math.max(1, ...data.weeklyVolume.map((day) => Number(day.total)));
    const step = Math.max(1, Math.ceil(rawMax / 4));
    const max = step * 4;
    const points = data.weeklyVolume.map((entry, index) => {
      const x = data.weeklyVolume.length > 1 ? (index / (data.weeklyVolume.length - 1)) * 360 : 180;
      const y = 150 - (Number(entry.total) / max) * 150;
      return { x: Number(x.toFixed(1)), y: Number(y.toFixed(1)) };
    });
    const yAxis = document.getElementById('volumeYAxis');
    if (yAxis) yAxis.replaceChildren(...[4, 3, 2, 1, 0].map((n) => createTextElement('span', '', n * step)));
    const dots = document.getElementById('volumeDots');
    if (dots) {
      dots.replaceChildren(...(points.length > 14 ? [] : points).map((point, index) => {
        const dot = document.createElement('span');
        dot.style.left = `${(point.x / 360) * 100}%`;
        dot.style.top = `${(point.y / 150) * 100}%`;
        dot.title = `${data.weeklyVolume[index].label}: ${data.weeklyVolume[index].total}`;
        return dot;
      }));
    }
    const linePath = points.map((point, index) => `${index ? 'L' : 'M'}${point.x},${point.y}`).join(' ');
    const areaPath = `${linePath} L${points[points.length - 1]?.x || 360},150 L${points[0]?.x || 0},150 Z`;
    const line = document.getElementById('volumeLine');
    const area = document.getElementById('volumeArea');
    const labels = document.getElementById('volumeLabels');
    if (line) line.setAttribute('d', linePath || 'M0,140 L360,140');
    if (area) area.setAttribute('d', areaPath || 'M0,150 L360,150 Z');
    if (labels) {
      const every = data.weeklyVolume.length > 30 ? 15 : data.weeklyVolume.length > 14 ? 5 : 1;
      labels.replaceChildren(...data.weeklyVolume
        .filter((entry, index) => index % every === 0 || index === data.weeklyVolume.length - 1)
        .map((entry) => createTextElement('span', '', entry.label)));
    }
    const rangeLabel = document.getElementById('trendRange');
    if (rangeLabel) rangeLabel.textContent = `Last ${data.rangeDays || data.weeklyVolume.length} days`;
  }

  const tableBody = document.querySelector('.table-block tbody');
  if (tableBody && Array.isArray(data?.shipments)) {
    const shipmentRows = data.shipments.slice(0, 5).map((shipment) => {
      const row = document.createElement('tr');
      const tagClass = String(shipment.status || '').toLowerCase().replace(/\s+/g, '-');
      [shipment.id, shipment.customer, `${shipment.origin} → ${shipment.destination}`, formatDay(shipment.pickup), formatDay(shipment.delivery)].forEach((value) => {
        row.append(createTextElement('td', '', value));
      });

      const statusCell = document.createElement('td');
      statusCell.append(createTextElement('span', `tag ${tagClass}`, shipment.status));
      row.append(statusCell);

      const detailCell = document.createElement('td');
      const detailButton = createTextElement('button', 'table-detail-button', 'View');
      detailButton.type = 'button';
      detailButton.dataset.shipmentId = shipment.id;
      detailCell.append(detailButton);
      row.append(detailCell);
      return row;
    });
    if (!shipmentRows.length) {
      const emptyRow = document.createElement('tr');
      const emptyCell = createTextElement('td', 'empty-cell', 'No shipments yet. Use New Shipment to create your first load.');
      emptyCell.colSpan = 7;
      emptyRow.append(emptyCell);
      shipmentRows.push(emptyRow);
    }
    tableBody.replaceChildren(...shipmentRows);
    tableBody.querySelectorAll('.table-detail-button').forEach((button) => {
      button.addEventListener('click', () => openShipmentDetails(button.dataset.shipmentId));
    });
  }

  window.VeyraAssistant?.sync(data);
}

let detailsShipmentId = null;

/* ---------- VAULT: documents attached to a load ---------- */
const DOC_TYPE_LABELS = { cmr: 'CMR', pod: 'Proof of delivery', other: 'Other' };
let documentPollTimer = null;

function formatSize(bytes) {
  return bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

async function loadDocuments(shipmentId) {
  const list = document.getElementById('documentList');
  const status = document.getElementById('documentsStatus');
  const form = document.getElementById('documentForm');
  if (!list) return;
  clearTimeout(documentPollTimer);
  form?.classList.toggle('hidden', !hasPermission('shipments:document'));
  try {
    const response = await fetch(`/api/shipments/${encodeURIComponent(shipmentId)}/documents`, { headers: getAuthHeaders() });
    const result = response.ok ? await response.json() : { documents: [], readsDocuments: false };
    if (detailsShipmentId !== shipmentId) return;
    if (status) status.textContent = result.readsDocuments ? 'AI reads CMR and proof of delivery' : 'Reading is off · files are kept';
    const canRead = result.readsDocuments && hasPermission('shipments:document');
    const canDelete = hasPermission('shipments:status');
    const cards = result.documents.map((doc) => documentCard(shipmentId, doc, canRead, canDelete));
    if (!cards.length) cards.push(createTextElement('p', 'muted', 'No documents yet. Upload the CMR when the truck is loaded.'));
    list.replaceChildren(...cards);
    // The AI reads in the background; check again until it is done.
    if (result.documents.some((doc) => doc.extractionStatus === 'pending')) {
      documentPollTimer = setTimeout(() => loadDocuments(shipmentId), 3000);
    }
  } catch (_) {
    list.replaceChildren(createTextElement('p', 'muted', 'Documents unavailable.'));
  }
}

function documentCard(shipmentId, doc, canRead, canDelete) {
  const card = createTextElement('div', 'document-card');
  const head = createTextElement('div', 'document-head');
  const title = document.createElement('div');
  title.append(
    createTextElement('strong', '', doc.filename),
    createTextElement('small', '', `${DOC_TYPE_LABELS[doc.type] || doc.type} · ${formatSize(doc.size)} · ${formatTimestamp(doc.createdAt)}${doc.uploadedBy ? ` · ${doc.uploadedBy}` : ''}`)
  );
  const buttons = createTextElement('div', 'document-buttons');
  const download = Object.assign(createTextElement('a', 'btn btn-ghost small', 'Download'), {
    href: `/api/shipments/${encodeURIComponent(shipmentId)}/documents/${Number(doc.id)}/file`
  });
  buttons.append(download);
  if (hasPermission('shipments:document')) {
    // A file's type is only guessed when it comes by email: a person can correct it.
    const typeSelect = createTextElement('select', 'doc-type-select');
    typeSelect.setAttribute('aria-label', 'Document type');
    Object.entries(DOC_TYPE_LABELS).forEach(([value, label]) => {
      const option = createTextElement('option', '', label);
      option.value = value;
      typeSelect.append(option);
    });
    typeSelect.value = doc.type;
    typeSelect.addEventListener('change', async () => {
      typeSelect.disabled = true;
      try {
        const response = await fetch(`/api/shipments/${encodeURIComponent(shipmentId)}/documents/${Number(doc.id)}`, { method: 'PATCH', headers: getAuthHeaders(), body: JSON.stringify({ type: typeSelect.value }) });
        if (!response.ok) throw new Error((await response.json()).message || 'Could not change the type');
      } catch (error) {
        notify(error.message, 'error');
      }
      loadDocuments(shipmentId);
    });
    buttons.append(typeSelect);
  }
  if (canRead && ['skipped', 'failed'].includes(doc.extractionStatus) && ['cmr', 'pod'].includes(doc.type)) {
    const read = createTextElement('button', 'btn btn-ghost small', 'Read with AI');
    read.type = 'button';
    read.addEventListener('click', async () => {
      read.disabled = true;
      try {
        const response = await fetch(`/api/shipments/${encodeURIComponent(shipmentId)}/documents/${Number(doc.id)}/extract`, { method: 'POST', headers: getAuthHeaders() });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message || 'Could not start reading');
      } catch (error) {
        notify(error.message, 'error');
      }
      loadDocuments(shipmentId);
    });
    buttons.append(read);
  }
  if (canDelete) {
    const remove = createTextElement('button', 'btn btn-ghost small', 'Delete');
    remove.type = 'button';
    remove.addEventListener('click', async () => {
      if (!window.confirm(`Delete ${doc.filename}?`)) return;
      try {
        const response = await fetch(`/api/shipments/${encodeURIComponent(shipmentId)}/documents/${Number(doc.id)}`, { method: 'DELETE', headers: getAuthHeaders() });
        if (!response.ok) throw new Error((await response.json()).message || 'Could not delete');
        window.VeyraViews?.refresh();
      } catch (error) {
        notify(error.message, 'error');
      }
      loadDocuments(shipmentId);
    });
    buttons.append(remove);
  }
  head.append(title, buttons);
  card.append(head);

  if (doc.extractionStatus === 'pending') {
    card.append(createTextElement('p', 'muted', 'AI is reading this document…'));
  } else if (doc.extractionStatus === 'done' && doc.comparison) {
    const labels = { ok: 'matches', mismatch: 'differs', unknown: 'not clear' };
    const rows = doc.comparison.checks.map((check) => {
      const row = createTextElement('tr', `check-${check.status}`);
      row.append(
        createTextElement('td', '', check.label),
        createTextElement('td', '', check.document ?? '—'),
        createTextElement('td', '', check.load ?? '—'),
        createTextElement('td', '', `${labels[check.status]}${check.hint && check.status === 'mismatch' ? ` · ${check.hint}` : ''}`)
      );
      return row;
    });
    const head = document.createElement('thead');
    const headRow = document.createElement('tr');
    ['Field', 'Document says', 'Load says', ''].forEach((text) => headRow.append(createTextElement('th', '', text)));
    head.append(headRow);
    const body = document.createElement('tbody');
    body.append(...rows);
    const table = document.createElement('table');
    table.className = 'data-table compact';
    table.append(head, body);
    const wrap = createTextElement('div', 'table-scroll');
    wrap.append(table);
    card.append(wrap);
    const extracted = doc.extracted || {};
    if (extracted.signedByConsignee !== null && extracted.signedByConsignee !== undefined) {
      card.append(createTextElement('p', 'muted', extracted.signedByConsignee ? 'Receiver signature or stamp found.' : 'No receiver signature on the document.'));
    }
    if (extracted.notes) card.append(createTextElement('p', 'muted', `Remark on the document: ${extracted.notes}`));
    card.append(createTextElement('p', doc.comparison.mismatches ? 'warn-line' : 'muted', doc.comparison.mismatches
      ? `${doc.comparison.mismatches} difference${doc.comparison.mismatches === 1 ? '' : 's'}: check the paper against the load. Nothing was changed.`
      : 'Everything that could be read matches the load.'));
  } else if (doc.error) {
    card.append(createTextElement('p', 'muted', doc.extractionStatus === 'failed' ? `Could not be read: ${doc.error} (a model that can read images or PDFs is needed).` : doc.error));
  }
  return card;
}

function bindDocumentForm() {
  const form = document.getElementById('documentForm');
  const message = document.getElementById('documentFormMessage');
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const file = form.elements.file.files[0];
    if (!file || !detailsShipmentId) return;
    const maxBytes = (window.VeyraConfig.documents?.maxMb || 8) * 1048576;
    if (file.size > maxBytes) {
      message.textContent = `The file is larger than ${window.VeyraConfig.documents?.maxMb || 8} MB.`;
      return;
    }
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    message.textContent = 'Uploading…';
    try {
      const response = await fetch(`/api/shipments/${encodeURIComponent(detailsShipmentId)}/documents?type=${encodeURIComponent(form.elements.type.value)}&filename=${encodeURIComponent(file.name)}`, {
        method: 'POST',
        headers: { 'Content-Type': file.type },
        body: file
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Upload failed');
      form.reset();
      message.textContent = result.duplicate ? 'That file is already attached.' : '';
    } catch (error) {
      message.textContent = error.message;
    }
    submit.disabled = false;
    loadDocuments(detailsShipmentId);
  });
}

/* ---------- RELAY: drafted messages to driver / carrier / customer ---------- */
const MESSAGE_PURPOSES = {
  driver: [['location_request', 'Ask for location'], ['pickup_details', 'Pickup details']],
  carrier: [['booking_confirmation', 'Booking confirmation']],
  customer: [['status_update', 'Status update'], ['booking_confirmation', 'Truck booked'], ['delivered', 'Delivered']]
};
let messageTargetPhone = null;

function fillPurposeOptions(form) {
  const options = MESSAGE_PURPOSES[form.elements.recipient.value] || [];
  form.elements.purpose.replaceChildren(...options.map(([value, label]) => {
    const option = createTextElement('option', '', label);
    option.value = value;
    return option;
  }));
}

async function loadMessageDraft() {
  const form = document.getElementById('messageForm');
  const status = document.getElementById('messageFormMessage');
  if (!form || !detailsShipmentId) return;
  status.textContent = 'Preparing the text…';
  try {
    const response = await fetch(`/api/shipments/${encodeURIComponent(detailsShipmentId)}/messages/draft`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ recipient: form.elements.recipient.value, purpose: form.elements.purpose.value, language: form.elements.language.value })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || 'Draft failed');
    form.elements.body.value = result.draft.body;
    messageTargetPhone = result.draft.to;
    updateMessageSendState();
  } catch (error) {
    status.textContent = error.message;
  }
}

function updateMessageSendState() {
  const form = document.getElementById('messageForm');
  const status = document.getElementById('messageFormMessage');
  const send = document.getElementById('messageSend');
  if (!form || !status || !send) return;
  const channels = window.VeyraConfig.messaging?.channels || [];
  const channelOn = channels.includes(form.elements.channel.value);
  send.disabled = !messageTargetPhone || !channelOn;
  if (!messageTargetPhone) status.textContent = `No ${form.elements.recipient.value} phone number on this load. Add it, or copy the text.`;
  else if (!channelOn) status.textContent = `To: ${messageTargetPhone}. Automatic sending is off — copy the text and send it from your phone.`;
  else status.textContent = `To: ${messageTargetPhone}`;
}

function bindMessageForm() {
  const form = document.getElementById('messageForm');
  if (!form) return;
  fillPurposeOptions(form);
  form.elements.recipient.addEventListener('change', () => { fillPurposeOptions(form); loadMessageDraft(); });
  form.elements.purpose.addEventListener('change', loadMessageDraft);
  form.elements.language.addEventListener('change', loadMessageDraft);
  form.elements.channel.addEventListener('change', updateMessageSendState);
  document.getElementById('messageCopy')?.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(form.elements.body.value);
      notify('Text copied. Paste it into WhatsApp or SMS on your phone.', 'ok');
    } catch (_) {
      form.elements.body.select();
      notify('Select the text and copy it (Ctrl+C).', 'info');
    }
  });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const status = document.getElementById('messageFormMessage');
    const send = document.getElementById('messageSend');
    send.disabled = true;
    status.textContent = 'Sending…';
    try {
      const response = await fetch(`/api/shipments/${encodeURIComponent(detailsShipmentId)}/messages`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ recipient: form.elements.recipient.value, channel: form.elements.channel.value, body: form.elements.body.value })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Message not sent');
      notify(`Message sent to ${result.message.to}.`, 'ok');
    } catch (error) {
      notify(error.message, 'error');
    }
    await renderMessageList(detailsShipmentId);
    updateMessageSendState();
  });
}

async function renderMessageList(shipmentId) {
  const list = document.getElementById('messageList');
  if (!list) return;
  try {
    const response = await fetch(`/api/shipments/${encodeURIComponent(shipmentId)}/messages`, { headers: getAuthHeaders() });
    const result = response.ok ? await response.json() : { messages: [] };
    const items = (result.messages || []).map((entry) => {
      const item = createTextElement('div', `detail-timeline-item message-${entry.status}`);
      const content = document.createElement('div');
      const channel = entry.channel === 'whatsapp' ? 'WhatsApp' : 'SMS';
      // The provider's delivery report, when there is one, says more than "sent".
      const delivery = { delivered: 'delivered ✓✓', read: 'read ✓✓', failed: 'not delivered', undelivered: 'not delivered', sent: 'sent ✓', sending: 'sending…', queued: 'sending…' }[entry.deliveryStatus];
      const state = entry.status !== 'sent' ? 'not sent' : (delivery || 'sent ✓');
      const failed = ['failed', 'undelivered'].includes(entry.deliveryStatus);
      if (failed) item.classList.add('message-failed');
      if (['delivered', 'read'].includes(entry.deliveryStatus)) item.classList.add(`message-${entry.deliveryStatus}`);
      content.append(
        createTextElement('strong', '', `${channel} to ${entry.recipientType} · ${state}`),
        createTextElement('p', '', entry.body),
        entry.error ? createTextElement('p', 'warn-line', entry.error) : '',
        failed ? createTextElement('p', 'warn-line', `The number did not receive this message${entry.errorCode ? ` (provider code ${entry.errorCode})` : ''}. Check the number and call instead.`) : '',
        createTextElement('time', '', `${formatTimestamp(entry.createdAt)} · ${entry.toPhone}${entry.sentBy ? ` · ${entry.sentBy}` : ''}`)
      );
      item.append(createTextElement('span', 'timeline-marker'), content);
      return item;
    });
    if (!items.length) items.push(createTextElement('p', 'muted', 'No messages sent from VEYRA for this load yet.'));
    list.replaceChildren(...items);
  } catch (_) {
    list.replaceChildren(createTextElement('p', 'muted', 'Messages unavailable.'));
  }
}

function bindShipmentDetails() {
  const modal = document.getElementById('shipmentDetailsModal');
  const closeButton = document.getElementById('closeShipmentDetails');
  const closeDetails = () => {
    modal?.classList.add('hidden');
    detailsShipmentId = null;
    clearTimeout(documentPollTimer);
  };
  if (closeButton) closeButton.addEventListener('click', closeDetails);
  if (modal) {
    modal.addEventListener('click', (event) => {
      if (event.target === modal) closeDetails();
    });
  }
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && modal && !modal.classList.contains('hidden')) closeDetails();
  });

  bindMessageForm();
  bindDocumentForm();
  const trackingForm = document.getElementById('trackingForm');
  const trackingMessage = document.getElementById('trackingFormMessage');
  trackingForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!detailsShipmentId) return;
    const submit = trackingForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    trackingMessage.textContent = '';
    try {
      const response = await fetch(`/api/shipments/${encodeURIComponent(detailsShipmentId)}/tracking`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          location: trackingForm.elements.location.value.trim(),
          eta: trackingForm.elements.eta.value || undefined,
          note: trackingForm.elements.note.value.trim() || undefined
        })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'Location update failed');
      trackingForm.reset();
      notify(`Location saved for ${detailsShipmentId}.`, 'ok');
      await openShipmentDetails(detailsShipmentId);
      window.VeyraViews?.refresh();
    } catch (error) {
      trackingMessage.textContent = error.message;
    }
    submit.disabled = false;
  });
}

/* ---------- ROUTE and PULSE: advice from the company's own past loads ---------- */
function adviceBlock(title, lines) {
  const block = createTextElement('div', 'advice-item');
  block.append(createTextElement('strong', '', title));
  lines.forEach(([text, className]) => block.append(createTextElement('p', className || '', text)));
  return block;
}

function pulseLines(pulse) {
  const lines = [];
  if (pulse.carrier) lines.push([`Carriers on this lane: usually ${formatMoney(pulse.carrier.typical)} (${formatMoney(pulse.carrier.lowest)} – ${formatMoney(pulse.carrier.highest)}, ${pulse.carrier.loads} loads, ${pulse.basis}).`]);
  if (pulse.customer) lines.push([`Customers on this lane: usually ${formatMoney(pulse.customer.typical)}.`]);
  if (pulse.suggestedCustomerPrice) lines.push([`Suggested customer price: ${formatMoney(pulse.suggestedCustomerPrice)} — ${pulse.suggestionBasis}.`]);
  (pulse.flags || []).forEach((flag) => lines.push([flag.text, flag.level === 'warn' ? 'warn-line' : 'muted']));
  if (!lines.length) lines.push(['Not enough past loads on this lane to compare prices yet (3 needed).', 'muted']);
  return lines;
}
window.VeyraPulseLines = pulseLines;
window.VeyraAdviceBlock = adviceBlock;

async function loadShipmentAdvice(shipment) {
  const box = document.getElementById('shipmentAdvice');
  if (!box) return;
  box.replaceChildren();
  try {
    const id = encodeURIComponent(shipment.id);
    const [routeResponse, pulseResponse] = await Promise.all([
      fetch(`/api/agents/route/${id}`, { headers: getAuthHeaders() }),
      fetch(`/api/agents/pulse/${id}`, { headers: getAuthHeaders() })
    ]);
    if (detailsShipmentId !== shipment.id) return;
    const blocks = [];
    if (routeResponse.ok) {
      const route = await routeResponse.json();
      const lines = route.map ? [[`By road: ${route.map.distanceKm} km, ${route.map.drivingHours} h of driving (about ${route.map.withRestsHours} h with rests).`]] : [];
      lines.push([route.schedule.text, route.schedule.verdict === 'tight' ? 'warn-line' : (route.schedule.verdict === 'unknown' ? 'muted' : '')]);
      if (route.arrival) {
        lines.push([`Probable arrival: ${formatTimestamp(route.arrival.at)} (${route.arrival.basis})${route.arrival.late ? ' — after the promised delivery day' : ''}.`, route.arrival.late ? 'warn-line' : '']);
      }
      if (route.border) lines.push([`Border ${route.border.pair.replace('-', ' ↔ ')}: usually ${route.border.hours} h of waiting${route.border.counted ? ' (added to the estimate)' : ' (already part of past trips on this lane)'}.`]);
      if (route.traffic) lines.push([`Traffic now: ${route.traffic.delayMinutes ? `${route.traffic.delayMinutes} min of delay` : 'no delay'} on the road (${route.traffic.travelHours} h of driving at today's speed).`, route.traffic.delayMinutes >= 60 ? 'warn-line' : '']);
      (route.returnTrucks || []).forEach((truck) => lines.push([`Return truck: ${truck.name}${truck.phone ? `, ${truck.phone}` : ''}. ${truck.note}`]));
      blocks.push(adviceBlock('ROUTE · schedule', lines));
    }
    if (pulseResponse.ok) blocks.push(adviceBlock('PULSE · prices', pulseLines(await pulseResponse.json())));
    box.replaceChildren(...blocks);
  } catch (_) {
    box.replaceChildren();
  }
}

async function openShipmentDetails(shipmentId) {
  if (!isSignedIn()) {
    notify('Sign in to view shipment details.', 'info');
    document.getElementById('loginTrigger')?.click();
    return;
  }
  const modal = document.getElementById('shipmentDetailsModal');
  const timeline = document.getElementById('shipmentDetailTimeline');
  try {
    const id = encodeURIComponent(shipmentId);
    const [shipmentResponse, eventsResponse, trackingResponse] = await Promise.all([
      fetch(`/api/shipments/${id}`, { headers: getAuthHeaders() }),
      fetch(`/api/shipments/${id}/events`, { headers: getAuthHeaders() }),
      fetch(`/api/shipments/${id}/tracking`, { headers: getAuthHeaders() })
    ]);
    const shipment = await shipmentResponse.json();
    const events = await eventsResponse.json();
    const tracking = trackingResponse.ok ? await trackingResponse.json() : { updates: [] };
    if (!shipmentResponse.ok || !eventsResponse.ok) throw new Error('Shipment details unavailable. Sign in and try again.');
    detailsShipmentId = shipment.id;

    const driver = [shipment.driverName, shipment.driverPhone].filter(Boolean).join(', ');
    const values = {
      customer: shipment.customer,
      reference: shipment.reference,
      route: `${shipment.origin} → ${shipment.destination}`,
      dates: `${shipment.pickup} / ${shipment.delivery}`,
      freight: `${shipment.weight || '-'} / ${shipment.equipment || '-'}`,
      carrier: shipment.carrierName ? `${shipment.carrierName} / ${formatMoney(shipment.rate)}` : 'Unassigned',
      price: shipment.customerRate !== null && shipment.customerRate !== undefined
        ? `${formatMoney(shipment.customerRate)}${shipment.margin !== null && shipment.margin !== undefined ? ` / margin ${formatMoney(shipment.margin)}` : ''}`
        : '',
      driver: [driver, shipment.truckPlate].filter(Boolean).join(' / '),
      carrierPhone: shipment.carrierPhone,
      location: shipment.lastLocation
        ? `${shipment.lastLocation}${shipment.eta ? ` · ETA ${formatEta(shipment.eta)}` : ''} (${formatTimestamp(shipment.lastTrackedAt)})`
        : (TRACKABLE_STATUSES.includes(shipment.status) ? 'No location update yet' : ''),
      status: shipment.status,
      tracking: shipment.trackingNumber
    };

    const trackingForm = document.getElementById('trackingForm');
    const canTrack = hasPermission('shipments:track') && TRACKABLE_STATUSES.includes(shipment.status);
    trackingForm?.classList.toggle('hidden', !canTrack);
    const trackingMessage = document.getElementById('trackingFormMessage');
    if (trackingMessage) trackingMessage.textContent = '';
    const trackingList = document.getElementById('trackingList');
    if (trackingList) {
      const items = (tracking.updates || []).map((entry) => {
        const item = createTextElement('div', 'detail-timeline-item');
        const content = document.createElement('div');
        const mapLink = entry.lat !== null && entry.lat !== undefined && entry.lng !== null && entry.lng !== undefined
          ? Object.assign(createTextElement('a', 'map-link', 'Open map'), {
            href: `https://www.openstreetmap.org/?mlat=${Number(entry.lat)}&mlon=${Number(entry.lng)}#map=11/${Number(entry.lat)}/${Number(entry.lng)}`,
            target: '_blank',
            rel: 'noopener noreferrer'
          })
          : '';
        content.append(
          createTextElement('strong', '', entry.location),
          entry.eta ? createTextElement('p', '', `ETA ${formatEta(entry.eta)}`) : '',
          entry.note ? createTextElement('p', '', entry.note) : '',
          createTextElement('time', '', `${formatTimestamp(entry.createdAt)}${entry.source === 'gps' ? ' · GPS' : (entry.actorName ? ` · ${entry.actorName}` : '')}`),
          mapLink
        );
        item.append(createTextElement('span', 'timeline-marker'), content);
        return item;
      });
      if (!items.length) {
        items.push(createTextElement('p', 'muted', TRACKABLE_STATUSES.includes(shipment.status)
          ? 'No location updates yet. Call the driver and log where the truck is.'
          : 'Location updates start once a truck is booked (Dispatched).'));
      }
      trackingList.replaceChildren(...items);
    }
    Object.entries(values).forEach(([key, value]) => {
      const field = modal.querySelector(`[data-detail="${key}"]`);
      if (field) field.textContent = value || '-';
    });
    document.getElementById('shipmentDetailsTitle').textContent = shipment.id;
    document.getElementById('shipmentDetailsSubtitle').textContent = `${shipment.origin} → ${shipment.destination}`;
    if (timeline) {
      const eventItems = (events.events || []).map((entry) => {
        const item = document.createElement('div');
        item.className = 'detail-timeline-item';
        const content = document.createElement('div');
        content.append(
          createTextElement('strong', '', entry.status),
          createTextElement('p', '', entry.note || ''),
          createTextElement('time', '', formatTimestamp(entry.createdAt))
        );
        item.append(createTextElement('span', 'timeline-marker'), content);
        return item;
      });
      if (!eventItems.length) eventItems.push(createTextElement('p', '', 'No activity recorded.'));
      timeline.replaceChildren(...eventItems);
    }

    const messageForm = document.getElementById('messageForm');
    const canMessage = hasPermission('shipments:message');
    messageForm?.classList.toggle('hidden', !canMessage);
    const channels = window.VeyraConfig.messaging?.channels || [];
    const messagingStatus = document.getElementById('messagingStatus');
    if (messagingStatus) messagingStatus.textContent = channels.length ? `Sending by ${channels.join(' / ').toUpperCase()}` : 'Sending off · copy and send from your phone';
    if (canMessage) {
      messageForm.elements.recipient.value = TRACKABLE_STATUSES.includes(shipment.status) ? 'driver' : 'customer';
      fillPurposeOptions(messageForm);
      if (channels.length && !channels.includes(messageForm.elements.channel.value)) messageForm.elements.channel.value = channels[0];
      loadMessageDraft();
    }
    renderMessageList(shipment.id);
    loadDocuments(shipment.id);
    loadShipmentAdvice(shipment);
    modal.classList.remove('hidden');
  } catch (error) {
    notify(error.message, 'error');
  }
}


function bindDashboardRange() {
  const select = document.getElementById('dashboardRange');
  if (!select) return;
  select.addEventListener('change', () => {
    const days = Number(select.value);
    dashboardDays = [7, 30, 90].includes(days) ? days : 7;
    fetchDashboardData();
  });
}

// Keyboard accessibility for every dialog: move focus in, keep Tab inside, restore focus on close.
function bindModalA11y() {
  const selector = '.auth-modal, .shipment-modal, .shipment-details-modal, .dispatch-modal';
  const modals = Array.from(document.querySelectorAll(selector));
  const returnTo = new WeakMap();
  const focusable = (root) => Array.from(root.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'))
    .filter((node) => node.offsetParent !== null);

  modals.forEach((modal) => {
    new MutationObserver(() => {
      const open = !modal.classList.contains('hidden');
      if (open && !returnTo.has(modal)) {
        returnTo.set(modal, document.activeElement);
        if (!modal.contains(document.activeElement)) {
          requestAnimationFrame(() => focusable(modal)[0]?.focus());
        }
      } else if (!open && returnTo.has(modal)) {
        const previous = returnTo.get(modal);
        returnTo.delete(modal);
        if (previous && document.contains(previous) && typeof previous.focus === 'function') previous.focus();
      }
    }).observe(modal, { attributes: true, attributeFilter: ['class'] });
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Tab') return;
    const open = modals.find((modal) => !modal.classList.contains('hidden'));
    if (!open) return;
    const items = focusable(open);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && (document.activeElement === first || !open.contains(document.activeElement))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || !open.contains(document.activeElement))) {
      event.preventDefault();
      first.focus();
    }
  });
}
