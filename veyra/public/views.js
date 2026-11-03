/* =========================================================
   VEYRA — app views: Shipments, Carriers, Analytics
   Hash routing (#/dashboard, #/shipments, #/carriers, #/analytics).
   Relies on helpers defined in script.js:
   createTextElement, getAuthHeaders, getCurrentPermissions,
   openShipmentDetails, allowedShipmentStatuses,
   fetchDashboardData, loadAdminConsole.
   ========================================================= */
(function () {
  const VIEWS = ['dashboard', 'shipments', 'carriers', 'analytics'];
  const STATUS_ORDER = ['New', 'Sourcing', 'Pending Approval', 'Dispatched', 'In Transit', 'Exception', 'Delivered', 'Cancelled'];
  const STATUS_COLORS = {
    New: '#2563ff',
    Sourcing: '#38bdf8',
    'Pending Approval': '#fbbf24',
    Dispatched: '#a78bfa',
    'In Transit': '#7dd3fc',
    Delivered: '#14b8a6',
    Exception: '#f87171',
    Cancelled: '#64748b'
  };
  const EQUIPMENT = ['Dry Van', 'Reefer', 'Flatbed', 'LTL', 'Expedited'];
  const CARRIER_MODES = ['Truckload', 'LTL', 'Expedited', 'Reefer', 'Flatbed', 'Intermodal'];

  const state = {
    view: 'dashboard',
    params: new URLSearchParams(),
    shipments: { list: [], loaded: false, status: 'all', q: '', equipment: '', sort: 'newest' },
    carriers: { list: [], filter: 'all', q: '', formOpen: false },
    analytics: { days: 7, data: null }
  };

  /* ---------- helpers ---------- */
  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    Object.entries(attrs).forEach(([key, value]) => {
      if (value === undefined || value === null || value === false) return;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = String(value);
      else if (key === 'style') node.setAttribute('style', value);
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else node.setAttribute(key, value === true ? '' : value);
    });
    (Array.isArray(children) ? children : [children]).forEach((child) => {
      if (child === null || child === undefined || child === false) return;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    });
    return node;
  }

  function icon(name, cls = 'ico') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', cls);
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', `#i-${name}`);
    svg.append(use);
    return svg;
  }

  const currentUser = () => {
    try {
      return JSON.parse(localStorage.getItem('veyraUser') || 'null');
    } catch (_) {
      return null;
    }
  };
  const can = (permission) => {
    const permissions = getCurrentPermissions();
    return permissions.includes('*') || permissions.includes(permission);
  };
  const slug = (value) => String(value || '').toLowerCase().replace(/\s+/g, '-');
  const money = (value, digits = 0) => (value === null || value === undefined || Number.isNaN(Number(value))
    ? '—'
    : Number(value).toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: digits, minimumFractionDigits: digits }));
  const pct = (value) => (value === null || value === undefined ? '—' : `${Math.round(Number(value) * 100)}%`);
  const prettyDate = (value) => {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ''));
    if (!match) return value || '—';
    return new Date(Date.UTC(+match[1], +match[2] - 1, +match[3])).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
  };
  const shipmentNumber = (id) => Number(String(id).replace(/\D/g, '')) || 0;

  async function api(url, options = {}) {
    const response = await fetch(url, { headers: getAuthHeaders(), ...options });
    let body = null;
    try {
      body = await response.json();
    } catch (_) {
      body = null;
    }
    if (!response.ok) throw new Error(body?.message || `Request failed (${response.status})`);
    return body;
  }

  let toastTimer;
  function toast(message, type = 'ok') {
    const node = document.getElementById('toast');
    if (!node) return;
    node.textContent = message;
    node.className = `toast ${type}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.classList.add('hidden'), 3600);
  }

  function gate(container, kind) {
    const signedOut = kind === 'signin';
    const box = el('div', { class: 'card empty-state' }, [
      el('span', { class: 'empty-icon' }, icon(signedOut ? 'eye' : 'alert')),
      el('h3', { text: signedOut ? 'Sign in to open this page' : 'You don\'t have access to this page' }),
      el('p', {
        text: signedOut
          ? 'Live shipments, carriers and analytics are available to workspace members.'
          : 'Your role doesn\'t include this permission. Ask an administrator for access.'
      }),
      signedOut ? el('button', { class: 'btn btn-primary small', type: 'button', onclick: () => document.getElementById('loginTrigger')?.click() }, 'Sign in') : null
    ]);
    container.replaceChildren(box);
  }

  function loading(container) {
    container.replaceChildren(el('div', { class: 'card empty-state' }, [el('span', { class: 'spinner' }), el('p', { text: 'Loading…' })]));
  }

  function errorState(container, message, retry) {
    container.replaceChildren(el('div', { class: 'card empty-state' }, [
      el('span', { class: 'empty-icon danger' }, icon('alert')),
      el('h3', { text: 'Something went wrong' }),
      el('p', { text: message }),
      el('button', { class: 'btn btn-ghost small', type: 'button', onclick: retry }, 'Try again')
    ]));
  }

  function statusTag(status) {
    return el('span', { class: `tag ${slug(status)}`, text: status });
  }

  /* ---------- router ---------- */
  function parseHash() {
    const raw = window.location.hash.replace(/^#\/?/, '');
    const [path, query = ''] = raw.split('?');
    const view = VIEWS.includes(path) ? path : 'dashboard';
    return { view, params: new URLSearchParams(query) };
  }

  function navigate(view, params = {}) {
    const query = new URLSearchParams(params).toString();
    const target = `#/${view}${query ? `?${query}` : ''}`;
    if (window.location.hash === target) route();
    else window.location.hash = target;
  }

  function route() {
    const { view, params } = parseHash();
    state.view = view;
    state.params = params;
    const TITLES = { dashboard: 'Dashboard', shipments: 'Shipments', carriers: 'Carriers', analytics: 'Analytics' };
    document.title = `${TITLES[view]} | VEYRA`;

    document.querySelectorAll('.view[data-view]').forEach((node) => node.classList.toggle('hidden', node.dataset.view !== view));
    document.querySelector('.dashboard-panel')?.classList.toggle('is-wide', view !== 'dashboard');

    const activeNav = view === 'shipments' && params.get('status') === 'Pending Approval' ? 'approvals' : view;
    document.querySelectorAll('.side-nav [data-nav]').forEach((link) => {
      const isActive = link.dataset.nav === activeNav;
      link.classList.toggle('active', isActive);
      if (isActive) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });

    const search = document.getElementById('globalSearch');
    if (view === 'shipments') {
      state.shipments.status = params.get('status') && STATUS_ORDER.includes(params.get('status')) ? params.get('status') : 'all';
      state.shipments.q = params.get('q') || '';
      if (search) search.value = state.shipments.q;
      renderShipments();
    } else if (view === 'carriers') {
      if (search) search.value = state.carriers.q;
      renderCarriers();
    } else if (view === 'analytics') {
      if (search) search.value = '';
      renderAnalytics();
    } else if (search) {
      search.value = '';
    }
  }

  /* =========================================================
     SHIPMENTS
     ========================================================= */
  async function renderShipments() {
    const container = document.getElementById('shipmentsView');
    if (!container) return;
    if (!currentUser()) return gate(container, 'signin');
    if (!can('shipments:read')) return gate(container, 'denied');
    if (!state.shipments.loaded) loading(container);
    try {
      state.shipments.list = await api('/api/shipments?limit=200');
      state.shipments.loaded = true;
    } catch (error) {
      return errorState(container, error.message, renderShipments);
    }
    if (state.view !== 'shipments') return;
    buildShipmentsLayout(container);
  }

  function buildShipmentsLayout(container) {
    const s = state.shipments;
    const tabs = el('div', { class: 'status-tabs', id: 'shipmentStatusTabs', role: 'group', 'aria-label': 'Filter by status' });
    const searchInput = el('input', {
      type: 'search', placeholder: 'Search ID, customer, city, carrier…', value: s.q, 'aria-label': 'Search shipments',
      oninput: (event) => {
        s.q = event.target.value;
        const global = document.getElementById('globalSearch');
        if (global) global.value = s.q;
        updateShipmentList();
      }
    });
    searchInput.value = s.q;
    const equipmentSelect = el('select', {
      'aria-label': 'Equipment',
      onchange: (event) => { s.equipment = event.target.value; updateShipmentList(); }
    }, [el('option', { value: '', text: 'All equipment' }), ...EQUIPMENT.map((item) => el('option', { value: item, text: item }))]);
    equipmentSelect.value = s.equipment;
    const sortSelect = el('select', {
      'aria-label': 'Sort',
      onchange: (event) => { s.sort = event.target.value; updateShipmentList(); }
    }, [
      el('option', { value: 'newest', text: 'Newest first' }),
      el('option', { value: 'oldest', text: 'Oldest first' }),
      el('option', { value: 'customer', text: 'Customer A–Z' }),
      el('option', { value: 'rate', text: 'Rate: high to low' })
    ]);
    sortSelect.value = s.sort;

    const toolbar = el('div', { class: 'view-toolbar' }, [
      el('label', { class: 'search inline' }, [icon('search'), searchInput]),
      equipmentSelect,
      sortSelect
    ]);

    const table = el('table', { class: 'data-table' }, [
      el('thead', {}, el('tr', {}, ['ID', 'Customer', 'Lane', 'Pickup → Delivery', 'Freight', 'Carrier', 'Status', 'Actions'].map((h) => el('th', { text: h })))),
      el('tbody', { id: 'shipmentsTableBody' })
    ]);

    container.replaceChildren(
      tabs,
      el('div', { class: 'card table-card' }, [
        toolbar,
        el('div', { class: 'table-scroll' }, table),
        el('div', { class: 'table-footer', id: 'shipmentsFooter' })
      ])
    );
    updateShipmentList();
  }

  function filteredShipments() {
    const s = state.shipments;
    const q = s.q.trim().toLowerCase();
    let list = s.list.filter((shipment) => {
      if (s.status !== 'all' && shipment.status !== s.status) return false;
      if (s.equipment && shipment.equipment !== s.equipment) return false;
      if (!q) return true;
      return [shipment.id, shipment.reference, shipment.customer, shipment.origin, shipment.destination, shipment.carrierName, shipment.trackingNumber, shipment.status]
        .some((value) => String(value || '').toLowerCase().includes(q));
    });
    const sorters = {
      newest: (a, b) => shipmentNumber(b.id) - shipmentNumber(a.id),
      oldest: (a, b) => shipmentNumber(a.id) - shipmentNumber(b.id),
      customer: (a, b) => String(a.customer).localeCompare(String(b.customer)),
      rate: (a, b) => Number(b.rate || 0) - Number(a.rate || 0)
    };
    list = [...list].sort(sorters[s.sort] || sorters.newest);
    return list;
  }

  function updateShipmentList() {
    const s = state.shipments;
    const tabs = document.getElementById('shipmentStatusTabs');
    const body = document.getElementById('shipmentsTableBody');
    const footer = document.getElementById('shipmentsFooter');
    if (!tabs || !body) return;

    const counts = s.list.reduce((acc, shipment) => ({ ...acc, [shipment.status]: (acc[shipment.status] || 0) + 1 }), {});
    tabs.replaceChildren(...[['all', 'All', s.list.length], ...STATUS_ORDER.map((status) => [status, status, counts[status] || 0])]
      .map(([value, label, count]) => el('button', {
        type: 'button',
        class: `status-tab${s.status === value ? ' active' : ''}`,
        'aria-pressed': s.status === value ? 'true' : 'false',
        onclick: () => {
          const params = {};
          if (value !== 'all') params.status = value;
          if (s.q) params.q = s.q;
          navigate('shipments', params);
        }
      }, [value !== 'all' ? el('span', { class: 'dot', style: `--c:${STATUS_COLORS[value]}` }) : null, label, el('b', { text: count })])));

    const list = filteredShipments();
    const canStatus = can('shipments:status');
    const canDispatch = can('shipments:dispatch');

    if (!list.length) {
      body.replaceChildren(el('tr', {}, el('td', { colspan: '8', class: 'empty-cell' }, s.list.length
        ? 'No shipments match these filters.'
        : 'No shipments yet. Create your first load with “New Shipment”.')));
    } else {
      body.replaceChildren(...list.map((shipment) => {
        const actions = el('div', { class: 'row-actions' }, [
          el('button', { class: 'table-detail-button', type: 'button', onclick: () => openShipmentDetails(shipment.id) }, 'View')
        ]);
        const options = allowedShipmentStatuses(shipment.status);
        if (canStatus && options.length) {
          const select = el('select', {
            class: 'status-select', 'aria-label': `Change status of ${shipment.id}`,
            onchange: (event) => changeStatus(shipment.id, event.target.value, event.target)
          }, [el('option', { value: '', text: 'Move to…' }), ...options.map((option) => el('option', { value: option, text: option }))]);
          actions.append(select);
        }
        if (canDispatch && ['Sourcing', 'Pending Approval'].includes(shipment.status) && !shipment.carrierId) {
          actions.append(el('button', { class: 'dispatch-button', type: 'button', onclick: () => openDispatch(shipment) }, 'Dispatch'));
        }
        return el('tr', {}, [
          el('td', {}, [
            el('button', { class: 'link-btn id-link', type: 'button', onclick: () => openShipmentDetails(shipment.id) }, shipment.id),
            shipment.reference ? el('small', { class: 'cell-sub', text: shipment.reference }) : null
          ]),
          el('td', { text: shipment.customer }),
          el('td', {}, [el('span', { text: shipment.origin }), el('small', { class: 'cell-sub', text: `→ ${shipment.destination}` })]),
          el('td', {}, [el('span', { text: prettyDate(shipment.pickup) }), el('small', { class: 'cell-sub', text: `→ ${prettyDate(shipment.delivery)}` })]),
          el('td', {}, [el('span', { text: shipment.weight || '—' }), el('small', { class: 'cell-sub', text: shipment.equipment || '' })]),
          el('td', {}, shipment.carrierName
            ? [el('span', { text: shipment.carrierName }), el('small', { class: 'cell-sub', text: money(shipment.rate, 2) })]
            : [el('span', { class: 'muted', text: 'Unassigned' })]),
          el('td', {}, statusTag(shipment.status)),
          el('td', {}, actions)
        ]);
      }));
    }
    if (footer) footer.textContent = `Showing ${list.length} of ${s.list.length} shipments`;
  }

  async function changeStatus(shipmentId, status, select) {
    if (!status) return;
    select.disabled = true;
    try {
      await api(`/api/admin/shipments/${encodeURIComponent(shipmentId)}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status, note: `Status changed to ${status}` })
      });
      toast(`${shipmentId} moved to ${status}.`);
      await refreshAll();
    } catch (error) {
      toast(error.message, 'error');
      select.disabled = false;
      select.value = '';
    }
  }

  /* ---------- dispatch modal ---------- */
  let dispatchTarget = null;
  async function openDispatch(shipment) {
    const modal = document.getElementById('dispatchModal');
    const form = document.getElementById('dispatchForm');
    const select = document.getElementById('dispatchCarrier');
    const message = document.getElementById('dispatchFormMessage');
    if (!modal || !form || !select) return;
    dispatchTarget = shipment;
    form.reset();
    message.textContent = '';
    document.getElementById('dispatchModalTitle').textContent = `Dispatch ${shipment.id}`;
    document.getElementById('dispatchModalSubtitle').textContent = `${shipment.customer} · ${shipment.origin} → ${shipment.destination} · ${shipment.equipment || ''}`;
    select.replaceChildren(el('option', { value: '', text: 'Loading carriers…' }));
    modal.classList.remove('hidden');
    try {
      const carriers = (await api('/api/carriers')).filter((carrier) => carrier.status === 'Available');
      select.replaceChildren(
        el('option', { value: '', text: carriers.length ? 'Select an available carrier' : 'No carriers available' }),
        ...carriers.map((carrier) => el('option', { value: String(carrier.id), text: `${carrier.name} · ${carrier.mode}` }))
      );
      form.querySelector('button[type="submit"]').disabled = carriers.length === 0;
      if (!carriers.length) message.textContent = 'Every carrier is busy or inactive. Reactivate one on the Carriers page.';
      select.focus();
    } catch (error) {
      message.textContent = error.message;
    }
  }

  function bindDispatchModal() {
    const modal = document.getElementById('dispatchModal');
    const form = document.getElementById('dispatchForm');
    const close = () => modal?.classList.add('hidden');
    document.getElementById('closeDispatch')?.addEventListener('click', close);
    modal?.addEventListener('click', (event) => { if (event.target === modal) close(); });
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') close(); });
    form?.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!dispatchTarget) return;
      const carrierId = Number(form.elements.carrierId.value);
      const rate = Number(form.elements.rate.value);
      const message = document.getElementById('dispatchFormMessage');
      if (!carrierId || !Number.isFinite(rate) || rate <= 0) {
        message.textContent = 'Choose a carrier and enter a positive rate.';
        return;
      }
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      message.textContent = 'Dispatching…';
      try {
        await api(`/api/admin/shipments/${encodeURIComponent(dispatchTarget.id)}/dispatch`, {
          method: 'POST',
          body: JSON.stringify({ carrierId, rate })
        });
        close();
        toast(`${dispatchTarget.id} dispatched.`);
        await refreshAll();
      } catch (error) {
        message.textContent = error.message;
      }
      submit.disabled = false;
    });
  }

  /* ---------- CSV export ---------- */
  function csvCell(value) {
    let text = value === null || value === undefined ? '' : String(value);
    if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`; // block spreadsheet formula injection
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  async function exportCsv() {
    if (!currentUser()) {
      document.getElementById('loginTrigger')?.click();
      return;
    }
    try {
      if (!state.shipments.loaded) {
        state.shipments.list = await api('/api/shipments?limit=200');
        state.shipments.loaded = true;
      }
      const rows = state.view === 'shipments' ? filteredShipments() : state.shipments.list;
      const header = ['ID', 'Reference', 'Customer', 'Origin', 'Destination', 'Pickup', 'Delivery', 'Weight', 'Equipment', 'Carrier', 'Rate', 'Status', 'Tracking'];
      const lines = [header, ...rows.map((s) => [s.id, s.reference, s.customer, s.origin, s.destination, s.pickup, s.delivery, s.weight, s.equipment, s.carrierName, s.rate, s.status, s.trackingNumber])]
        .map((row) => row.map(csvCell).join(','));
      const blob = new Blob([`﻿${lines.join('\r\n')}`], { type: 'text/csv;charset=utf-8' });
      const link = el('a', { href: URL.createObjectURL(blob), download: `veyra-shipments-${new Date().toISOString().slice(0, 10)}.csv` });
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(link.href), 1000);
      toast(`Exported ${rows.length} shipments.`);
    } catch (error) {
      toast(error.message, 'error');
    }
  }

  /* =========================================================
     CARRIERS
     ========================================================= */
  async function renderCarriers() {
    const container = document.getElementById('carriersView');
    const addToggle = document.getElementById('addCarrierToggle');
    if (!container) return;
    addToggle?.classList.toggle('hidden', !currentUser() || !can('carriers:write'));
    if (!currentUser()) return gate(container, 'signin');
    if (!can('carriers:read')) return gate(container, 'denied');
    if (!state.carriers.list.length) loading(container);
    try {
      state.carriers.list = await api('/api/carriers');
    } catch (error) {
      return errorState(container, error.message, renderCarriers);
    }
    if (state.view !== 'carriers') return;
    buildCarriersLayout(container);
  }

  function buildCarriersLayout(container) {
    const c = state.carriers;
    const list = c.list;
    const count = (status) => list.filter((carrier) => carrier.status === status).length;

    const kpis = el('div', { class: 'stats-grid' }, [
      kpiCard('Total Carriers', list.length, 'In your network', 'carrier', 'blue'),
      kpiCard('Available', count('Available'), 'Ready for dispatch', 'check-circle', 'green'),
      kpiCard('Busy', count('Busy'), 'On an active load', 'truck', 'sky'),
      kpiCard('Inactive', count('Inactive'), 'Not taking loads', 'alert', 'amber')
    ]);

    const nameInput = el('input', { name: 'name', required: true, maxlength: '120', placeholder: 'Carrier company name' });
    const modeSelect = el('select', { name: 'mode', required: true }, [el('option', { value: '', text: 'Choose mode' }), ...CARRIER_MODES.map((mode) => el('option', { text: mode }))]);
    const formMessage = el('p', { class: 'shipment-form-message', role: 'status' });
    const form = el('form', {
      class: `card add-carrier${c.formOpen ? '' : ' hidden'}`,
      id: 'addCarrierForm',
      onsubmit: async (event) => {
        event.preventDefault();
        const submit = event.target.querySelector('button[type="submit"]');
        submit.disabled = true;
        formMessage.textContent = '';
        try {
          const result = await api('/api/carriers', {
            method: 'POST',
            body: JSON.stringify({ name: nameInput.value.trim(), mode: modeSelect.value })
          });
          c.formOpen = false;
          toast(`${result.carrier.name} added to your network.`);
          await refreshAll();
        } catch (error) {
          formMessage.textContent = error.message;
          submit.disabled = false;
        }
      }
    }, [
      el('div', { class: 'add-carrier-head' }, [el('strong', { text: 'Add a carrier' }), el('small', { text: 'New carriers start as Available.' })]),
      el('div', { class: 'add-carrier-fields' }, [
        el('label', {}, ['Name', nameInput]),
        el('label', {}, ['Mode', modeSelect]),
        el('button', { class: 'btn btn-primary small', type: 'submit' }, 'Add carrier')
      ]),
      formMessage
    ]);

    const tabs = el('div', { class: 'status-tabs' }, [['all', 'All', list.length], ['Available', 'Available', count('Available')], ['Busy', 'Busy', count('Busy')], ['Inactive', 'Inactive', count('Inactive')]]
      .map(([value, label, n]) => el('button', {
        type: 'button',
        class: `status-tab${c.filter === value ? ' active' : ''}`,
        'aria-pressed': c.filter === value ? 'true' : 'false',
        onclick: () => { c.filter = value; buildCarriersLayout(container); }
      }, [label, el('b', { text: n })])));

    const q = c.q.trim().toLowerCase();
    const visible = list.filter((carrier) => (c.filter === 'all' || carrier.status === c.filter)
      && (!q || `${carrier.name} ${carrier.mode}`.toLowerCase().includes(q)));
    const canWrite = can('carriers:write');

    const grid = el('div', { class: 'carrier-grid', id: 'carrierGrid' }, visible.length ? visible.map((carrier) => {
      const initials = carrier.name.split(/\s+/).slice(0, 2).map((part) => part.charAt(0).toUpperCase()).join('');
      let toggle = null;
      if (canWrite) {
        if (carrier.activeLoads > 0) {
          toggle = el('button', { class: 'btn btn-ghost small', type: 'button', disabled: true, title: 'Carrier is on an active load' }, 'On a load');
        } else {
          const next = carrier.status === 'Available' ? 'Inactive' : 'Available';
          toggle = el('button', {
            class: `btn small ${next === 'Available' ? 'btn-primary' : 'btn-ghost'}`,
            type: 'button',
            onclick: (event) => setCarrierStatus(carrier, next, event.currentTarget)
          }, next === 'Inactive' ? 'Set inactive' : carrier.status === 'Busy' ? 'Mark available' : 'Reactivate');
        }
      }
      return el('article', { class: `card carrier-card ${slug(carrier.status)}` }, [
        el('header', {}, [
          el('span', { class: 'carrier-avatar', text: initials }),
          el('div', { class: 'carrier-title' }, [el('strong', { text: carrier.name }), el('small', { text: carrier.mode })]),
          el('span', { class: `carrier-status ${slug(carrier.status)}`, text: carrier.status })
        ]),
        el('div', { class: 'carrier-metrics' }, [
          metric('Loads', carrier.totalLoads),
          metric('Active', carrier.activeLoads),
          metric('Delivered', carrier.deliveredLoads),
          metric('Booked', money(carrier.revenue))
        ]),
        el('div', { class: 'carrier-current' }, carrier.currentShipment
          ? [icon('truck', 'ico sm'), 'Current load ', el('button', { class: 'link-btn', type: 'button', onclick: () => openShipmentDetails(carrier.currentShipment) }, carrier.currentShipment)]
          : [el('span', { class: 'muted', text: carrier.averageRate ? `Avg. rate ${money(carrier.averageRate)}` : 'No loads booked yet' })]),
        el('footer', {}, [
          el('button', { class: 'btn btn-ghost small', type: 'button', onclick: () => navigate('shipments', { q: carrier.name }) }, 'View loads'),
          toggle
        ])
      ]);
    }) : [el('div', { class: 'card empty-state wide' }, [el('p', { text: list.length ? 'No carriers match this filter.' : 'No carriers yet. Add your first carrier to start dispatching.' })])]);

    container.replaceChildren(kpis, form, tabs, grid);
  }

  function metric(label, value) {
    return el('div', {}, [el('small', { text: label }), el('strong', { text: value })]);
  }

  function kpiCard(label, value, meta, iconName, tone) {
    return el('div', { class: 'stat-card' }, [
      el('div', { class: 'stat-top' }, [el('span', { text: label }), el('span', { class: `stat-icon ${tone}` }, icon(iconName, ''))]),
      el('div', { class: 'stat-value', text: value }),
      el('div', { class: 'stat-meta', text: meta })
    ]);
  }

  async function setCarrierStatus(carrier, status, button) {
    button.disabled = true;
    try {
      await api(`/api/carriers/${Number(carrier.id)}/status`, { method: 'PATCH', body: JSON.stringify({ status }) });
      toast(`${carrier.name} is now ${status}.`);
      await refreshAll();
    } catch (error) {
      toast(error.message, 'error');
      button.disabled = false;
    }
  }

  /* =========================================================
     ANALYTICS
     ========================================================= */
  async function renderAnalytics() {
    const container = document.getElementById('analyticsView');
    const range = document.getElementById('analyticsRange');
    if (!container) return;
    range?.classList.toggle('hidden', !currentUser() || !can('analytics:read'));
    if (!currentUser()) return gate(container, 'signin');
    if (!can('analytics:read')) return gate(container, 'denied');
    range?.querySelectorAll('button').forEach((button) => {
      const active = Number(button.dataset.days) === state.analytics.days;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    if (!state.analytics.data) loading(container);
    try {
      state.analytics.data = await api(`/api/analytics?days=${state.analytics.days}`);
    } catch (error) {
      return errorState(container, error.message, renderAnalytics);
    }
    if (state.view !== 'analytics') return;
    buildAnalyticsLayout(container, state.analytics.data);
  }

  function buildAnalyticsLayout(container, data) {
    const stats = data.stats || {};
    const kpis = el('div', { class: 'kpi-grid' }, [
      kpiCard('Total Shipments', stats.totalShipments ?? 0, `${stats.activeShipments ?? 0} still open`, 'truck', 'blue'),
      kpiCard('Pending Approval', stats.pendingApproval ?? 0, 'Waiting for a decision', 'doc', 'amber'),
      kpiCard('Delivery Rate', pct(stats.deliveryRate), 'Delivered of closed loads', 'check-circle', 'green'),
      kpiCard('Exceptions', stats.exceptions ?? 0, `${pct(stats.exceptionRate)} of all loads`, 'alert', 'red'),
      kpiCard('Booked Revenue', money(stats.bookedRevenue), `${stats.pricedLoads ?? 0} priced loads`, 'chart', 'sky'),
      kpiCard('Average Rate', money(stats.averageRate), `${stats.availableCarriers ?? 0} of ${stats.totalCarriers ?? 0} carriers available`, 'bolt', 'blue')
    ]);

    // Volume bar chart
    const volume = data.weeklyVolume || [];
    const maxVolume = Math.max(1, ...volume.map((point) => point.total));
    const created = volume.reduce((sum, point) => sum + point.total, 0);
    const labelEvery = volume.length > 30 ? 15 : volume.length > 7 ? 5 : 1;
    const bars = el('div', { class: 'bar-chart', role: 'img', 'aria-label': `Shipments created per day over the last ${data.rangeDays} days` }, volume.map((point, index) => el('div', { class: 'bar-col', title: `${point.label}: ${point.total}` }, [
      el('span', { class: `bar${point.total ? '' : ' zero'}`, style: `height:${Math.max(point.total ? 4 : 1, (point.total / maxVolume) * 100)}%` }),
      el('small', { class: index % labelEvery === 0 || index === volume.length - 1 ? '' : 'ghost', text: point.label })
    ])));
    const volumeCard = el('div', { class: 'card panel-card span-2' }, [
      el('div', { class: 'mini-head' }, [
        el('span', {}, [el('strong', { text: 'Shipments created' }), el('small', { text: `Last ${data.rangeDays} days · peak ${maxVolume === 1 && !created ? 0 : maxVolume}/day` })]),
        el('span', { class: 'big-number', text: created })
      ]),
      created ? bars : el('div', { class: 'empty-inline', text: 'No shipments were created in this range.' })
    ]);

    const statusRows = STATUS_ORDER.map((status) => ({ label: status, total: data.statuses?.[status] || 0, color: STATUS_COLORS[status] }));
    const statusCard = el('div', { class: 'card panel-card' }, [
      el('div', { class: 'mini-head' }, el('span', {}, [el('strong', { text: 'Pipeline by status' }), el('small', { text: 'All shipments, current state' })])),
      hbars(statusRows)
    ]);

    const equipmentRows = (data.equipment || []).map((row, index) => ({ ...row, color: ['#2563ff', '#38bdf8', '#a78bfa', '#14b8a6', '#fbbf24', '#64748b'][index % 6] }));
    const equipmentCard = el('div', { class: 'card panel-card' }, [
      el('div', { class: 'mini-head' }, el('span', {}, [el('strong', { text: 'Equipment mix' }), el('small', { text: 'Share of all loads' })])),
      equipmentRows.length ? hbars(equipmentRows) : el('div', { class: 'empty-inline', text: 'No shipments yet.' })
    ]);

    const lanesCard = el('div', { class: 'card panel-card' }, [
      el('div', { class: 'mini-head' }, el('span', {}, [el('strong', { text: 'Top lanes' }), el('small', { text: 'Most frequent origin → destination' })])),
      miniTable(['Lane', 'Loads', 'Avg. rate'], (data.topLanes || []).map((lane) => [
        el('span', {}, [lane.origin, el('small', { class: 'cell-sub', text: `→ ${lane.destination}` })]),
        lane.total,
        money(lane.averageRate)
      ]), 'No lanes yet.')
    ]);

    const customersCard = el('div', { class: 'card panel-card' }, [
      el('div', { class: 'mini-head' }, el('span', {}, [el('strong', { text: 'Top customers' }), el('small', { text: 'By number of loads' })])),
      miniTable(['Customer', 'Loads', 'Open', 'Booked'], (data.topCustomers || []).map((row) => [
        el('button', { class: 'link-btn', type: 'button', onclick: () => navigate('shipments', { q: row.customer }) }, row.customer),
        row.total,
        row.active,
        money(row.revenue)
      ]), 'No customers yet.')
    ]);

    const carrierRows = [...(data.carrierPerformance || [])].sort((a, b) => b.totalLoads - a.totalLoads || b.revenue - a.revenue);
    const carriersCard = el('div', { class: 'card panel-card span-2' }, [
      el('div', { class: 'mini-head' }, [
        el('span', {}, [el('strong', { text: 'Carrier performance' }), el('small', { text: 'Loads, outcomes and booked revenue per carrier' })]),
        el('a', { class: 'view-all', href: '#/carriers' }, ['Manage carriers ', icon('chevron', 'ico sm rot')])
      ]),
      miniTable(['Carrier', 'Status', 'Loads', 'Active', 'Delivered', 'Exceptions', 'Booked', 'Avg. rate'], carrierRows.map((carrier) => [
        el('span', {}, [carrier.name, el('small', { class: 'cell-sub', text: carrier.mode })]),
        el('span', { class: `carrier-status ${slug(carrier.status)}`, text: carrier.status }),
        carrier.totalLoads,
        carrier.activeLoads,
        carrier.deliveredLoads,
        carrier.exceptionLoads,
        money(carrier.revenue),
        money(carrier.averageRate)
      ]), 'No carriers yet.')
    ]);

    container.replaceChildren(kpis, el('div', { class: 'analytics-grid' }, [volumeCard, statusCard, equipmentCard, lanesCard, customersCard, carriersCard]));
  }

  function hbars(rows) {
    const total = rows.reduce((sum, row) => sum + row.total, 0);
    const max = Math.max(1, ...rows.map((row) => row.total));
    return el('div', { class: 'hbars' }, rows.map((row) => el('div', { class: 'hbar' }, [
      el('span', { class: 'hbar-label' }, [el('span', { class: 'dot', style: `--c:${row.color}` }), row.label]),
      el('span', { class: 'hbar-track' }, el('i', { style: `width:${(row.total / max) * 100}%;background:${row.color}` })),
      el('span', { class: 'hbar-value' }, [el('b', { text: row.total }), el('small', { text: total ? ` ${Math.round((row.total / total) * 100)}%` : '' })])
    ])));
  }

  function miniTable(headers, rows, emptyText) {
    if (!rows.length) return el('div', { class: 'empty-inline', text: emptyText });
    return el('div', { class: 'table-scroll' }, el('table', { class: 'data-table compact' }, [
      el('thead', {}, el('tr', {}, headers.map((header) => el('th', { text: header })))),
      el('tbody', {}, rows.map((cells) => el('tr', {}, cells.map((cell) => el('td', {}, cell)))))
    ]));
  }

  /* =========================================================
     NOTIFICATIONS (derived from real shipments and carriers)
     ========================================================= */
  const notifications = { items: [], open: false, failed: false };
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  async function loadNotifications() {
    if (!currentUser() || !can('shipments:read')) {
      notifications.items = [];
      notifications.failed = false;
      renderNotifications();
      return;
    }
    try {
      notifications.failed = false;
      const [shipments, carriers] = await Promise.all([
        api('/api/shipments?limit=200'),
        can('carriers:read') ? api('/api/carriers') : Promise.resolve(null)
      ]);
      const count = (status) => shipments.filter((shipment) => shipment.status === status).length;
      const items = [];
      const exceptions = count('Exception');
      const pending = count('Pending Approval');
      const fresh = count('New');
      const sourcing = count('Sourcing');
      const available = carriers ? carriers.filter((carrier) => carrier.status === 'Available').length : null;
      if (exceptions) items.push({ tone: 'danger', title: `${plural(exceptions, 'shipment is', 'shipments are')} in Exception`, hint: 'Review and resolve', href: '#/shipments?status=Exception' });
      if (pending) items.push({ tone: 'warn', title: `${plural(pending, 'shipment is', 'shipments are')} waiting for approval`, hint: 'Open the approvals queue', href: '#/shipments?status=Pending%20Approval' });
      if (available === 0 && (sourcing || pending)) items.push({ tone: 'danger', title: 'No carriers are available', hint: 'Reactivate or add a carrier', href: '#/carriers' });
      else if (sourcing) items.push({ tone: 'info', title: `${plural(sourcing, 'load needs', 'loads need')} a carrier`, hint: 'In Sourcing', href: '#/shipments?status=Sourcing' });
      if (fresh) items.push({ tone: 'info', title: `${plural(fresh, 'new load is', 'new loads are')} waiting to be sourced`, hint: 'Move to Sourcing', href: '#/shipments?status=New' });
      notifications.items = items;
    } catch (_) {
      notifications.items = [];
      notifications.failed = true;
    }
    renderNotifications();
  }

  function renderNotifications() {
    const dot = document.getElementById('notifDot');
    const list = document.getElementById('notifList');
    const count = document.getElementById('notifCount');
    const button = document.getElementById('notifBtn');
    const items = notifications.items;
    dot?.classList.toggle('hidden', items.length === 0);
    if (button) button.setAttribute('aria-label', items.length ? `Notifications, ${items.length} need attention` : 'Notifications');
    if (count) count.textContent = items.length ? `${items.length} need attention` : '';
    if (!list) return;
    if (!currentUser()) {
      list.replaceChildren(el('div', { class: 'notif-empty' }, [
        el('p', { text: 'Sign in to see alerts about your loads.' }),
        el('button', { class: 'btn btn-primary small', type: 'button', onclick: () => { setNotificationsOpen(false); document.getElementById('loginTrigger')?.click(); } }, 'Sign in')
      ]));
      return;
    }
    if (notifications.failed) {
      list.replaceChildren(el('div', { class: 'notif-empty' }, [
        el('p', { text: 'Couldn\'t load alerts right now.' }),
        el('button', { class: 'btn btn-ghost small', type: 'button', onclick: loadNotifications }, 'Try again')
      ]));
      return;
    }
    list.replaceChildren(...(items.length ? items.map((item) => el('a', {
      class: `notif-item ${item.tone}`,
      href: item.href,
      onclick: () => setNotificationsOpen(false)
    }, [el('span', { class: 'notif-bullet' }), el('span', {}, [el('strong', { text: item.title }), el('small', { text: item.hint })])]))
      : [el('div', { class: 'notif-empty' }, [el('p', { text: 'You\'re all caught up. Nothing needs attention.' })])]));
  }

  function setNotificationsOpen(open) {
    notifications.open = open;
    document.getElementById('notifPanel')?.classList.toggle('hidden', !open);
    document.getElementById('notifBtn')?.setAttribute('aria-expanded', String(open));
    if (open) loadNotifications();
  }

  function bindNotifications() {
    document.getElementById('notifBtn')?.addEventListener('click', () => setNotificationsOpen(!notifications.open));
    document.addEventListener('click', (event) => {
      if (notifications.open && !event.target.closest('.notif-wrap')) setNotificationsOpen(false);
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && notifications.open) {
        setNotificationsOpen(false);
        document.getElementById('notifBtn')?.focus();
      }
    });
    renderNotifications();
  }

  /* =========================================================
     SHARED
     ========================================================= */
  async function refreshAll() {
    state.shipments.loaded = false;
    await Promise.allSettled([fetchDashboardData(), loadAdminConsole()]);
    if (state.view === 'shipments') await renderShipments();
    if (state.view === 'carriers') await renderCarriers();
    if (state.view === 'analytics') await renderAnalytics();
    loadNotifications();
  }

  function onSessionChange() {
    state.shipments = { ...state.shipments, list: [], loaded: false };
    state.carriers.list = [];
    state.analytics.data = null;
    window.VeyraAssistant?.onSessionChange();
    loadNotifications();
    route();
  }

  function bindGlobal() {
    window.addEventListener('hashchange', route);

    document.querySelectorAll('[data-export-csv]').forEach((button) => button.addEventListener('click', exportCsv));

    document.getElementById('addCarrierToggle')?.addEventListener('click', () => {
      state.carriers.formOpen = !state.carriers.formOpen;
      const form = document.getElementById('addCarrierForm');
      form?.classList.toggle('hidden', !state.carriers.formOpen);
      if (state.carriers.formOpen) form?.querySelector('input')?.focus();
    });

    document.getElementById('analyticsRange')?.addEventListener('click', (event) => {
      const button = event.target.closest('button[data-days]');
      if (!button) return;
      state.analytics.days = Number(button.dataset.days);
      renderAnalytics();
    });

    const search = document.getElementById('globalSearch');
    search?.addEventListener('input', () => {
      if (state.view === 'shipments') {
        state.shipments.q = search.value;
        const local = document.querySelector('#shipmentsView .search input');
        if (local) local.value = search.value;
        updateShipmentList();
      } else if (state.view === 'carriers') {
        state.carriers.q = search.value;
        const container = document.getElementById('carriersView');
        if (container && state.carriers.list.length) buildCarriersLayout(container);
      }
    });
    search?.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      if (state.view === 'dashboard' || state.view === 'analytics') {
        const q = search.value.trim();
        navigate('shipments', q ? { q } : {});
      }
    });

    bindDispatchModal();
    bindNotifications();
  }

  window.VeyraViews = { refresh: refreshAll, onSessionChange, toast, navigate };

  document.addEventListener('DOMContentLoaded', () => {
    bindGlobal();
    const initial = parseHash();
    route();
    if (initial.view !== 'dashboard') {
      requestAnimationFrame(() => document.getElementById('demo')?.scrollIntoView({ block: 'start' }));
    }
  });
})();
