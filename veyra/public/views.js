/* =========================================================
   VEYRA — app views: Shipments, Carriers, Analytics
   Hash routing (#/dashboard, #/shipments, #/carriers, #/analytics).
   Relies on helpers defined in script.js:
   createTextElement, getAuthHeaders, getCurrentPermissions,
   openShipmentDetails, allowedShipmentStatuses,
   fetchDashboardData, loadAdminConsole.
   ========================================================= */
(function () {
  const VIEWS = ['dashboard', 'shipments', 'inbox', 'carriers', 'analytics'];
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
  const equipmentList = () => window.VeyraConfig?.equipment || ['Dry Van', 'Tent / Curtainsider', 'Reefer', 'Flatbed', 'LTL', 'Expedited'];
  const TRACKABLE = ['Dispatched', 'In Transit', 'Exception'];
  const CARRIER_MODES = ['Truckload', 'LTL', 'Expedited', 'Reefer', 'Flatbed', 'Intermodal'];

  const state = {
    view: 'dashboard',
    params: new URLSearchParams(),
    shipments: { items: [], total: 0, allCount: 0, statusCounts: {}, page: 1, pages: 1, loaded: false, status: 'all', q: '', equipment: '', sort: 'newest' },
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
  const money = (value, digits = 0) => formatMoney(value, digits);
  const pct = (value) => (value === null || value === undefined ? '—' : `${Math.round(Number(value) * 100)}%`);
  const prettyDate = (value) => {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ''));
    if (!match) return value || '—';
    return new Date(Date.UTC(+match[1], +match[2] - 1, +match[3])).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
  };

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
    const TITLES = { dashboard: 'Dashboard', shipments: 'Shipments', inbox: 'Inbox & tasks', carriers: 'Carriers', analytics: 'Analytics' };
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
      state.shipments.page = 1;
      if (search) search.value = state.shipments.q;
      renderShipments();
    } else if (view === 'carriers') {
      if (search) search.value = state.carriers.q;
      renderCarriers();
    } else if (view === 'inbox') {
      if (search) search.value = '';
      renderInbox();
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
  const PAGE_SIZE = 50;
  let searchTimer;

  function shipmentQuery(page = state.shipments.page, pageSize = PAGE_SIZE) {
    const s = state.shipments;
    const params = new URLSearchParams({ page: String(page), limit: String(pageSize), sort: s.sort });
    if (s.status !== 'all') params.set('status', s.status);
    if (s.q.trim()) params.set('q', s.q.trim());
    if (s.equipment) params.set('equipment', s.equipment);
    return `/api/shipments/search?${params.toString()}`;
  }

  // The server filters, sorts and pages, so this works the same with 50 or 50,000 loads.
  async function renderShipments() {
    const container = document.getElementById('shipmentsView');
    if (!container) return;
    if (!currentUser()) return gate(container, 'signin');
    if (!can('shipments:read')) return gate(container, 'denied');
    if (!state.shipments.loaded) loading(container);
    try {
      const result = await api(shipmentQuery());
      Object.assign(state.shipments, {
        items: result.items, total: result.total, allCount: result.allCount, statusCounts: result.statusCounts,
        pages: result.pages, page: result.page, loaded: true
      });
    } catch (error) {
      return errorState(container, error.message, renderShipments);
    }
    if (state.view !== 'shipments') return;
    if (!document.getElementById('shipmentsTableBody')) buildShipmentsLayout(container);
    updateShipmentList();
  }

  function reloadFirstPage() {
    state.shipments.page = 1;
    renderShipments();
  }

  function buildShipmentsLayout(container) {
    const s = state.shipments;
    const tabs = el('div', { class: 'status-tabs', id: 'shipmentStatusTabs', role: 'group', 'aria-label': 'Filter by status' });
    const searchInput = el('input', {
      type: 'search', placeholder: 'Search ID, customer, city, carrier, truck…', value: s.q, 'aria-label': 'Search shipments',
      oninput: (event) => {
        s.q = event.target.value;
        const global = document.getElementById('globalSearch');
        if (global) global.value = s.q;
        clearTimeout(searchTimer);
        searchTimer = setTimeout(reloadFirstPage, 300);
      }
    });
    searchInput.value = s.q;
    const equipmentSelect = el('select', {
      'aria-label': 'Equipment',
      onchange: (event) => { s.equipment = event.target.value; reloadFirstPage(); }
    }, [el('option', { value: '', text: 'All equipment' }), ...equipmentList().map((item) => el('option', { value: item, text: item }))]);
    equipmentSelect.value = s.equipment;
    const sortSelect = el('select', {
      'aria-label': 'Sort',
      onchange: (event) => { s.sort = event.target.value; reloadFirstPage(); }
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
  }

  function updateShipmentList() {
    const s = state.shipments;
    const tabs = document.getElementById('shipmentStatusTabs');
    const body = document.getElementById('shipmentsTableBody');
    const footer = document.getElementById('shipmentsFooter');
    if (!tabs || !body) return;

    const counts = s.statusCounts || {};
    tabs.replaceChildren(...[['all', 'All', s.allCount || 0], ...STATUS_ORDER.map((status) => [status, status, counts[status] || 0])]
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

    const list = s.items || [];
    const canStatus = can('shipments:status');
    const canDispatch = can('shipments:dispatch');
    const filtered = s.q.trim() || s.equipment || s.status !== 'all';

    if (!list.length) {
      body.replaceChildren(el('tr', {}, el('td', { colspan: '8', class: 'empty-cell' }, filtered
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
            ? [
              el('span', { text: shipment.carrierName }),
              el('small', { class: 'cell-sub', text: [money(shipment.rate, 2), shipment.truckPlate].filter(Boolean).join(' · ') }),
              TRACKABLE.includes(shipment.status)
                ? el('small', {
                  class: `cell-sub${shipment.lastLocation ? ' location-line' : ' warn-line'}`,
                  text: shipment.lastLocation
                    ? `Now: ${shipment.lastLocation}${shipment.eta ? ` · ETA ${formatEta(shipment.eta)}` : ''}`
                    : 'No location yet'
                })
                : null
            ]
            : [el('span', { class: 'muted', text: 'Unassigned' })]),
          el('td', {}, statusTag(shipment.status)),
          el('td', {}, actions)
        ]);
      }));
    }
    if (footer) {
      const from = s.total ? (s.page - 1) * PAGE_SIZE + 1 : 0;
      const to = Math.min(s.page * PAGE_SIZE, s.total);
      const go = (page) => { s.page = page; renderShipments(); };
      footer.replaceChildren(
        el('span', { text: `Showing ${from}–${to} of ${s.total} shipments` }),
        s.pages > 1 ? el('span', { class: 'pager' }, [
          el('button', { class: 'btn btn-ghost small', type: 'button', disabled: s.page <= 1, onclick: () => go(s.page - 1) }, '← Previous'),
          el('span', { class: 'muted', text: `Page ${s.page} of ${s.pages}` }),
          el('button', { class: 'btn btn-ghost small', type: 'button', disabled: s.page >= s.pages, onclick: () => go(s.page + 1) }, 'Next →')
        ]) : null
      );
    }
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
    // Pre-fill the customer price if it was agreed at order intake.
    if (shipment.customerRate !== null && shipment.customerRate !== undefined) form.elements.customerRate.value = String(shipment.customerRate);
    updateDispatchMargin();
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
    renderScout(shipment);
    document.getElementById('dispatchPulse')?.replaceChildren();
    renderPulse();
  }

  // SCOUT: ranked carrier suggestions with reasons and a suggested rate. A person still decides.
  async function renderScout(shipment) {
    const box = document.getElementById('dispatchSuggestions');
    const form = document.getElementById('dispatchForm');
    if (!box || !form) return;
    box.replaceChildren(el('p', { class: 'muted', text: 'SCOUT is ranking carriers…' }));
    try {
      const { recommendations } = await api(`/api/agents/scout/${encodeURIComponent(shipment.id)}`);
      if (dispatchTarget?.id !== shipment.id) return;
      if (!recommendations.length) {
        box.replaceChildren(el('p', { class: 'muted', text: 'SCOUT: no available carriers to suggest.' }));
        return;
      }
      box.replaceChildren(
        el('div', { class: 'scout-head' }, [el('strong', { text: 'SCOUT suggestions' }), el('small', { class: 'muted', text: 'Based on trailer fit and past loads. Click to use.' })]),
        ...recommendations.slice(0, 3).map((item, index) => el('button', {
          type: 'button',
          class: `scout-item${index === 0 ? ' best' : ''}`,
          onclick: () => {
            form.elements.carrierId.value = String(item.carrierId);
            if (item.suggestedRate && !form.elements.rate.value) form.elements.rate.value = String(item.suggestedRate);
            updateDispatchMargin();
            schedulePulse();
            form.elements.rate.focus();
          }
        }, [
          el('span', { class: 'scout-title' }, [el('strong', { text: item.name }), el('span', { class: 'scout-score', text: `${item.score} pts` })]),
          el('small', { text: item.reasons.join(' · ') || item.mode }),
          item.suggestedRate ? el('small', { class: 'scout-rate', text: `Suggested ${money(item.suggestedRate)} — ${item.rateBasis}` }) : null
        ]))
      );
    } catch (error) {
      box.replaceChildren(el('p', { class: 'muted', text: `SCOUT unavailable: ${error.message}` }));
    }
  }

  // Live "you earn X on this load" line while the dispatcher types prices.
  function updateDispatchMargin() {
    const form = document.getElementById('dispatchForm');
    const line = document.getElementById('dispatchMargin');
    if (!form || !line) return;
    const rate = Number(form.elements.rate.value);
    const price = Number(form.elements.customerRate.value);
    line.classList.remove('negative');
    if (!form.elements.rate.value || !form.elements.customerRate.value || !rate || !price) {
      line.textContent = 'Enter both prices to see your margin.';
      return;
    }
    const margin = price - rate;
    line.textContent = `Margin: ${money(margin, 2)} (${Math.round((margin / price) * 100)}%)`;
    line.classList.toggle('negative', margin < 0);
  }

  // PULSE: is this price usual for the lane? Refreshed a moment after the dispatcher stops typing.
  let pulseTimer = null;
  function schedulePulse() {
    clearTimeout(pulseTimer);
    pulseTimer = setTimeout(renderPulse, 400);
  }

  async function renderPulse() {
    const form = document.getElementById('dispatchForm');
    const box = document.getElementById('dispatchPulse');
    const target = dispatchTarget;
    if (!form || !box || !target) return;
    const query = new URLSearchParams();
    if (Number(form.elements.rate.value) > 0) query.set('rate', form.elements.rate.value);
    if (Number(form.elements.customerRate.value) > 0) query.set('customerRate', form.elements.customerRate.value);
    try {
      const pulse = await api(`/api/agents/pulse/${encodeURIComponent(target.id)}?${query}`);
      if (dispatchTarget?.id !== target.id) return;
      box.replaceChildren(window.VeyraAdviceBlock('PULSE · prices', window.VeyraPulseLines(pulse)));
    } catch (_) {
      box.replaceChildren();
    }
  }

  function bindDispatchModal() {
    const modal = document.getElementById('dispatchModal');
    const form = document.getElementById('dispatchForm');
    const close = () => modal?.classList.add('hidden');
    form?.addEventListener('input', schedulePulse);
    document.getElementById('closeDispatch')?.addEventListener('click', close);
    modal?.addEventListener('click', (event) => { if (event.target === modal) close(); });
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') close(); });
    form?.addEventListener('input', updateDispatchMargin);
    form?.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!dispatchTarget) return;
      const carrierId = Number(form.elements.carrierId.value);
      const rate = Number(form.elements.rate.value);
      const customerRate = form.elements.customerRate.value ? Number(form.elements.customerRate.value) : undefined;
      const message = document.getElementById('dispatchFormMessage');
      if (!carrierId || !Number.isFinite(rate) || rate <= 0) {
        message.textContent = 'Choose a carrier and enter a positive rate.';
        return;
      }
      if (customerRate !== undefined && customerRate < rate
        && !window.confirm('The customer price is lower than the carrier rate, so this load loses money. Book it anyway?')) {
        return;
      }
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      message.textContent = 'Dispatching…';
      const optional = (name) => form.elements[name].value.trim() || undefined;
      try {
        await api(`/api/admin/shipments/${encodeURIComponent(dispatchTarget.id)}/dispatch`, {
          method: 'POST',
          body: JSON.stringify({
            carrierId,
            rate,
            customerRate,
            driverName: optional('driverName'),
            driverPhone: optional('driverPhone'),
            truckPlate: optional('truckPlate')
          })
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
      // Every page, with the filters on screen (Shipments page) or everything (elsewhere).
      const onShipments = state.view === 'shipments';
      const saved = { ...state.shipments };
      if (!onShipments) Object.assign(state.shipments, { status: 'all', q: '', equipment: '', sort: 'newest' });
      const rows = [];
      try {
        for (let page = 1; page <= 100; page += 1) {
          const result = await api(shipmentQuery(page, 200));
          rows.push(...result.items);
          if (page >= result.pages) break;
        }
      } finally {
        if (!onShipments) Object.assign(state.shipments, saved);
      }
      const currency = window.VeyraConfig?.currency || 'USD';
      const header = ['ID', 'Reference', 'Customer', 'Origin', 'Destination', 'Pickup', 'Delivery', 'Weight', 'Equipment', 'Carrier', `Carrier rate (${currency})`,
        `Customer price (${currency})`, `Margin (${currency})`, 'Truck plate', 'Driver', 'Driver phone', 'Last location', 'ETA', 'Status', 'Tracking'];
      const lines = [header, ...rows.map((s) => [s.id, s.reference, s.customer, s.origin, s.destination, s.pickup, s.delivery, s.weight, s.equipment, s.carrierName, s.rate,
        s.customerRate, s.margin, s.truckPlate, s.driverName, s.driverPhone, s.lastLocation, s.eta, s.status, s.trackingNumber])]
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
    const phoneInput = el('input', { name: 'phone', type: 'tel', maxlength: '40', placeholder: 'Dispatch phone' });
    const contactInput = el('input', { name: 'contactName', maxlength: '120', placeholder: 'Contact person' });
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
            body: JSON.stringify({
              name: nameInput.value.trim(),
              mode: modeSelect.value,
              phone: phoneInput.value.trim() || undefined,
              contactName: contactInput.value.trim() || undefined
            })
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
        el('label', {}, ['Phone', phoneInput]),
        el('label', {}, ['Contact', contactInput]),
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
          el('div', { class: 'carrier-title' }, [
            el('strong', { text: carrier.name }),
            el('small', { text: [carrier.mode, carrier.contactName, carrier.phone].filter(Boolean).join(' · ') })
          ]),
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
      state.analytics.finance = can('shipments:finance') ? await api('/api/finance/summary').catch(() => null) : null;
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
      kpiCard('Carrier Cost Booked', money(stats.bookedRevenue), `${stats.pricedLoads ?? 0} loads · avg ${money(stats.averageRate)}`, 'chart', 'sky'),
      kpiCard('Gross Margin', money(stats.grossMargin), stats.marginLoads
        ? `${pct(stats.marginRate)} on ${stats.marginLoads} loads with a customer price`
        : 'Add customer prices to see margin', 'bolt', 'blue')
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

    // Every AI call is logged; this is where its use and cost (tokens) are visible.
    const agentRows = data.agents || [];
    const agentsCard = el('div', { class: 'card panel-card span-2' }, [
      el('div', { class: 'mini-head' }, el('span', {}, [el('strong', { text: 'AI agents' }), el('small', { text: `Calls in the last ${data.rangeDays} days · tokens are what the AI provider bills` })])),
      miniTable(['Agent', 'Calls', 'Succeeded', 'Tokens in', 'Tokens out', 'Avg. time'], agentRows.map((row) => [
        row.agent,
        row.calls,
        `${row.succeeded} (${row.calls ? Math.round((row.succeeded / row.calls) * 100) : 0}%)`,
        row.inputTokens.toLocaleString('en-US'),
        row.outputTokens.toLocaleString('en-US'),
        row.avgLatencyMs === null ? '—' : `${(row.avgLatencyMs / 1000).toFixed(1)} s`
      ]), window.VeyraConfig?.ai?.enabled ? 'No AI calls in this period.' : 'AI is off. Add OPENROUTER_API_KEY to turn on FLOW.')
    ]);

    // Money that is still open: delivered loads the customer has not paid, carriers not yet paid.
    const finance = state.analytics.finance;
    const financeCard = finance ? el('div', { class: 'card panel-card span-2' }, [
      el('div', { class: 'mini-head' }, el('span', {}, [
        el('strong', { text: 'Open money' }),
        el('small', { text: `Customers owe ${money(finance.receivable)} (${finance.receivableLoads} loads, ${finance.notInvoiced} not invoiced yet) · you owe carriers ${money(finance.payable)} (${finance.payableLoads} loads)` })
      ])),
      miniTable(['Load', 'Customer', 'Customer owes', 'Carrier is owed', 'Delivered'], finance.open.map((row) => [
        el('button', { class: 'link-button', type: 'button', onclick: () => openShipmentDetails(row.id) }, row.id),
        el('span', {}, [row.customer, el('small', { class: 'cell-sub', text: row.invoiceNumber ? `Invoice ${row.invoiceNumber}` : (row.invoicedAt ? 'Invoice sent' : 'Not invoiced') })]),
        row.customerPaidAt || row.customerRate === null ? '—' : money(row.customerRate),
        row.carrierPaidAt || row.rate === null ? '—' : el('span', {}, [money(row.rate), el('small', { class: 'cell-sub', text: row.carrierName || '' })]),
        row.daysSinceDelivery === null ? '—' : `${row.daysSinceDelivery} day${row.daysSinceDelivery === 1 ? '' : 's'} ago`
      ]), 'Nothing is open: every delivered load is paid on both sides.')
    ]) : null;

    container.replaceChildren(kpis, el('div', { class: 'analytics-grid' }, [financeCard, volumeCard, statusCard, equipmentCard, lanesCard, customersCard, carriersCard, agentsCard].filter(Boolean)));
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
     INBOX & TASKS (what NEXUS and the other agents prepared)
     ========================================================= */
  async function renderInbox() {
    const container = document.getElementById('inboxView');
    if (!container) return;
    if (!currentUser()) return gate(container, 'signin');
    if (!can('shipments:read')) return gate(container, 'denied');
    if (!container.children.length) loading(container);
    try {
      const [{ tasks }, inbox, sentinel] = await Promise.all([
        api('/api/tasks'),
        can('shipments:create') ? api('/api/inbox') : Promise.resolve({ items: [] }),
        api('/api/agents/sentinel').catch(() => ({ risks: [] }))
      ]);
      if (state.view !== 'inbox') return;
      state.inbox = { tasks, items: inbox.items, risks: sentinel.risks || [] };
    } catch (error) {
      return errorState(container, error.message, renderInbox);
    }
    buildInboxLayout(container);
    loadNotifications();
  }

  function taskCard(task) {
    const when = typeof formatTimestamp === 'function' ? formatTimestamp(task.createdAt) : task.createdAt;
    const body = el('div', { class: 'task-body' });
    const actions = el('div', { class: 'task-actions' });
    const dismiss = (label) => el('button', { class: 'btn btn-ghost small', type: 'button', onclick: (event) => taskAction(event.currentTarget, `/api/tasks/${task.id}/dismiss`, {}, 'Task closed.') }, label);
    const openLoad = () => el('button', { class: 'btn btn-ghost small', type: 'button', onclick: () => openShipmentDetails(task.shipmentId) }, 'Open load');
    const payload = task.payload || {};

    if (task.kind === 'review_intake') {
      const draft = payload.parsed?.draft;
      const missing = payload.parsed?.missing || [];
      body.append(el('p', { class: 'muted', text: `${payload.from || 'Unknown sender'}${payload.subject ? ` · ${payload.subject}` : ''}` }));
      if (draft) {
        body.append(el('ul', { class: 'task-facts' }, [
          ['Customer', draft.customer], ['Route', draft.origin && draft.destination ? `${draft.origin} → ${draft.destination}` : null],
          ['Pickup', draft.pickup], ['Delivery', draft.delivery],
          ['Weight', draft.weight ? `${draft.weight} ${window.VeyraConfig?.weightUnit || 'kg'}` : null], ['Equipment', draft.equipment],
          ['Price', draft.customerRate ? money(draft.customerRate) : null]
        ].map(([label, value]) => el('li', { class: value ? '' : 'missing' }, [el('span', { text: label }), el('strong', { text: value || 'missing' })]))));
        (payload.parsed.questions || []).forEach((question) => body.append(el('p', { class: 'task-question', text: `Ask the customer: ${question}` })));
        (payload.parsed.notes || []).forEach((note) => body.append(el('p', { class: 'muted', text: note })));
      } else {
        body.append(el('p', { text: payload.preview || '' }));
        body.append(el('p', { class: 'warn-line', text: payload.note || 'Not read yet.' }));
      }
      const files = (state.inbox?.items || []).find((entry) => entry.id === task.inboxId)?.attachments || [];
      if (files.length) body.append(fileList(task.inboxId, files));
      if (files.length && can('shipments:document')) actions.append(attachButton(task.inboxId));
      actions.append(
        el('button', {
          class: 'btn btn-primary small', type: 'button',
          onclick: () => {
            const item = (state.inbox?.items || []).find((entry) => entry.id === task.inboxId);
            if (typeof window.openShipmentModal === 'function') {
              window.openShipmentModal({ ...(draft || {}) }, { inboxId: task.inboxId, missing, emailText: item ? `${item.subject ? `Subject: ${item.subject}\n\n` : ''}${item.body}` : (payload.preview || '') });
            }
          }
        }, 'Create load'),
        dismiss('Dismiss')
      );
    } else if (task.kind === 'book_carrier') {
      const recommendations = payload.recommendations || [];
      if (!recommendations.length) body.append(el('p', { class: 'warn-line', text: 'No carrier is available. Add or reactivate one on the Carriers page.' }));
      recommendations.forEach((item, index) => body.append(el('div', { class: `task-reco${index === 0 ? ' best' : ''}` }, [
        el('span', { class: 'scout-title' }, [el('strong', { text: item.name }), el('span', { class: 'scout-score', text: `${item.score} pts` })]),
        el('small', { text: item.reasons.join(' · ') || item.mode }),
        item.suggestedRate ? el('small', { class: 'scout-rate', text: `Suggested ${money(item.suggestedRate)} — ${item.rateBasis}` }) : null
      ])));
      actions.append(
        el('button', {
          class: 'btn btn-primary small', type: 'button',
          onclick: async () => {
            try {
              const shipment = await api(`/api/shipments/${encodeURIComponent(task.shipmentId)}`);
              openDispatch(shipment);
            } catch (error) {
              toast(error.message, 'error');
            }
          }
        }, 'Open dispatch'),
        openLoad(),
        dismiss('Dismiss')
      );
    } else if (task.kind === 'message') {
      const channels = window.VeyraConfig?.messaging?.channels || [];
      const textarea = el('textarea', { rows: '3', maxlength: '1000', 'aria-label': 'Message text' });
      textarea.value = payload.body || '';
      const channelSelect = el('select', { 'aria-label': 'Send by' }, ['whatsapp', 'sms'].map((channel) => el('option', { value: channel, text: channel === 'sms' ? 'SMS' : 'WhatsApp', disabled: !channels.includes(channel) })));
      const firstOn = ['whatsapp', 'sms'].find((channel) => channels.includes(channel));
      if (firstOn) channelSelect.value = firstOn;
      body.append(el('p', { class: 'muted', text: `To the ${payload.recipient}: ${payload.to || 'no number'}` }), textarea);
      if (!channels.length) body.append(el('p', { class: 'warn-line', text: 'Sending is off for your company. Copy the text and send it from your phone, then close the task.' }));
      if (can('shipments:message')) {
        actions.append(el('span', { class: 'task-send' }, [channelSelect, el('button', {
          class: 'btn btn-primary small', type: 'button', disabled: !channels.length,
          onclick: (event) => taskAction(event.currentTarget, `/api/tasks/${task.id}/approve`, { channel: channelSelect.value, body: textarea.value }, 'Message sent.')
        }, 'Approve & send')]));
      }
      actions.append(
        el('button', {
          class: 'btn btn-ghost small', type: 'button',
          onclick: async () => {
            try {
              await navigator.clipboard.writeText(textarea.value);
              toast('Text copied. Paste it into WhatsApp or SMS.');
            } catch (_) {
              textarea.select();
              toast('Select the text and copy it (Ctrl+C).', 'info');
            }
          }
        }, 'Copy'),
        openLoad(),
        dismiss('Skip')
      );
    } else if (task.kind === 'check_document') {
      body.append(el('div', { class: 'table-scroll' }, el('table', { class: 'data-table compact' }, [
        el('thead', {}, el('tr', {}, ['Field', 'Document says', 'Load says', ''].map((h) => el('th', { text: h })))),
        el('tbody', {}, (payload.mismatches || []).map((check) => el('tr', {}, [
          el('td', { text: check.label }), el('td', { text: check.document ?? '—' }), el('td', { text: check.load ?? '—' }), el('td', { class: 'warn-line', text: check.hint || '' })
        ])))
      ])));
      actions.append(openLoad(), dismiss('Checked'));
    } else {
      body.append(el('p', { text: payload.text || '' }));
      [['Carrier', payload.carrierPhone], ['Driver', payload.driverPhone]].filter(([, phone]) => phone).forEach(([who, phone]) => body.append(
        el('p', { class: 'muted' }, [`${who}: `, el('a', { href: `tel:${String(phone).replace(/[^+\d]/g, '')}`, text: phone })])
      ));
      actions.append(openLoad(), dismiss('Done'));
    }
    return el('article', { class: `card task-card kind-${task.kind}` }, [
      el('header', {}, [el('strong', { text: task.title }), el('small', { class: 'muted', text: when })]),
      body,
      actions
    ]);
  }

  // Files that came with an email: each is a download link.
  function fileList(inboxId, files) {
    return el('p', { class: 'file-list' }, [
      el('span', { class: 'muted', text: `${files.length} file${files.length === 1 ? '' : 's'}: ` }),
      ...files.map((file) => el('a', {
        class: 'file-chip', href: `/api/inbox/${inboxId}/attachments/${file.id}/file`, download: file.filename,
        text: `${file.filename} (${Math.max(1, Math.round(file.size / 1024))} KB)`
      }))
    ]);
  }

  function attachButton(inboxId) {
    return el('button', {
      class: 'btn btn-ghost small', type: 'button',
      onclick: (event) => {
        const answer = window.prompt('Which load do these files belong to? Type its number, for example SHP-12');
        if (!answer) return;
        const shipmentId = answer.trim().toUpperCase().replace(/^(\d+)$/, 'SHP-$1').replace(/\s+/g, '');
        taskAction(event.currentTarget, `/api/inbox/${inboxId}/attach`, { shipmentId }, `Files added to ${shipmentId}.`);
      }
    }, 'Attach files to a load');
  }

  // SENTINEL: loads that are in trouble or about to be, worst first.
  function riskPanel(risks) {
    const label = { high: 'Urgent', medium: 'Soon', low: 'Note' };
    return el('section', { class: 'card risk-panel' }, [
      el('header', {}, [el('strong', { text: `SENTINEL · ${risks.length} risk${risks.length === 1 ? '' : 's'} on open loads` }), el('small', { class: 'muted', text: 'Checked now' })]),
      el('ul', { class: 'risk-list' }, risks.slice(0, 12).map((risk) => el('li', { class: `risk-${risk.severity}` }, [
        el('span', { class: 'risk-level', text: label[risk.severity] || risk.severity }),
        el('div', {}, [
          el('button', { class: 'link-button', type: 'button', onclick: () => openShipmentDetails(risk.shipmentId) }, risk.title),
          el('small', { class: 'muted', text: `${risk.customer} · ${risk.lane} — ${risk.advice}` })
        ])
      ]))),
      risks.length > 12 ? el('p', { class: 'muted', text: `…and ${risks.length - 12} more.` }) : null
    ]);
  }

  async function taskAction(button, url, body, doneText) {
    button.disabled = true;
    try {
      await api(url, { method: 'POST', body: JSON.stringify(body) });
      toast(doneText);
      await Promise.allSettled([renderInbox(), loadNotifications()]);
    } catch (error) {
      toast(error.message, 'error');
      button.disabled = false;
    }
  }

  function buildInboxLayout(container) {
    const { tasks, items, risks = [] } = state.inbox;
    const blocked = items.filter((item) => item.status === 'blocked');
    const hasTaskEmail = (id) => tasks.some((task) => task.inboxId === id);
    const waiting = items.filter((item) => item.status !== 'blocked' && !hasTaskEmail(item.id));

    const taskList = tasks.length
      ? tasks.map(taskCard)
      : [el('div', { class: 'card empty-state wide' }, [el('p', { text: 'Nothing is waiting for you. New orders by email, bookings and late trucks will show up here.' })])];

    const sections = [];
    if (risks.length) sections.push(riskPanel(risks));
    sections.push(el('div', { class: 'task-list' }, taskList));
    if (waiting.length) {
      sections.push(el('h3', { class: 'task-heading', text: 'Emails without a task' }), ...waiting.map((item) => emailCard(item)));
    }
    if (blocked.length) {
      sections.push(
        el('h3', { class: 'task-heading', text: 'Blocked emails' }),
        el('p', { class: 'muted', text: 'These senders are not on your allowed list, so they were not read.' }),
        ...blocked.map((item) => emailCard(item, true))
      );
    }
    container.replaceChildren(...sections);
  }

  function emailCard(item, blocked = false) {
    return el('article', { class: 'card task-card' }, [
      el('header', {}, [el('strong', { text: item.subject || '(no subject)' }), el('small', { class: 'muted', text: item.from || '' })]),
      el('div', { class: 'task-body' }, [
        el('p', { text: item.body.slice(0, 400) }),
        !blocked && item.attachments?.length ? fileList(item.id, item.attachments) : null
      ]),
      el('div', { class: 'task-actions' }, [
        !blocked && item.attachments?.length && can('shipments:document') ? attachButton(item.id) : null,
        blocked ? null : el('button', {
          class: 'btn btn-primary small', type: 'button',
          onclick: () => window.openShipmentModal?.({}, { inboxId: item.id, emailText: `${item.subject ? `Subject: ${item.subject}\n\n` : ''}${item.body}` })
        }, 'Create load'),
        el('button', { class: 'btn btn-ghost small', type: 'button', onclick: (event) => taskAction(event.currentTarget, `/api/inbox/${item.id}/dismiss`, {}, 'Email dismissed.') }, 'Dismiss')
      ])
    ]);
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
      document.getElementById('navInboxBadge')?.classList.add('hidden');
      renderNotifications();
      return;
    }
    try {
      notifications.failed = false;
      // Counts come from the server, so they are right at any number of loads.
      const { alerts } = await api('/api/alerts');
      const items = [];
      const { exceptions, pendingApproval: pending, new: fresh, sourcing, staleTracking, staleHours } = alerts;
      const available = can('carriers:read') ? alerts.availableCarriers : null;
      if (exceptions) items.push({ tone: 'danger', title: `${plural(exceptions, 'shipment is', 'shipments are')} in Exception`, hint: 'Review and resolve', href: '#/shipments?status=Exception' });
      if (staleTracking) items.push({ tone: 'warn', title: `${plural(staleTracking, 'truck has', 'trucks have')} no location update in ${staleHours}h`, hint: 'Call the driver or check GPS', href: '#/shipments?status=In%20Transit' });
      if (pending) items.push({ tone: 'warn', title: `${plural(pending, 'shipment is', 'shipments are')} waiting for approval`, hint: 'Open the approvals queue', href: '#/shipments?status=Pending%20Approval' });
      if (available === 0 && (sourcing || pending)) items.push({ tone: 'danger', title: 'No carriers are available', hint: 'Reactivate or add a carrier', href: '#/carriers' });
      else if (sourcing) items.push({ tone: 'info', title: `${plural(sourcing, 'load needs', 'loads need')} a carrier`, hint: 'In Sourcing', href: '#/shipments?status=Sourcing' });
      if (fresh) items.push({ tone: 'info', title: `${plural(fresh, 'new load is', 'new loads are')} waiting to be sourced`, hint: 'Move to Sourcing', href: '#/shipments?status=New' });
      if (alerts.openTasks) items.unshift({ tone: 'warn', title: `${plural(alerts.openTasks, 'task is', 'tasks are')} waiting for you`, hint: 'Orders, bookings and messages the agents prepared', href: '#/inbox' });
      const badge = document.getElementById('navInboxBadge');
      if (badge) {
        badge.textContent = alerts.openTasks;
        badge.classList.toggle('hidden', !alerts.openTasks);
      }
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
    // New emails and tasks can arrive while someone works on another page: refresh the counts quietly.
    setInterval(() => {
      if (!document.hidden && currentUser()) loadNotifications();
    }, 60000);
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
    if (state.view === 'inbox') await renderInbox();
    loadNotifications();
  }

  function onSessionChange() {
    state.shipments = { ...state.shipments, items: [], total: 0, allCount: 0, statusCounts: {}, page: 1, loaded: false };
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
        clearTimeout(searchTimer);
        searchTimer = setTimeout(reloadFirstPage, 300);
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
