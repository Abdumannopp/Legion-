/* =========================================================
   VEYRA — AI Assistant card + Map & Tracking card
   The card proposes a draft shipment based on the latest load.
   "Edit Details" edits the draft; "Create Shipment" opens the
   order-intake form pre-filled with it. Depends on script.js
   (createTextElement, formatDay, isSignedIn, notify,
   openShipmentDetails).
   ========================================================= */
(function () {
  const equipmentList = () => window.VeyraConfig?.equipment || ['Dry Van', 'Tent / Curtainsider', 'Reefer', 'Flatbed', 'LTL', 'Expedited'];
  const weightUnit = () => window.VeyraConfig?.weightUnit || 'kg';
  const MAX_WEIGHT = 1000000;
  const FIELDS = [
    { key: 'origin', label: 'Origin', icon: 'pin', type: 'text' },
    { key: 'destination', label: 'Destination', icon: 'flag', type: 'text' },
    { key: 'weight', label: 'Weight', icon: 'weight', type: 'number' },
    { key: 'equipment', label: 'Equipment', icon: 'truck', type: 'select' },
    { key: 'pickup', label: 'Pickup', icon: 'calendar', type: 'date' },
    { key: 'delivery', label: 'Delivery', icon: 'calendar', type: 'date' }
  ];

  const isoDay = (offset) => {
    const date = new Date();
    date.setDate(date.getDate() + offset);
    return date.toISOString().slice(0, 10);
  };
  const defaultDraft = () => ({ origin: 'Dallas, TX', destination: 'Houston, TX', weight: 10000, equipment: 'Dry Van', pickup: isoDay(0), delivery: isoDay(1) });
  const cityOf = (value) => String(value || '').split(',')[0].trim();
  const parseWeight = (value) => {
    const digits = Number(String(value || '').replace(/[^\d.]/g, ''));
    return Number.isFinite(digits) && digits > 0 ? Math.round(digits) : null;
  };

  const state = { draft: defaultDraft(), dirty: false, editing: false, latest: null, route: null };

  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'ico');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', `#i-${name}`);
    svg.append(use);
    return svg;
  }

  function display(key, value) {
    if (key === 'weight') return `${Number(value).toLocaleString('en-US')} ${weightUnit()}`;
    if (key === 'pickup' || key === 'delivery') {
      const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value));
      return match ? new Date(Date.UTC(+match[1], +match[2] - 1, +match[3])).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' }) : String(value);
    }
    return String(value);
  }

  function renderDetails() {
    const container = document.getElementById('assistantDetails');
    if (!container) return;
    container.replaceChildren(...FIELDS.map((field) => {
      const row = document.createElement('div');
      row.dataset.field = field.key;
      const label = document.createElement('span');
      label.append(icon(field.icon), field.label);
      let valueNode;
      if (state.editing) {
        if (field.type === 'select') {
          valueNode = document.createElement('select');
          equipmentList().forEach((item) => valueNode.append(new Option(item, item)));
        } else {
          valueNode = document.createElement('input');
          valueNode.type = field.type;
          if (field.type === 'number') { valueNode.min = '1'; valueNode.max = String(MAX_WEIGHT); valueNode.step = '1'; }
          if (field.type === 'text') valueNode.maxLength = 160;
        }
        valueNode.value = state.draft[field.key];
        valueNode.id = `assistant-${field.key}`;
        valueNode.name = field.key;
        valueNode.setAttribute('aria-label', field.label);
        valueNode.className = 'assistant-input';
      } else {
        valueNode = document.createElement('strong');
        valueNode.textContent = display(field.key, state.draft[field.key]);
      }
      row.append(label, valueNode);
      return row;
    }));
  }

  function renderPrompt() {
    const d = state.draft;
    const prompt = document.getElementById('assistantPrompt');
    if (prompt) {
      prompt.textContent = `Create a shipment for ${Number(d.weight).toLocaleString('en-US')} ${weightUnit()} ${String(d.equipment).toLowerCase()} from ${cityOf(d.origin)} to ${cityOf(d.destination)}, pickup ${display('pickup', d.pickup)}.`;
    }
  }

  function renderSource() {
    const source = document.getElementById('assistantSource');
    if (!source) return;
    source.replaceChildren();
    if (state.dirty) {
      source.textContent = 'Your edits';
    } else if (state.latest?.id) {
      const link = document.createElement('button');
      link.type = 'button';
      link.className = 'link-btn';
      link.textContent = `Latest load ${state.latest.id}`;
      link.addEventListener('click', () => openShipmentDetails(state.latest.id));
      source.append(link);
    } else {
      source.textContent = isSignedIn() ? 'No loads yet — sample details' : 'Sample details';
    }
  }

  function renderButtons() {
    const editBtn = document.getElementById('editDetailsBtn');
    const createBtn = document.getElementById('createShipmentBtn');
    if (editBtn) {
      editBtn.textContent = state.editing ? 'Save Details' : 'Edit Details';
      editBtn.setAttribute('aria-pressed', String(state.editing));
      editBtn.classList.toggle('btn-primary', state.editing);
      editBtn.classList.toggle('btn-ghost', !state.editing);
    }
    if (createBtn) {
      createBtn.disabled = state.editing;
      createBtn.title = state.editing ? 'Save your details first (Esc cancels)' : '';
    }
    const title = document.getElementById('assistantTitle');
    if (title) title.textContent = state.editing ? 'Edit the details, then save (Esc to cancel):' : "Here's a draft based on your latest load. Please confirm:";
  }

  function renderMap() {
    const set = (id, value) => {
      const node = document.getElementById(id);
      if (node) node.textContent = value;
    };
    const route = state.route;
    set('mapOrigin', cityOf(route?.origin || 'Dallas, TX'));
    set('mapDestination', cityOf(route?.destination || 'Houston, TX'));
    set('mapOriginTime', route?.pickup ? `Pickup ${formatDay(route.pickup)}` : 'Sample');
    set('mapDestinationTime', route?.delivery ? `Delivery ${formatDay(route.delivery)}` : 'Sample');
    set('mapStatus', state.latest?.status || 'Sample route');
    set('mapStatusSub', state.latest?.id ? `${state.latest.id} · latest load` : 'Sign in for live loads');
  }

  function render() {
    renderPrompt();
    renderDetails();
    renderSource();
    renderButtons();
    renderMap();
  }

  function setError(message) {
    const node = document.getElementById('assistantError');
    if (node) node.textContent = message || '';
  }

  function readEditedDraft() {
    const next = {};
    for (const field of FIELDS) {
      const input = document.getElementById(`assistant-${field.key}`);
      next[field.key] = input ? input.value.trim() : state.draft[field.key];
    }
    if (!next.origin || !next.destination) return { error: 'Origin and destination are required.' };
    const weight = Number(next.weight);
    if (!/^\d+$/.test(String(next.weight)) || weight < 1 || weight > MAX_WEIGHT) return { error: `Weight must be a whole number between 1 and ${MAX_WEIGHT.toLocaleString('en-US')} ${weightUnit()}.` };
    if (!equipmentList().includes(next.equipment)) return { error: 'Choose a valid equipment type.' };
    const valid = (value) => /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
    if (!valid(next.pickup) || !valid(next.delivery)) return { error: 'Enter valid pickup and delivery dates.' };
    if (next.delivery < next.pickup) return { error: 'Delivery must be on or after pickup.' };
    return { draft: { ...next, weight } };
  }

  function toggleEdit() {
    if (!state.editing) {
      state.editing = true;
      setError('');
      render();
      document.getElementById('assistant-origin')?.focus();
      return;
    }
    const result = readEditedDraft();
    if (result.error) {
      setError(result.error);
      return;
    }
    state.draft = result.draft;
    state.dirty = true;
    state.editing = false;
    setError('');
    render();
    document.getElementById('editDetailsBtn')?.focus();
  }

  function cancelEdit() {
    if (!state.editing) return;
    state.editing = false;
    setError('');
    render();
    document.getElementById('editDetailsBtn')?.focus();
  }

  function sync(data) {
    const latest = Array.isArray(data?.shipments) ? data.shipments[0] : null;
    state.latest = latest ? { id: latest.id, status: latest.status } : null;
    state.route = data?.route || null;
    if (!state.dirty && !state.editing) {
      const draft = defaultDraft();
      if (data?.route) {
        draft.origin = data.route.origin || draft.origin;
        draft.destination = data.route.destination || draft.destination;
        draft.weight = parseWeight(data.route.weight) || draft.weight;
        if (equipmentList().includes(data.route.equipment)) draft.equipment = data.route.equipment;
      }
      state.draft = draft;
    }
    render();
  }

  function reset() {
    state.draft = defaultDraft();
    state.dirty = false;
    state.editing = false;
    state.latest = null;
    state.route = null;
    setError('');
    render();
  }

  function onSessionChange() {
    if (!isSignedIn()) reset();
  }

  async function openLatest() {
    if (!isSignedIn()) {
      notify('Sign in to track your loads.', 'info');
      document.getElementById('loginTrigger')?.click();
      return;
    }
    if (state.latest?.id) openShipmentDetails(state.latest.id);
    else window.VeyraViews?.navigate('shipments');
  }

  window.VeyraAssistant = { sync, reset, onSessionChange, getDraft: () => ({ ...state.draft }) };

  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('editDetailsBtn')?.addEventListener('click', toggleEdit);
    document.getElementById('mapDetailsBtn')?.addEventListener('click', openLatest);
    document.querySelector('.assistant-card')?.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && state.editing) {
        event.stopPropagation();
        cancelEdit();
      } else if (event.key === 'Enter' && event.target.tagName === 'INPUT') {
        event.preventDefault();
        toggleEdit();
      }
    });
    render();
  });
})();
