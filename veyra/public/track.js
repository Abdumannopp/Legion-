// Public tracking page: shows one load's status to a customer who has the link. No account, no other data.
(function () {
  const root = document.getElementById('track');
  const token = window.location.pathname.split('/').filter(Boolean).pop() || '';
  const node = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  };
  const when = (value) => {
    if (!value) return '';
    const date = new Date(/T|Z/.test(value) ? value : `${String(value).replace(' ', 'T')}Z`);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  };
  const STEPS = ['Booked', 'On the way', 'Delivered'];
  const stepOf = { Dispatched: 0, 'In Transit': 1, Exception: 1, Delivered: 2 };
  const friendly = {
    New: 'Order received', Sourcing: 'Looking for a truck', 'Pending Approval': 'Being confirmed', Dispatched: 'Truck booked',
    'In Transit': 'On the way', Exception: 'Delayed — our team is working on it', Delivered: 'Delivered', Cancelled: 'Cancelled'
  };

  function show(data) {
    const fact = (label, value) => {
      const row = node('div', 'fact');
      row.append(node('span', '', label), node('strong', '', value || '—'));
      return row;
    };
    const steps = node('ol', 'steps');
    const current = stepOf[data.status];
    STEPS.forEach((name, index) => steps.append(node('li', current !== undefined && index <= current ? 'done' : '', name)));
    const facts = node('div', 'facts');
    facts.append(
      fact('From', data.origin), fact('To', data.destination), fact('Pickup', data.pickup), fact('Planned delivery', data.delivery),
      fact('Last known place', data.lastLocation ? `${data.lastLocation}${data.lastTrackedAt ? ` (${when(data.lastTrackedAt)})` : ''}` : 'No update yet'),
      fact('Expected arrival', data.eta ? when(data.eta) : '—'), fact('Truck', data.truckPlate), fact('Your reference', data.reference)
    );
    root.replaceChildren(
      node('p', 'company', data.company),
      node('h1', '', `Shipment ${data.load}`),
      node('p', `status status-${String(data.status).toLowerCase().replace(/\s+/g, '-')}`, friendly[data.status] || data.status),
      data.status === 'Cancelled' ? '' : steps,
      facts,
      node('p', 'muted', `Updated ${when(new Date().toISOString())}. This page refreshes every few minutes.`)
    );
    document.title = `${data.load} · ${friendly[data.status] || data.status}`;
  }

  async function load() {
    try {
      const response = await fetch(`/api/public/track/${encodeURIComponent(token)}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Tracking is unavailable.');
      show(data);
    } catch (error) {
      root.replaceChildren(node('h1', '', 'Tracking unavailable'), node('p', 'muted', error.message));
    }
  }
  load();
  setInterval(load, 5 * 60 * 1000);
}());
