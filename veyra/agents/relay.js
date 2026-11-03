// RELAY — operational messages to the driver, the carrier or the customer.
// Drafts come from fixed templates (no language model): they are free, instant and always
// state the load's real data. A person reads the draft, may edit it, and presses Send.
// The phone number always comes from the load record, never from the browser, so the
// app cannot be used to text arbitrary numbers.

const LANGUAGES = ['uz', 'ru', 'en'];

const PURPOSES = {
  driver: ['pickup_details', 'location_request'],
  carrier: ['booking_confirmation'],
  customer: ['booking_confirmation', 'status_update', 'delivered']
};

const TEMPLATES = {
  en: {
    pickup_details: (d) => `Hello ${d.driver || 'driver'}, load ${d.id}: pickup ${d.pickup} at ${d.origin}, delivery ${d.delivery} to ${d.destination}. ${d.weight}${d.equipment ? `, ${d.equipment}` : ''}.${d.reference ? ` Ref ${d.reference}.` : ''} — ${d.company}`,
    location_request: (d) => `Hello ${d.driver || 'driver'}, please reply with your current location and ETA for load ${d.id} (${d.origin} → ${d.destination}). Thank you — ${d.company}`,
    booking_confirmation_carrier: (d) => `${d.company}: load ${d.id} booked with ${d.carrier}. ${d.origin} → ${d.destination}, pickup ${d.pickup}, delivery ${d.delivery}. Rate ${d.rate}.${d.plate ? ` Truck ${d.plate}.` : ''}`,
    booking_confirmation_customer: (d) => `${d.company}: your load ${d.id}${d.reference ? ` (ref ${d.reference})` : ''} ${d.origin} → ${d.destination} has a truck booked${d.plate ? ` (${d.plate})` : ''}. Pickup ${d.pickup}.`,
    status_update: (d) => `${d.company}: load ${d.id}${d.reference ? ` (ref ${d.reference})` : ''} is ${d.status}.${d.location ? ` Last location: ${d.location}.` : ''}${d.eta ? ` ETA ${d.eta}.` : ''}`,
    delivered: (d) => `${d.company}: load ${d.id}${d.reference ? ` (ref ${d.reference})` : ''} was delivered to ${d.destination}. Thank you for your business.`
  },
  ru: {
    pickup_details: (d) => `Здравствуйте, ${d.driver || 'водитель'}! Груз ${d.id}: загрузка ${d.pickup}, ${d.origin}; выгрузка ${d.delivery}, ${d.destination}. ${d.weight}${d.equipment ? `, ${d.equipment}` : ''}.${d.reference ? ` Номер заказа ${d.reference}.` : ''} — ${d.company}`,
    location_request: (d) => `Здравствуйте, ${d.driver || 'водитель'}! Сообщите, пожалуйста, где вы сейчас и когда ожидается прибытие по грузу ${d.id} (${d.origin} → ${d.destination}). Спасибо — ${d.company}`,
    booking_confirmation_carrier: (d) => `${d.company}: груз ${d.id} забронирован за ${d.carrier}. ${d.origin} → ${d.destination}, загрузка ${d.pickup}, выгрузка ${d.delivery}. Ставка ${d.rate}.${d.plate ? ` Машина ${d.plate}.` : ''}`,
    booking_confirmation_customer: (d) => `${d.company}: для вашего груза ${d.id}${d.reference ? ` (заказ ${d.reference})` : ''} ${d.origin} → ${d.destination} назначена машина${d.plate ? ` (${d.plate})` : ''}. Загрузка ${d.pickup}.`,
    status_update: (d) => `${d.company}: груз ${d.id}${d.reference ? ` (заказ ${d.reference})` : ''} — статус: ${d.status}.${d.location ? ` Последнее местоположение: ${d.location}.` : ''}${d.eta ? ` Прибытие: ${d.eta}.` : ''}`,
    delivered: (d) => `${d.company}: груз ${d.id}${d.reference ? ` (заказ ${d.reference})` : ''} доставлен в ${d.destination}. Спасибо за сотрудничество.`
  },
  uz: {
    pickup_details: (d) => `Assalomu alaykum, ${d.driver || 'haydovchi'}! Yuk ${d.id}: yuklash ${d.pickup}, ${d.origin}; tushirish ${d.delivery}, ${d.destination}. ${d.weight}${d.equipment ? `, ${d.equipment}` : ''}.${d.reference ? ` Buyurtma raqami ${d.reference}.` : ''} — ${d.company}`,
    location_request: (d) => `Assalomu alaykum, ${d.driver || 'haydovchi'}! Iltimos, ${d.id} yuki (${d.origin} → ${d.destination}) bo'yicha hozir qayerdaligingiz va qachon yetib borishingizni yozing. Rahmat — ${d.company}`,
    booking_confirmation_carrier: (d) => `${d.company}: ${d.id} yuki ${d.carrier} uchun band qilindi. ${d.origin} → ${d.destination}, yuklash ${d.pickup}, tushirish ${d.delivery}. Narx ${d.rate}.${d.plate ? ` Mashina ${d.plate}.` : ''}`,
    booking_confirmation_customer: (d) => `${d.company}: ${d.id}${d.reference ? ` (buyurtma ${d.reference})` : ''} yukingiz ${d.origin} → ${d.destination} uchun mashina ajratildi${d.plate ? ` (${d.plate})` : ''}. Yuklash ${d.pickup}.`,
    status_update: (d) => `${d.company}: ${d.id}${d.reference ? ` (buyurtma ${d.reference})` : ''} yuk holati: ${d.status}.${d.location ? ` Oxirgi joylashuv: ${d.location}.` : ''}${d.eta ? ` Yetib borish: ${d.eta}.` : ''}`,
    delivered: (d) => `${d.company}: ${d.id}${d.reference ? ` (buyurtma ${d.reference})` : ''} yuk ${d.destination} manziliga yetkazildi. Hamkorligingiz uchun rahmat.`
  }
};

function recipientPhone(shipment, recipient) {
  if (recipient === 'driver') return shipment.driver_phone || null;
  if (recipient === 'carrier') return shipment.carrierPhone || null;
  if (recipient === 'customer') return shipment.customer_phone || null;
  return null;
}

function draftMessage({ shipment, recipient, purpose, language, company, formatMoney }) {
  const lang = LANGUAGES.includes(language) ? language : 'en';
  const allowed = PURPOSES[recipient] || [];
  const chosen = allowed.includes(purpose) ? purpose : allowed[0];
  if (!chosen) return null;
  const key = chosen === 'booking_confirmation' ? `booking_confirmation_${recipient}` : chosen;
  const data = {
    id: `SHP-${shipment.id}`,
    company,
    customer: shipment.customer,
    origin: shipment.origin,
    destination: shipment.destination,
    pickup: shipment.pickup,
    delivery: shipment.delivery,
    weight: shipment.weight,
    equipment: shipment.equipment,
    reference: shipment.reference,
    carrier: shipment.carrierName,
    rate: shipment.rate !== null && shipment.rate !== undefined ? formatMoney(shipment.rate) : '—',
    plate: shipment.truck_plate,
    driver: shipment.driver_name,
    status: shipment.status,
    location: shipment.last_location,
    eta: shipment.eta ? String(shipment.eta).replace('T', ' ') : null
  };
  return { purpose: chosen, language: lang, body: TEMPLATES[lang][key](data), to: recipientPhone(shipment, recipient) };
}

module.exports = { draftMessage, recipientPhone, LANGUAGES, PURPOSES };
