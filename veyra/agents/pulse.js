// PULSE — price sense from the company's own past loads on the same lane. No language model and
// no outside market feed: it answers "what did we pay and charge here before, and is this price unusual?"
// It only advises; a person sets the price.
const { median } = require('./route');

const MIN_SAMPLES = 3;
const UNUSUAL_SHARE = 0.3;
const THIN_MARGIN = 0.05;
const round2 = (value) => Math.round(value * 100) / 100;

function stats(values) {
  if (values.length < MIN_SAMPLES) return null;
  return { loads: values.length, typical: round2(median(values)), lowest: round2(Math.min(...values)), highest: round2(Math.max(...values)) };
}

// data: from db.getPulseData. rate / customerRate: prices being considered (optional; default to the load's own).
function analyzePrices(data, { rate = null, customerRate = null, formatMoney = (value) => String(value) } = {}) {
  const { shipment } = data;
  const paid = rate ?? shipment.rate ?? null;
  const charged = customerRate ?? shipment.customer_rate ?? null;

  // Prefer loads with the same trailer type when there are enough of them.
  const sameEquipment = data.history.filter((row) => row.equipment === shipment.equipment);
  const usable = (rows) => rows.filter((row) => row.rate !== null && row.rate !== undefined).length >= MIN_SAMPLES;
  const rows = usable(sameEquipment) ? sameEquipment : data.history;
  const basis = rows === sameEquipment && sameEquipment.length ? `same lane and ${shipment.equipment}` : 'same lane, any trailer';

  const number = (value) => (value === null || value === undefined ? null : Number(value));
  const carrierRates = rows.map((row) => number(row.rate)).filter((value) => value > 0);
  const customerRates = rows.map((row) => number(row.customerRate)).filter((value) => value > 0);
  const marginShares = rows
    .filter((row) => number(row.rate) > 0 && number(row.customerRate) > 0)
    .map((row) => (row.customerRate - row.rate) / row.customerRate);

  const carrier = stats(carrierRates);
  const customer = stats(customerRates);
  const typicalMargin = marginShares.length >= MIN_SAMPLES ? median(marginShares) : null;

  // What to ask the customer: keep the usual margin on top of the carrier's price.
  let suggestedCustomerPrice = null;
  let suggestionBasis = null;
  if (paid && typicalMargin !== null && typicalMargin > 0 && typicalMargin < 0.9) {
    suggestedCustomerPrice = round2(paid / (1 - typicalMargin));
    suggestionBasis = `carrier price plus the usual ${Math.round(typicalMargin * 100)}% margin on this lane`;
  } else if (customer) {
    suggestedCustomerPrice = customer.typical;
    suggestionBasis = `typical customer price on ${customer.loads} past loads`;
  }

  const flags = [];
  if (paid && carrier) {
    const difference = (paid - carrier.typical) / carrier.typical;
    if (difference > UNUSUAL_SHARE) flags.push({ code: 'carrier_high', level: 'warn', text: `The carrier price ${formatMoney(paid)} is ${Math.round(difference * 100)}% above the usual ${formatMoney(carrier.typical)} on this lane.` });
    if (difference < -UNUSUAL_SHARE) flags.push({ code: 'carrier_low', level: 'info', text: `The carrier price ${formatMoney(paid)} is ${Math.round(-difference * 100)}% below the usual ${formatMoney(carrier.typical)}. Check that the carrier understood the load.` });
  }
  if (charged && customer) {
    const difference = (charged - customer.typical) / customer.typical;
    if (difference < -UNUSUAL_SHARE) flags.push({ code: 'customer_low', level: 'warn', text: `The customer price ${formatMoney(charged)} is ${Math.round(-difference * 100)}% below the usual ${formatMoney(customer.typical)} on this lane.` });
  }
  let margin = null;
  if (paid && charged) {
    margin = { amount: round2(charged - paid), share: round2((charged - paid) / charged) };
    if (margin.amount < 0) flags.push({ code: 'loss', level: 'warn', text: `This load loses ${formatMoney(-margin.amount)}: the customer pays less than the carrier costs.` });
    else if (margin.share < THIN_MARGIN) flags.push({ code: 'thin_margin', level: 'warn', text: `The margin is only ${Math.round(margin.share * 100)}% (${formatMoney(margin.amount)}).` });
  }

  return {
    basis,
    loads: rows.length,
    carrier,
    customer,
    typicalMarginShare: typicalMargin === null ? null : round2(typicalMargin),
    suggestedCustomerPrice,
    suggestionBasis,
    margin,
    flags,
    enoughHistory: Boolean(carrier || customer)
  };
}

module.exports = { analyzePrices, MIN_SAMPLES };
