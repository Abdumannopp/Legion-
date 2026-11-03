// SCOUT — carrier sourcing. Ranks the company's available carriers for one load and suggests
// a rate. This is deterministic code, not a language model ("no LLM for what a formula can do"):
// it is free, instant, and the same input always gives the same, explainable answer.
// SCOUT only recommends; a person still chooses the carrier and books the truck.

// Which carrier service fits which trailer the load needs.
const MODE_FOR_EQUIPMENT = {
  'Dry Van': ['Truckload'],
  'Tent / Curtainsider': ['Truckload'],
  Reefer: ['Reefer'],
  Flatbed: ['Flatbed'],
  LTL: ['LTL'],
  Expedited: ['Expedited', 'Truckload']
};

function rankCarriers({ shipment, carriers, laneAverageRate, laneLoads }) {
  const fits = MODE_FOR_EQUIPMENT[shipment.equipment] || [];
  const ranked = carriers.map((carrier) => {
    let score = 0;
    const reasons = [];

    if (fits.includes(carrier.mode)) {
      score += 40;
      reasons.push(`${carrier.mode} fits ${shipment.equipment}`);
    } else if (fits.length) {
      reasons.push(`${carrier.mode} may not fit ${shipment.equipment}`);
    }

    if (carrier.laneDelivered) {
      score += Math.min(carrier.laneDelivered * 10, 30);
      reasons.push(`Delivered ${carrier.laneDelivered} load${carrier.laneDelivered === 1 ? '' : 's'} on this lane`);
    }
    if (carrier.delivered) {
      score += Math.min(carrier.delivered * 2, 20);
    }
    const handled = carrier.delivered + carrier.exceptionLoads;
    if (carrier.exceptionLoads && handled) {
      const exceptionShare = carrier.exceptionLoads / handled;
      score -= Math.round(exceptionShare * 20);
      reasons.push(`${carrier.exceptionLoads} past load${carrier.exceptionLoads === 1 ? '' : 's'} with problems`);
    }
    if (!carrier.delivered && !carrier.exceptionLoads) reasons.push('No delivery history yet');
    if (!carrier.phone) reasons.push('No phone number on file');

    const suggestedRate = carrier.laneAverageRate ?? laneAverageRate ?? null;
    return {
      carrierId: carrier.id,
      name: carrier.name,
      mode: carrier.mode,
      phone: carrier.phone,
      score: Math.max(score, 0),
      reasons,
      suggestedRate: suggestedRate === null ? null : Math.round(suggestedRate * 100) / 100,
      rateBasis: carrier.laneAverageRate !== null && carrier.laneAverageRate !== undefined
        ? 'This carrier\'s average on this lane'
        : (laneAverageRate !== null && laneAverageRate !== undefined ? `Company average on this lane (${laneLoads} loads)` : null)
    };
  });
  ranked.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  return ranked;
}

module.exports = { rankCarriers, MODE_FOR_EQUIPMENT };
