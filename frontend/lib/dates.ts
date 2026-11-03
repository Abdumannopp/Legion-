/**
 * Timestamps from the API. The current server sends full ISO strings with a
 * zone ("…Z"); the original API sent zone-less UTC, and the dashboard still
 * appended "Z" to every value — which turned "…Z" into "…ZZ", an Invalid
 * Date, and "NaNd ago" on every alert. Add the zone only when it is missing.
 */
export function apiDate(value: string): Date {
  return new Date(/(Z|[+-]\d{2}:?\d{2})$/i.test(value) ? value : `${value}Z`);
}
