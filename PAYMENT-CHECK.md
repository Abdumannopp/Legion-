# Payment check: stopping financial fraud before the money leaves

Business email compromise (BEC), a fake-voice "CEO" call and stolen accounts all
end the same way: money is sent to the attacker's account. Legion is not in the
payment path, so **your payment software (ERP, bank connector, accounting) asks
Legion before sending money**. Legion answers "allow" or "hold".

## Before the first check (hosted workspaces)

An administrator must first read and confirm the notice in Dashboard → **Defense** → **Payments on hold**:
what a "hold" is, that a person decides, that Legion's answers are not financial advice and can be wrong, and that
the customer remains responsible for payments. Who confirmed, when, and which version of the text are recorded
and written to the audit log.

Until it is confirmed, a **new** workspace's check answers `403` (`acknowledgement_required`), so the client exits
with `1` and **your payment software must not pay automatically**: nothing is decided, nothing is stored. A
workspace that was already using the check is asked to confirm but is not cut off. If the text of the notice changes
in substance, the version number rises and administrators are asked again. A self-hosted installation is not asked.

## When a payment is held

| Reason | Meaning |
|---|---|
| New account | Your organisation has never made a confirmed payment to this account number. "Our bank details have changed" is the most common start of fraud. |
| Requester under attack | The account or mailbox of the person asking for the payment is compromised (there is an active campaign in Legion). |
| Mailbox being taken over | A mailbox in the organisation showed takeover signs in the last 48 hours. |
| Rejected before | Someone has already rejected this exact payment. |

A held payment appears in Dashboard → **Defense** → **Payments on hold**, and an
alert is raised (the Executor agent, MITRE T1657).

## What a person does

1. Call the supplier or colleague on a number **you already had** — not one from
   the email, the invoice, or given by the caller. A familiar voice or video can
   be fake.
2. If confirmed — **"Confirmed by phone — release"** (administrators only). The
   account number is then "confirmed", and later payments to it are not held as
   a new account.
3. If not — **"Reject"**. The payment software keeps it on hold.

Every check, release and rejection is written to the audit log.

## Connecting your payment software

It uses the same sensor credential issued for Wazuh (Dashboard → Connect).
A ready-made client is `integrations/custom-legion.py`:

```bash
custom-legion.py --payment-check @/etc/legion.key \
  https://legion.example.com/security-events/webhook  payment.json
```

`payment.json`:

```json
{
  "beneficiary": { "account": "DE89 3704 0044 0532 0130 00", "name": "Acme Supplies Ltd" },
  "amount": 12500,
  "currency": "EUR",
  "requestedBy": "dana@acme.example",
  "reference": "INV-2026-0042"
}
```

Result (exit code):

| Code | Meaning | What the payment software does |
|---|---|---|
| `0` | allow | sends the payment |
| `3` | held | does not send; asks again later |
| `1` | error (Legion unreachable, too many checks, etc.) | **does not send automatically** |

The answer is also printed as JSON (with the reasons and how to verify). The
request is signed (HMAC, timestamp, one-time nonce) and accepted only for the
payment check.

Each organisation may make at most 120 checks per minute; above that Legion
answers 429 and the client exits with `1`. At most 20 held-payment alerts are
raised per hour; above that payments are still held, without new alerts.

## Privacy

The account number **itself is never stored**. Legion keeps only a keyed hash
(to recognise the account again) and the last 4 characters (for a person to
recognise it). The hash is different for every organisation.

## Honest limits

- **If the payment software does not ask Legion, Legion cannot stop the
  payment.** Legion cannot reach into your bank or ERP; this connection is needed.
- On an error (`1`) the payment must not be sent automatically — the payment
  software itself has to enforce that.
- Legion does not verify the amount or the account holder with the bank; it
  looks only at the organisation's own history and active attacks.
- The confirmation call is a human step. Clicking "release" without making it
  defeats the protection.
