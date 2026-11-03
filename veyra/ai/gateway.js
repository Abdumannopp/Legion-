// AI Gateway: the only place VEYRA talks to a language model.
//
// - Provider: OpenRouter (one key, many models). No key = AI is off; nothing leaves the server.
// - Model: OPENROUTER_MODEL. Left empty on purpose, so no model name is hard-coded that may
//   later be retired; OpenRouter then uses the account's default model.
// - No HTTP-Referer header: it would reveal the server's address. Only the title "VEYRA" is sent.
// - Every call is logged in agent_tasks (agent, model, tokens, time, result) for cost control.
// - The model only ever returns data (JSON). It cannot call tools or write to the database;
//   callers validate the JSON with the same rules as human input.
const { httpError } = require('../lib/validation');

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';
const TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS) || 20000;

let transport = (url, init) => fetch(url, init);

// Tests replace the network with a fake; production never calls this.
function setTransport(fn) {
  transport = fn || ((url, init) => fetch(url, init));
}

function isEnabled() {
  return Boolean(process.env.OPENROUTER_API_KEY);
}

function modelName() {
  return process.env.OPENROUTER_MODEL ? process.env.OPENROUTER_MODEL.trim() : '';
}

// Models sometimes wrap JSON in ``` fences or add a sentence; take the first JSON object.
function extractJson(text) {
  const cleaned = String(text || '').replace(/```(?:json)?/gi, '').trim();
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start === -1 || end <= start) throw new Error('Model did not return JSON.');
  return JSON.parse(cleaned.slice(start, end + 1));
}

async function callOnce(body, signal) {
  const response = await transport(OPENROUTER_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
      'Content-Type': 'application/json',
      'X-Title': 'VEYRA'
    },
    body: JSON.stringify(body),
    signal
  });
  const text = await response.text();
  let data = null;
  try {
    data = JSON.parse(text);
  } catch (_) {
    data = null;
  }
  if (!response.ok) {
    const error = new Error(data?.error?.message || `AI provider returned ${response.status}`);
    error.retryable = response.status === 429 || response.status >= 500;
    throw error;
  }
  return data;
}

/**
 * Ask the model for a JSON object.
 * @param {object} options
 * @param {string} options.agent        Agent name for the log (FLOW, RELAY, ...).
 * @param {string} options.system       Trusted instructions.
 * @param {string} options.user         Untrusted content (an email, a chat message).
 * @param {(task: object) => Promise<void>} options.log  Writes the agent_tasks row.
 */
async function completeJson({ agent, system, user, maxTokens = 700, log }) {
  if (!isEnabled()) throw httpError(503, 'AI is not configured. Add OPENROUTER_API_KEY to the server settings.');
  const body = {
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user }
    ],
    temperature: 0,
    max_tokens: maxTokens
  };
  const model = modelName();
  if (model) body.model = model;

  const started = Date.now();
  let lastError;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const data = await callOnce(body, controller.signal);
      clearTimeout(timer);
      const content = data?.choices?.[0]?.message?.content;
      const parsed = extractJson(content);
      await log?.({
        agent,
        status: 'succeeded',
        model: data?.model || model || null,
        inputTokens: data?.usage?.prompt_tokens ?? null,
        outputTokens: data?.usage?.completion_tokens ?? null,
        latencyMs: Date.now() - started
      });
      return parsed;
    } catch (error) {
      clearTimeout(timer);
      lastError = error.name === 'AbortError' ? new Error('AI provider timed out.') : error;
      const retryable = error.name === 'AbortError' || error.retryable || error instanceof TypeError;
      if (!retryable || attempt === 1) break;
    }
  }
  await log?.({ agent, status: 'failed', model: model || null, latencyMs: Date.now() - started, error: lastError?.message });
  throw httpError(502, 'The AI assistant could not answer right now. Please fill the form by hand or try again.');
}

module.exports = { completeJson, isEnabled, setTransport, extractJson };
