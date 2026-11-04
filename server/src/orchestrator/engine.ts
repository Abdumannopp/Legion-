/**
 * Agent Orchestrator v0.
 *
 * Workflows are defined here, in code: a fixed list of steps, each naming the
 * agent that performs it and the catalog action it may propose. The
 * orchestrator decides nothing about permissions:
 *
 *  - each step's actor is the step's agent, asserted by this engine — never
 *    taken from a request, an alert or a model;
 *  - each step goes through the action engine (policy, approvals, emergency
 *    stop) exactly like a person's proposal;
 *  - step inputs are derived deterministically from the trigger (the alert),
 *    and validated again by the catalog schema;
 *  - there are no loops and no dynamic steps: at most MAX_STEPS per run;
 *  - a run is idempotent per (workflow, alert, mode), and each step's action
 *    has a deterministic idempotency key, so re-running never duplicates.
 *
 * v0 uses no language model at all. Alert text is attacker-controlled data;
 * it is never interpreted as an instruction here.
 */
import { randomUUID } from "node:crypto";
import { queryAll, queryOne } from "../db/pool.js";
import { isPublicAddress } from "../blocklist.js";
import * as store from "../store.js";
import type { Agent, Alert } from "../types.js";
import { ActionError, proposeAction, runQueued, type ActionRequest } from "../actions/engine.js";
import type { ActorRef } from "../policy/types.js";

export const MAX_STEPS = 10;

interface StepDefinition {
  name: string;
  agent: Agent;
  action_id: string;
  /** The step's input from the alert, or null when the step does not apply. */
  input: (alert: Alert, previous: StepResult[]) => Record<string, unknown> | null;
}

export interface WorkflowDefinition { name: string; summary: string; trigger: "alert"; steps: readonly StepDefinition[] }

export interface StepResult {
  name: string;
  agent: Agent;
  action_id: string;
  outcome: "proposed" | "skipped" | "refused";
  action_request_id: string | null;
  action_status: string | null;
  note: string | null;
}

const WORKFLOWS: readonly WorkflowDefinition[] = [
  {
    name: "alert_response",
    summary: "Triage an alert, prepare containment of its source, tell the administrators about critical ones",
    trigger: "alert",
    steps: [
      { name: "triage", agent: "Oracle", action_id: "alert.triage", input: (a) => ({ alert_id: a.id }) },
      {
        name: "contain_source", agent: "Vanguard", action_id: "ip.block",
        input: (a) => (a.source_ip && isPublicAddress(a.source_ip) && (a.severity === "high" || a.severity === "critical")
          ? { ip: a.source_ip, minutes: 60, reason: `Prepared by Vanguard for alert ${a.id}` }
          : null),
      },
      {
        name: "notify", agent: "Sentinel", action_id: "notify.admins",
        input: (a) => (a.severity === "critical" ? { subject: `Critical alert ${a.id}`, alert_id: a.id } : null),
      },
    ],
  },
];

export function workflowDefinitions(): Array<{ name: string; summary: string; trigger: string; steps: Array<{ name: string; agent: Agent; action_id: string }> }> {
  return WORKFLOWS.map((w) => ({ name: w.name, summary: w.summary, trigger: w.trigger, steps: w.steps.map(({ name, agent, action_id }) => ({ name, agent, action_id })) }));
}

export class WorkflowError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) { super(message); }
}

export interface WorkflowRun {
  id: string; tenant_id: string; workflow: string; trigger_type: string; trigger_id: string; mode: "shadow" | "simulation";
  status: "running" | "completed" | "failed"; steps: StepResult[]; started_by: ActorRef; error: string | null; created_at: string; finished_at: string | null;
}
type Row = Omit<WorkflowRun, "created_at" | "finished_at"> & { created_at: Date; finished_at: Date | null };
const COLUMNS = "tenant_id, id, workflow, trigger_type, trigger_id, mode, status, steps, started_by, error, created_at, finished_at";
const toRun = (r: Row): WorkflowRun => ({ ...r, created_at: r.created_at.toISOString(), finished_at: r.finished_at?.toISOString() ?? null });

/**
 * Runs (or returns the existing run of) a workflow for one alert.
 * `startedBy` is who asked for the run; each step still acts as its own agent.
 */
export async function runWorkflow(tenantId: string, name: string, alertId: string, mode: "shadow" | "simulation", startedBy: ActorRef): Promise<{ run: WorkflowRun; replayed: boolean }> {
  const wf = WORKFLOWS.find((w) => w.name === name);
  if (!wf) throw new WorkflowError(404, "unknown_workflow", "No such workflow");
  if (wf.steps.length > MAX_STEPS) throw new WorkflowError(500, "too_many_steps", "Workflow is too long");
  const alert = await store.getAlert(tenantId, alertId);
  if (!alert) throw new WorkflowError(404, "alert_not_found", "Alert not found");

  const id = randomUUID();
  const inserted = await queryOne<Row>(
    `INSERT INTO workflow_runs (tenant_id, id, workflow, trigger_type, trigger_id, mode, status, started_by)
     VALUES ($1, $2, $3, 'alert', $4, $5, 'running', $6)
     ON CONFLICT (tenant_id, workflow, trigger_type, trigger_id, mode) DO NOTHING RETURNING ${COLUMNS}`,
    [tenantId, id, wf.name, alert.id, mode, JSON.stringify(startedBy)],
  );
  if (!inserted) {
    const existing = await queryOne<Row>(
      `SELECT ${COLUMNS} FROM workflow_runs WHERE tenant_id = $1 AND workflow = $2 AND trigger_type = 'alert' AND trigger_id = $3 AND mode = $4`,
      [tenantId, wf.name, alert.id, mode],
    );
    return { run: toRun(existing!), replayed: true };
  }

  const results: StepResult[] = [];
  let status: "completed" | "failed" = "completed";
  let error: string | null = null;
  try {
    for (const step of wf.steps) {
      const input = step.input(alert, results);
      const base = { name: step.name, agent: step.agent, action_id: step.action_id };
      if (!input) { results.push({ ...base, outcome: "skipped", action_request_id: null, action_status: null, note: "does not apply to this alert" }); continue; }
      try {
        const { action } = await proposeAction(tenantId, {
          action_id: step.action_id, input, mode,
          actor: { kind: "agent", agent: step.agent }, origin: "agent",
          idempotency_key: `wf:${id}:${step.name}`,
          reason: `workflow ${wf.name}, step ${step.name}`,
        });
        const settled: ActionRequest | null = action.status === "queued" ? await runQueued(tenantId, action.id) : action;
        results.push({ ...base, outcome: "proposed", action_request_id: action.id, action_status: settled?.status ?? action.status, note: null });
      } catch (e) {
        if (!(e instanceof ActionError)) throw e;
        results.push({ ...base, outcome: "refused", action_request_id: null, action_status: null, note: e.code });
        if (e.code === "paused") break; // emergency stop: no further steps
      }
    }
  } catch (e) {
    status = "failed";
    error = (e instanceof Error ? e.message : "workflow failed").slice(0, 500);
  }
  const done = await queryOne<Row>(
    `UPDATE workflow_runs SET status = $3, steps = $4, error = $5, finished_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING ${COLUMNS}`,
    [tenantId, id, status, JSON.stringify(results), error],
  );
  return { run: toRun(done!), replayed: false };
}

export async function getRun(tenantId: string, id: string): Promise<WorkflowRun | null> {
  if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
  const r = await queryOne<Row>(`SELECT ${COLUMNS} FROM workflow_runs WHERE tenant_id = $1 AND id = $2`, [tenantId, id]);
  return r ? toRun(r) : null;
}

export async function listRuns(tenantId: string, limit: number): Promise<WorkflowRun[]> {
  return (await queryAll<Row>(`SELECT ${COLUMNS} FROM workflow_runs WHERE tenant_id = $1 ORDER BY created_at DESC, id LIMIT $2`, [tenantId, limit])).map(toRun);
}
