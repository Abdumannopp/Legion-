/**
 * Requirement 1: a stranger cannot become the first administrator.
 *
 * On a brand-new self-hosted install nobody has an account yet, so "who may
 * create the first one" cannot be answered by a login. It is answered by a
 * one-time setup token that the server prints to its own console at startup:
 * only someone with access to the machine Legion was installed on can read it.
 *
 * Two separate attacks are covered:
 *  - the stranger who simply gets to the setup page first (no token → refused);
 *  - the race, where several registrations arrive at once and each one sees
 *    "no workspace yet" before any of them has written one.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import { app } from "../src/index.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as setup from "../src/setup-token.js";

const owner = (n = 0) => ({
  email: `owner${n}@onprem.local`,
  password: "a-good-password",
  tenant_name: `On-Prem Corp ${n}`,
});

beforeAll(async () => {
  await migrate();
  config.deploymentMode = "self-hosted";
});

afterAll(async () => {
  config.deploymentMode = "saas";
  await closePool();
});

beforeEach(async () => {
  await truncateAll(); // every test starts as a brand-new installation
});

describe("without the setup token", () => {
  it("refuses to create the first administrator", async () => {
    await setup.issueSetupToken();
    const res = await request(app).post("/auth/register").send(owner()).expect(403);
    expect(res.body.detail).toMatch(/setup token/i);
    const { rows } = await query("SELECT count(*)::int AS n FROM users");
    expect(rows[0].n).toBe(0);
  });

  it("refuses a wrong token", async () => {
    await setup.issueSetupToken();
    await request(app)
      .post("/auth/register")
      .send({ ...owner(), setup_token: "lst_" + "0".repeat(43) })
      .expect(403);
  });

  it("refuses when no token has been issued at all", async () => {
    // e.g. the tokens table was wiped: fail closed, never open.
    await request(app)
      .post("/auth/register")
      .send({ ...owner(), setup_token: "anything" })
      .expect(403);
  });
});

describe("with the setup token", () => {
  it("creates the first administrator", async () => {
    const token = await setup.issueSetupToken();
    const res = await request(app)
      .post("/auth/register")
      .send({ ...owner(), setup_token: token })
      .expect(201);
    expect(res.body.role).toBe("admin");
  });

  it("works only once", async () => {
    const token = await setup.issueSetupToken();
    await request(app).post("/auth/register").send({ ...owner(1), setup_token: token }).expect(201);
    await request(app).post("/auth/register").send({ ...owner(2), setup_token: token }).expect(403);
    const { rows } = await query("SELECT count(*)::int AS n FROM tenants");
    expect(rows[0].n).toBe(1);
  });

  it("is stored only as a hash — a database copy does not reveal it", async () => {
    const token = await setup.issueSetupToken();
    const { rows } = await query("SELECT token_hash FROM setup_token");
    expect(rows).toHaveLength(1);
    expect(rows[0].token_hash).not.toContain(token);
    expect(rows[0].token_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("the race", () => {
  it("lets exactly one of many simultaneous registrations through", async () => {
    // Before the fix: the "is anyone set up yet?" check happened, then a
    // quarter-second bcrypt hash, then the insert. Every request in that
    // window saw an empty installation and created its own administrator.
    const token = await setup.issueSetupToken();
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        request(app).post("/auth/register").send({ ...owner(i), setup_token: token })
      )
    );
    const created = results.filter((r) => r.status === 201);
    expect(created).toHaveLength(1);
    expect(results.filter((r) => r.status === 403)).toHaveLength(9);

    const { rows } = await query(
      "SELECT (SELECT count(*) FROM tenants)::int AS t, (SELECT count(*) FROM users)::int AS u"
    );
    expect(rows[0]).toEqual({ t: 1, u: 1 });
  });

  it("is also closed when the attackers do not have the token", async () => {
    // Belt and braces: even if the token check were removed, the database
    // lock alone must still stop a second workspace appearing.
    const token = await setup.issueSetupToken();
    const results = await Promise.all([
      request(app).post("/auth/register").send({ ...owner(0), setup_token: token }),
      ...Array.from({ length: 5 }, (_, i) =>
        request(app).post("/auth/register").send(owner(i + 1))
      ),
    ]);
    expect(results.filter((r) => r.status === 201)).toHaveLength(1);
    const { rows } = await query("SELECT count(*)::int AS n FROM tenants");
    expect(rows[0].n).toBe(1);
  });
});

describe("hosted (SaaS) mode is unchanged", () => {
  it("still allows open sign-up without a token", async () => {
    config.deploymentMode = "saas";
    try {
      await request(app).post("/auth/register").send(owner()).expect(201);
      await request(app).post("/auth/register").send(owner(1)).expect(201);
    } finally {
      config.deploymentMode = "self-hosted";
    }
  });
});
