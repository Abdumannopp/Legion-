/**
 * Which third party — if any — sees the customer's alert text.
 *
 * This is a privacy decision before it is a feature decision, so the rule is a
 * pure function with its own tests rather than a branch buried in a fetch call.
 * The case that matters most is the one where an operator names a provider and
 * the key for it is missing: nothing may be sent to the *other* provider.
 */
import { describe, it, expect } from "vitest";
import { resolveProvider, aiConfigWarnings, type AiSettings } from "../src/ai.js";

const off: AiSettings = {
  aiProvider: "",
  openrouterApiKey: "",
  openrouterModel: "",
  groqApiKey: "",
  groqModel: "llama-3.3-70b-versatile",
};

const settings = (overrides: Partial<AiSettings>): AiSettings => ({ ...off, ...overrides });

describe("no key at all", () => {
  it("resolves to no provider", () => {
    expect(resolveProvider(off)).toBeNull();
  });

  it("says nothing — an install with no AI is the default, not a mistake", () => {
    expect(aiConfigWarnings(off)).toEqual([]);
  });
});

describe("one key set", () => {
  it("uses OpenRouter when only its key is present", () => {
    const provider = resolveProvider(settings({ openrouterApiKey: "sk-or-x" }));
    expect(provider?.name).toBe("openrouter");
    expect(provider?.url).toBe("https://openrouter.ai/api/v1/chat/completions");
    expect(provider?.apiKey).toBe("sk-or-x");
  });

  it("uses Groq when only its key is present", () => {
    const provider = resolveProvider(settings({ groqApiKey: "gsk-x" }));
    expect(provider?.name).toBe("groq");
    expect(provider?.url).toBe("https://api.groq.com/openai/v1/chat/completions");
    expect(provider?.model).toBe("llama-3.3-70b-versatile");
  });

  it("leaves the OpenRouter model empty so the account default applies", () => {
    // Shipping a hardcoded model id would break every install on the day that
    // id retires; an empty model is dropped from the request body instead.
    expect(resolveProvider(settings({ openrouterApiKey: "sk-or-x" }))?.model).toBe("");
  });

  it("passes a configured OpenRouter model through", () => {
    const provider = resolveProvider(
      settings({ openrouterApiKey: "sk-or-x", openrouterModel: "vendor/some-model" })
    );
    expect(provider?.model).toBe("vendor/some-model");
  });
});

describe("both keys set", () => {
  const both = settings({ openrouterApiKey: "sk-or-x", groqApiKey: "gsk-x" });

  it("prefers OpenRouter", () => {
    expect(resolveProvider(both)?.name).toBe("openrouter");
  });

  it("warns, because the operator probably did not mean to configure two", () => {
    const warnings = aiConfigWarnings(both);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/AI_PROVIDER=groq/);
  });

  it("honours an explicit choice of the non-default one", () => {
    expect(resolveProvider({ ...both, aiProvider: "groq" })?.name).toBe("groq");
    expect(aiConfigWarnings({ ...both, aiProvider: "groq" })).toEqual([]);
  });
});

describe("an explicit provider that cannot be honoured", () => {
  it("sends nothing anywhere rather than falling back to the other provider", () => {
    // The operator named OpenRouter. Quietly shipping their alert text to Groq
    // instead would disclose it to a party they did not choose.
    const s = settings({ aiProvider: "openrouter", groqApiKey: "gsk-x" });
    expect(resolveProvider(s)).toBeNull();
    expect(aiConfigWarnings(s)[0]).toMatch(/OPENROUTER_API_KEY is empty/);
  });

  it("does the same in the other direction", () => {
    const s = settings({ aiProvider: "groq", openrouterApiKey: "sk-or-x" });
    expect(resolveProvider(s)).toBeNull();
    expect(aiConfigWarnings(s)[0]).toMatch(/GROQ_API_KEY is empty/);
  });

  it("treats an unknown provider name as off, and says so", () => {
    const s = settings({ aiProvider: "openai", openrouterApiKey: "sk-or-x" });
    expect(resolveProvider(s)).toBeNull();
    expect(aiConfigWarnings(s)[0]).toMatch(/not a provider Legion knows/);
  });

  it("accepts the name with stray case or spacing", () => {
    const s = settings({ aiProvider: "  OpenRouter ", openrouterApiKey: "sk-or-x" });
    expect(resolveProvider(s)?.name).toBe("openrouter");
  });
});

describe("outbound request shape", () => {
  it("identifies Legion to OpenRouter without disclosing the customer's hostname", () => {
    // OpenRouter also accepts HTTP-Referer. Sending it would hand them the
    // internal address of the customer's console, which is not ours to give.
    const headers = resolveProvider(settings({ openrouterApiKey: "sk-or-x" }))!.extraHeaders;
    expect(headers["X-OpenRouter-Title"]).toBe("Legion");
    expect(headers).not.toHaveProperty("HTTP-Referer");
  });

  it("adds no extra headers for Groq", () => {
    expect(resolveProvider(settings({ groqApiKey: "gsk-x" }))!.extraHeaders).toEqual({});
  });
});
