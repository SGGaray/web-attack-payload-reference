import { describe, it, expect } from "vitest";
import { NextRequest } from "next/server";
import { POST } from "./route";

function makeRequest(body: unknown) {
  return new NextRequest("http://localhost/api/hash", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

describe("POST /api/hash", () => {
  it("rejects a non-string text field", async () => {
    const res = await POST(makeRequest({ text: 12345 }));
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toMatch(/must be a string/i);
  });

  it("rejects when no requested algorithm is in the allowed set", async () => {
    const res = await POST(
      makeRequest({ text: "hello", algorithms: ["md6", "sha512"] })
    );
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toMatch(/No valid algorithms/i);
  });

  it("rejects text over the maximum length", async () => {
    const res = await POST(makeRequest({ text: "a".repeat(100_001) }));
    expect(res.status).toBe(413);
  });
});
