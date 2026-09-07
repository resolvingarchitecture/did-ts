/**
 * Conformance against did-vectors/rotation.json — the guardian rotation
 * acceptance rule (DESIGN.md §4.3). Vendored copy in test/vectors/.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { verifyEvent, evaluateRotation, type NostrEvent } from "../src/index.js";

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL("./vectors/rotation.json", import.meta.url)), "utf8"),
);

const cooldownSeconds: number = vectors.cooldown_seconds;

test("every event in every rotation case is a well-formed Nostr event", async (t) => {
  for (const c of vectors.cases) {
    await t.test(c.name, () => {
      for (const ev of c.events as NostrEvent[]) {
        const r = verifyEvent(ev);
        assert.ok(r.ok, `event ${ev.id} failed at step ${r.step}: ${r.reason}`);
      }
    });
  }
});

test("acceptance rule reaches the stated verdict", async (t) => {
  for (const c of vectors.cases) {
    await t.test(`${c.name} -> ${c.accept ? "accept" : "reject"}`, () => {
      const verdict = evaluateRotation(c.events as NostrEvent[], { cooldownSeconds });
      assert.equal(verdict.accepted, c.accept, verdict.reason);
      if (c.accept) {
        assert.ok(verdict.new, "an accepted rotation names a successor key");
        assert.ok(verdict.old, "an accepted rotation names the old key");
      }
    });
  }
});
