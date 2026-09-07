/**
 * Conformance against did-vectors/events.json — the interoperability contract
 * (DESIGN.md §2.3). Vendored copy in test/vectors/.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  serializeEvent,
  computeId,
  verifyEvent,
  signEvent,
  type NostrEvent,
} from "../src/index.js";

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL("./vectors/events.json", import.meta.url)), "utf8"),
);

const keyBySec = new Map<string, string>(); // pubkey -> sec
for (const k of Object.values(vectors.keys) as { sec: string; pub: string }[]) {
  keyBySec.set(k.pub, k.sec);
}

test("canonical serialisation edge cases", async (t) => {
  for (const c of vectors.serialization) {
    await t.test(c.name, () => {
      const preimage = serializeEvent(c.input);
      assert.equal(preimage, c.preimage, "preimage");
      assert.equal(
        Buffer.byteLength(preimage, "utf8"),
        c.preimage_utf8_bytes,
        "preimage byte count",
      );
      assert.equal(computeId(c.input), c.id, "id");
    });
  }
});

test("valid events verify", async (t) => {
  for (const c of vectors.valid_events) {
    await t.test(c.name, () => {
      const r = verifyEvent(c.event as NostrEvent);
      assert.ok(r.ok, `expected valid, got step ${r.step}: ${r.reason}`);
    });
  }
});

test("valid event signatures reproduce (aux_rand = 0)", async (t) => {
  for (const c of vectors.valid_events) {
    const ev = c.event as NostrEvent;
    const sec = keyBySec.get(ev.pubkey);
    if (!sec) continue; // key not in the table
    await t.test(c.name, () => {
      const re = signEvent(
        { created_at: ev.created_at, kind: ev.kind, tags: ev.tags, content: ev.content },
        sec,
      );
      assert.equal(re.id, ev.id, "id");
      assert.equal(re.sig, ev.sig, "sig");
    });
  }
});

test("invalid events are rejected at the stated step", async (t) => {
  for (const c of vectors.invalid_events) {
    await t.test(`${c.name} (fails_step ${c.fails_step}, rejected_by ${c.rejected_by})`, () => {
      const r = verifyEvent(c.event as NostrEvent);
      assert.equal(r.ok, false, "expected rejection");
      assert.equal(r.step, c.fails_step, `expected failure at step ${c.fails_step}, got ${r.step}`);
    });
  }
});
