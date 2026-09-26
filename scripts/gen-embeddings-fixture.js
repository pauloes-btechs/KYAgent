#!/usr/bin/env node
// Regenerates fixtures/embeddings.json (EMBEDDINGS_MODE=fixture). Deterministic: running it twice
// produces byte-identical output. Method: src/memory/fixtureVectors.js.
import { writeFileSync } from 'node:fs';
import { signalsText, textSha256 } from '../src/memory/signalsText.js';
import { FIXTURE_MODEL, FIXTURE_SEED, WEIGHTS, allSignalSets, fixtureVector, roundVector } from '../src/memory/fixtureVectors.js';
import { DEFAULT_FIXTURE_PATH, EMBEDDING_DIMENSIONS } from '../src/memory/embeddings.js';

export function buildFixture(dims = EMBEDDING_DIMENSIONS) {
  const vectors = {};
  for (const signals of allSignalSets()) {
    const text = signalsText(signals);
    vectors[textSha256(text)] = { signals: [...signals].sort(), text, embedding: roundVector(fixtureVector(signals, dims)) };
  }
  const sorted = Object.fromEntries(Object.keys(vectors).sort().map((k) => [k, vectors[k]]));
  return {
    model: FIXTURE_MODEL,
    dimensions: dims,
    similarity: 'cosine',
    method:
      'Synthetic, deterministic; NOT Voyage output. One sha256-seeded axis per signal (+NO_SIGNALS), ' +
      'Gram-Schmidt orthonormalised; embedding = normalise(sum of weighted axes of the signal set), ' +
      'empty set = NO_SIGNALS axis; components rounded to 1e-7. Keys = sha256(signalsText). ' +
      'Covers all 64 subsets of the closed signal set. See src/memory/fixtureVectors.js.',
    seed: FIXTURE_SEED,
    weights: WEIGHTS,
    generator: 'scripts/gen-embeddings-fixture.js',
    vectors: sorted,
  };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('gen-embeddings-fixture.js')) {
  const doc = buildFixture();
  writeFileSync(DEFAULT_FIXTURE_PATH, `${JSON.stringify(doc)}\n`);
  console.log(`wrote ${Object.keys(doc.vectors).length} vectors (${doc.dimensions}-d, ${doc.model})`);
}
