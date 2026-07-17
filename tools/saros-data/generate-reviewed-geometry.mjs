#!/usr/bin/env node
/**
 * Build Fractonica's reviewed solar-eclipse geometry asset from the compact
 * saros-geo v1 split files.
 *
 * The input corpus is deliberately external to this repository while it is
 * being curated. The generated ECLP container and manifest are checked in so
 * releases are self-contained and verifiable.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const SERIES_START = 101;
const SERIES_END = 161;
const EXPECTED_SERIES = SERIES_END - SERIES_START + 1;
const EXPECTED_ECLIPSES = 2044;
const EXPECTED_PATH_POINTS = 276576;
const EXPECTED_INPUT_SHA256 = 'a68314cdcf6fe5ec67768af4db30bdc8d395b1416827af15f87463eeb73e8db2';

function usage() {
  return [
    'Usage:',
    '  node tools/saros-data/generate-reviewed-geometry.mjs \\\n    --input /path/to/saros-geo/data \\\n    --output assets/saros/geo/v1/reviewed-101-161.eclp \\\n    --manifest assets/saros/geo/v1/manifest.json \\\n    --imported-at 2026-07-17',
  ].join('\n');
}

function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === '--help' || flag === '-h') {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    }
    if (!flag.startsWith('--')) throw new Error(`Unexpected argument: ${flag}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${flag}`);
    values.set(flag.slice(2), value);
    index += 1;
  }
  for (const required of ['input', 'output', 'manifest', 'imported-at']) {
    if (!values.has(required)) throw new Error(`Missing --${required}\n\n${usage()}`);
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(values.get('imported-at'))) {
    throw new Error('--imported-at must use YYYY-MM-DD');
  }
  return Object.fromEntries(values);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function unixFromUtc(value) {
  const parsed = Date.parse(value.replace(' ', 'T') + 'Z');
  if (!Number.isSafeInteger(parsed)) throw new Error(`Invalid UTC timestamp: ${value}`);
  return Math.floor(parsed / 1000);
}

function countPoints(records) {
  return records.reduce(
    (total, record) =>
      total + record.geometry.coordinates.reduce((sum, polygon) => sum + polygon[0].length, 0),
    0,
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const input = path.resolve(args.input);
  const output = path.resolve(args.output);
  const manifestPath = path.resolve(args.manifest);
  const codecPath = path.join(path.dirname(input), 'saros_geo.js');
  const { decodeSeries, decodeSingle, encodeSingle } = await import(pathToFileURL(codecPath).href);

  const series = {};
  let eclipses = 0;
  let pathPoints = 0;
  let firstUnixSeconds = null;
  let lastUnixSeconds = null;
  let inputBytes = 0;
  const inputHasher = createHash('sha256');
  inputHasher.update('fractonica-reviewed-saros-geo-input-v1\0');

  for (let saros = SERIES_START; saros <= SERIES_END; saros += 1) {
    const file = path.join(input, `${saros}.bin`);
    const bytes = fs.readFileSync(file);
    inputHasher.update(String(saros));
    inputHasher.update('.bin\0');
    inputHasher.update(bytes);
    inputBytes += bytes.length;
    const records = decodeSeries(bytes);
    const entries = records.map((record) => [unixFromUtc(record.datetime_utc), record]);
    if (entries.length === 0) throw new Error(`Series ${saros} has no eclipses`);
    for (const [unixSeconds] of entries) {
      firstUnixSeconds = firstUnixSeconds === null ? unixSeconds : Math.min(firstUnixSeconds, unixSeconds);
      lastUnixSeconds = lastUnixSeconds === null ? unixSeconds : Math.max(lastUnixSeconds, unixSeconds);
    }
    eclipses += entries.length;
    pathPoints += countPoints(records);
    series[saros] = entries;
  }

  if (Object.keys(series).length !== EXPECTED_SERIES || eclipses !== EXPECTED_ECLIPSES || pathPoints !== EXPECTED_PATH_POINTS) {
    throw new Error(
      `Unexpected reviewed corpus: series=${Object.keys(series).length}, eclipses=${eclipses}, points=${pathPoints}`,
    );
  }

  const inputSha256 = inputHasher.digest('hex');
  if (inputSha256 !== EXPECTED_INPUT_SHA256) {
    throw new Error(
      'Unexpected reviewed input digest: expected '
        + EXPECTED_INPUT_SHA256
        + ', got '
        + inputSha256,
    );
  }

  const encoded = Buffer.from(encodeSingle(series));
  const decoded = decodeSingle(encoded);
  if (Object.keys(decoded).length !== EXPECTED_SERIES) {
    throw new Error('Generated container failed its round-trip verification');
  }

  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  fs.writeFileSync(output, encoded);

  const manifest = {
    schemaVersion: 1,
    datasetId: 'fractonica-solar-eclipse-geometry-reviewed-101-161-v1',
    artifact: {
      file: path.basename(output),
      bytes: encoded.length,
      sha256: sha256(encoded),
      format: 'saros-geo-eclp-v1',
    },
    source: {
      catalog: 'NASA GSFC solar eclipse catalog',
      catalogUrl: 'https://eclipse.gsfc.nasa.gov/SEcat5/SEcatalog.html?level=1',
      geometryPipeline: 'Legacy saros-geo manual normalization and review workflow',
      importInput: path.basename(path.dirname(input)),
      sourceInputSha256: inputSha256,
      sourceFileCount: EXPECTED_SERIES,
      sourceBytes: inputBytes,
      importedAt: args['imported-at'],
      sourceRetrievalMetadata: 'Original upstream retrieval date was not retained; the pinned input digest identifies this reviewed import snapshot.',
      sourceLicense: {
        status: 'NASA Eclipse Web Site copyright notice: NASA material is not protected by copyright unless noted.',
        noticeUrl: 'https://eclipse.gsfc.nasa.gov/SEpubs/copyright.html',
        attribution: 'Derived from NASA/Goddard Space Flight Center eclipse material attributed to Fred Espenak (eclipse.gsfc.nasa.gov).',
      },
    },
    review: {
      status: 'reviewed',
      includedSeries: { start: SERIES_START, end: SERIES_END },
      excludedSeries: 'All series outside 101-161 are intentionally absent from this geometry release.',
    },
    coverage: {
      eclipseCount: eclipses,
      pathPointCount: pathPoints,
      firstUnixSeconds,
      lastUnixSeconds,
    },
    generatedBy: {
      script: 'tools/saros-data/generate-reviewed-geometry.mjs',
      generatorVersion: 1,
    },
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(`${manifest.artifact.sha256}  ${output}\n`);
}

main().catch((error) => {
  process.stderr.write(`error: ${error.message}\n`);
  process.exitCode = 1;
});
