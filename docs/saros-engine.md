# Saros engine

Fractonica's Saros engine is an offline-capable, read-only temporal and
eclipse-path service. It uses an actual adjacent pair of solar eclipses to
calculate a phase; it does not use the average Saros duration for a clock
reading.

## Deterministic inputs

Every calculation accepts an explicit signed Unix timestamp: integral seconds
plus a nanosecond fraction. It is a POSIX/Unix representation of the catalog's
UTC fields, so callers must not encode leap seconds as a `:60` value. A
timestamp at the end of an interval is outside that interval and is resolved
against the next known eclipse pair.

The clock returns both an exact rational phase and a 64-bit fixed-point phase
word. Consumers may ask for a bit prefix or complete MSB-first octal digits.

| Request | Meaning |
| --- | --- |
| 3 bits | one eighth of an eclipse interval |
| 30 bits | ten octal digits; the standard two five-digit pulse glyphs |
| 32 bits | ten octal digits plus two residual phase bits |
| 64 bits | full cached fixed-point phase word |

Rarity classification requires complete octal digits. It is distinct from the
raw high-resolution phase word.

## Reviewed geometry release

The initial geometry release is:

- asset: `assets/saros/geo/v1/reviewed-101-161.eclp`;
- manifest: `assets/saros/geo/v1/manifest.json`;
- included Saros series: 101 through 161 inclusive;
- scope: reviewed geometry only.

The manifest contains the immutable artifact hash, pinned reviewed-input hash,
source attribution, counts, coverage, and release boundary. This first
release uses the same bounded catalog for phase and geometry, so requests
outside 101–161 fail explicitly rather than extrapolating a clock or a path.

## HTTP profile and routes

The engine is available from the normal local node and from the stateless
profile:

```sh
cargo run -p fractonica-node -- --profile saros
```

The Saros profile opens no SQLite database and creates no data directory. It
is still loopback-only. Its read-only routes are:

| Route | Purpose |
| --- | --- |
| `GET /api/v1/saros` | Semantics version and immutable geometry-release manifest. |
| `GET /api/v1/saros/pulse?atUnixSeconds=…&anchorSaros=141` | Standard 30-bit pulse as two MSB-first five-digit glyphs. |
| `GET /api/v1/saros/series/{saros}/reading?atUnixSeconds=…&precisionBits=…` | Exact phase ratio, 64-bit word, and requested 1–64-bit prefix. |
| `GET /api/v1/saros/series/{saros}/eclipses/{sequence}/path` | Reviewed GeoJSON `MultiPolygon` path. |

All calculation routes require `atUnixSeconds`; the server does not sample its
own clock for them. Invalid query values return a `422` problem response.
Series or eclipse requests outside the reviewed release return a `404` problem
response. The checked-in [OpenAPI contract](../contracts/openapi/v1.yaml) is
the normative wire description.

## Rebuilding the release

The generator accepts only the exact reviewed 101–161 input snapshot pinned by
its source SHA-256 guard. It writes the same binary artifact and manifest when
given the same codec and input files:

```sh
node tools/saros-data/generate-reviewed-geometry.mjs \
  --input /path/to/saros-geo/data \
  --output assets/saros/geo/v1/reviewed-101-161.eclp \
  --manifest assets/saros/geo/v1/manifest.json \
  --imported-at 2026-07-17
```

Changing the reviewed source corpus is a new data-release decision: add a new
dataset ID and manifest rather than altering this v1 asset in place.

## Data provenance

The temporal source is the NASA GSFC solar-eclipse catalogue. Path geometry is
the manually normalized and reviewed compact `saros-geo` corpus. The first
Fractonica asset is a carefully identified import snapshot: it does not claim
to reproduce the historical interactive curation session. Future generator
revisions must retain the prior artifact and manifest hash, then publish a new
dataset ID rather than mutate an existing release.
