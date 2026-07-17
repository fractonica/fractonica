# Eclipse data provenance

Fractonica distributes one reviewed solar-eclipse geometry release in this
repository: `assets/saros/geo/v1/reviewed-101-161.eclp`. Its adjacent manifest
contains the immutable artifact hash, source attribution, release scope and
coverage. The source temporal catalogue is NASA GSFC solar-eclipse data; the
geometry is a manually normalized and reviewed legacy `saros-geo` import.

The asset intentionally covers only Saros series 101 through 161. Phase and
geometry outside that range are unavailable in this first release, not
inferred. Historical Exeligmos binary assets are not copied into this
repository.

The checked-in manifest pins the exact reviewed source snapshot with
`sourceInputSha256`, `sourceFileCount`, and `sourceBytes`. Its `importedAt`
field records the Fractonica packaging date. The original legacy pipeline did
not retain an upstream retrieval date; that absence is documented explicitly
in `sourceRetrievalMetadata` rather than guessed.

The manifest's `sourceLicense` records the applicable NASA Eclipse Web Site
notice and the attribution to retain with derivatives. NASA's own notice says
that its material is not protected by copyright unless it is marked otherwise,
and asks users to credit the source. This does not authorize NASA names, logos,
or endorsement claims. See the [NASA Eclipse Web Site copyright
notice](https://eclipse.gsfc.nasa.gov/SEpubs/copyright.html).

Before a temporal dataset can ship in a node, desktop bundle, firmware image,
or SDK package, it must have a checked-in manifest containing:

- the upstream source, license or public-domain basis, and retrieval date (or
  an explicit statement that the historical retrieval date is unavailable);
- the generator source revision and exact input version;
- coverage interval, record count, and stable format version;
- SHA-256 hashes for source and generated files;
- validation results for ordering, index bounds, series membership, and
  conformance vectors.

Generated datasets are implementation artifacts, not a second semantic source
of truth. The `fractonica-temporal-core` contract determines how an approved
catalogue is interpreted. Geometry is never required by a clock-only helper
and must be packaged separately from timestamps and series indexes.

Small helpers should receive only the data they need. For example, a single
Saros series can be represented by a compact timestamp table, while a full
visualisation node may opt into richer metadata after provenance validation.
