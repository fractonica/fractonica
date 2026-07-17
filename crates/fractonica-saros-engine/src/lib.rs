//! Standalone Saros engine facade.
//!
//! This crate composes exact temporal arithmetic with the immutable reviewed
//! eclipse geometry release. Its public API is deliberately independent of
//! HTTP, SQLite, and the system clock.

#![forbid(unsafe_code)]

use std::{fmt::Write as _, mem};

use fractonica_saros_geo::{EclipseMetadata, GeoError, GeometryEvent, GeometryPoint, SingleFile};
use fractonica_temporal_core::{
    BitPrecision, ClockReading, EclipsePoint, Interval, PhaseBoundary, PhaseProjection, PhaseRatio,
    PhaseWord64, PulseAddress10, Rarity, TemporalError, Timestamp, classify_rarity, clock_reading,
    pulse_reading_10,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Version of the public Saros semantics implemented by this engine.
pub const SEMANTICS_VERSION: &str = "1.0.0";
/// Hard upper bound for an eagerly materialised path response.
pub const MAX_PATH_POINTS: u32 = 300_000;

const EMBEDDED_GEOMETRY: &[u8] =
    include_bytes!("../../../assets/saros/geo/v1/reviewed-101-161.eclp");
const EMBEDDED_MANIFEST: &str = include_str!("../../../assets/saros/geo/v1/manifest.json");
const REVIEWED_DATASET_ID: &str = "fractonica-solar-eclipse-geometry-reviewed-101-161-v1";
const REVIEWED_SOURCE_INPUT_SHA256: &str =
    "a68314cdcf6fe5ec67768af4db30bdc8d395b1416827af15f87463eeb73e8db2";
const REVIEWED_SOURCE_FILE_COUNT: u32 = 61;
const REVIEWED_SOURCE_BYTES: u64 = 2_056_880;
const REVIEWED_IMPORTED_AT: &str = "2026-07-17";
const REVIEWED_SOURCE_LICENSE_URL: &str = "https://eclipse.gsfc.nasa.gov/SEpubs/copyright.html";

#[derive(Debug, Error)]
pub enum SarosEngineError {
    #[error("embedded geometry manifest is invalid: {0}")]
    Manifest(#[from] serde_json::Error),

    #[error("embedded geometry asset is invalid: {0}")]
    Geometry(GeoError),

    #[error("temporal calculation failed: {0}")]
    Temporal(TemporalError),

    #[error("geometry manifest schema version {0} is unsupported")]
    UnsupportedManifestVersion(u32),

    #[error("geometry manifest does not describe the embedded artifact")]
    ManifestMismatch,

    #[error("Saros series {0} is intentionally outside the reviewed geometry release")]
    GeometryUnavailable(u16),

    #[error("Saros series {0} does not have a complete adjacent eclipse interval at this instant")]
    OutsideCoverage(u16),

    #[error("eclipse sequence {sequence} is absent from Saros {saros}")]
    EclipseUnavailable { saros: u16, sequence: u16 },

    #[error("Saros series {0} cannot be represented by the current temporal core")]
    UnsupportedSeries(u16),

    #[error("eclipse sequence {sequence} cannot be represented by the current temporal core")]
    UnsupportedSequence { sequence: u16 },

    #[error("path contains more than {MAX_PATH_POINTS} points")]
    PathTooLarge,

    #[error("next temporal flip could not be represented as a Unix timestamp")]
    TimestampOverflow,
}

impl From<GeoError> for SarosEngineError {
    fn from(value: GeoError) -> Self {
        Self::Geometry(value)
    }
}

impl From<TemporalError> for SarosEngineError {
    fn from(value: TemporalError) -> Self {
        Self::Temporal(value)
    }
}

/// Public immutable descriptor for the checked-in reviewed geometry release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeometryRelease {
    pub schema_version: u32,
    pub dataset_id: String,
    pub artifact: GeometryArtifact,
    pub source: GeometrySource,
    pub review: GeometryReview,
    pub coverage: GeometryCoverage,
    pub generated_by: GeometryGenerator,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeometryArtifact {
    pub file: String,
    pub bytes: usize,
    pub sha256: String,
    pub format: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeometrySource {
    pub catalog: String,
    pub catalog_url: String,
    pub geometry_pipeline: String,
    pub import_input: String,
    pub source_input_sha256: String,
    pub source_file_count: u32,
    pub source_bytes: u64,
    pub imported_at: String,
    pub source_retrieval_metadata: String,
    pub source_license: GeometrySourceLicense,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeometrySourceLicense {
    pub status: String,
    pub notice_url: String,
    pub attribution: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeometryReview {
    pub status: String,
    pub included_series: SeriesRange,
    pub excluded_series: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SeriesRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeometryCoverage {
    pub eclipse_count: u32,
    pub path_point_count: u32,
    pub first_unix_seconds: i64,
    pub last_unix_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeometryGenerator {
    pub script: String,
    pub generator_version: u32,
}

/// Stable identity of an eclipse in the reviewed geometry release.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EclipseIdentity {
    pub saros: u16,
    pub sequence: u16,
    pub unix_seconds: i64,
}

/// Catalog-backed exact temporal reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SarosReading {
    pub saros: u16,
    pub at: Timestamp,
    pub previous: EclipseIdentity,
    pub next: EclipseIdentity,
    pub clock: ClockReading,
    pub next_flip_at: Timestamp,
}

impl SarosReading {
    #[must_use]
    pub const fn phase(self) -> PhaseRatio {
        self.clock.phase
    }

    #[must_use]
    pub const fn word(self) -> PhaseWord64 {
        self.clock.word
    }

    #[must_use]
    pub const fn projection(self) -> PhaseProjection {
        self.clock.projection
    }

    /// Classifies the complete-octal portion of the requested phase view.
    pub fn rarity(self) -> Result<Rarity, TemporalError> {
        let address =
            fractonica_temporal_core::OctalAddress::from_projection(self.clock.projection)?;
        Ok(classify_rarity(address))
    }
}

/// The standard two-glyph realtime pulse resolved against one anchor series.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SarosPulse {
    pub anchor_saros: u16,
    pub reading: SarosReading,
    pub glyphs: PulseAddress10,
}

/// Eagerly materialised geometry for one reviewed eclipse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EclipsePath {
    pub identity: EclipseIdentity,
    pub metadata: EclipseMetadata,
    pub polygons: Vec<Vec<GeometryPoint>>,
}

/// An immutable engine backed by the checked-in geometry release.
#[derive(Debug)]
pub struct SarosEngine {
    geometry: SingleFile<'static>,
    release: GeometryRelease,
}

impl SarosEngine {
    /// Loads and deep-validates Fractonica's reviewed Saros 101–161 release.
    pub fn embedded_reviewed() -> Result<Self, SarosEngineError> {
        let release = serde_json::from_str::<GeometryRelease>(EMBEDDED_MANIFEST)?;
        validate_release_manifest(&release, EMBEDDED_GEOMETRY)?;
        let geometry = SingleFile::open(EMBEDDED_GEOMETRY)?;
        geometry.validate()?;
        validate_coverage(&geometry, &release)?;
        Ok(Self { geometry, release })
    }

    #[must_use]
    pub const fn semantics_version(&self) -> &'static str {
        SEMANTICS_VERSION
    }

    #[must_use]
    pub fn geometry_release(&self) -> &GeometryRelease {
        &self.release
    }

    #[must_use]
    pub fn geometry_available(&self, saros: u16) -> bool {
        (self.release.review.included_series.start..=self.release.review.included_series.end)
            .contains(&saros)
    }

    pub fn eclipse(
        &self,
        saros: u16,
        sequence: u16,
    ) -> Result<(EclipseIdentity, EclipseMetadata), SarosEngineError> {
        let section = self.section(saros)?;
        let record = section.record(sequence).map_err(|error| match error {
            GeoError::RecordOutOfRange => SarosEngineError::EclipseUnavailable { saros, sequence },
            other => SarosEngineError::Geometry(other),
        })?;
        let metadata = record.metadata()?;
        Ok((
            EclipseIdentity {
                saros,
                sequence,
                unix_seconds: metadata.unix_seconds,
            },
            metadata,
        ))
    }

    pub fn reading_at(
        &self,
        saros: u16,
        at: Timestamp,
        precision: BitPrecision,
    ) -> Result<SarosReading, SarosEngineError> {
        let section = self.section(saros)?;
        if section.record_count() < 2 {
            return Err(SarosEngineError::OutsideCoverage(saros));
        }

        let first = section.record(0)?.metadata()?;
        let last_index = section.record_count() - 1;
        let last = section.record(last_index)?.metadata()?;
        if at < Timestamp::from_epoch_seconds(first.unix_seconds)
            || at >= Timestamp::from_epoch_seconds(last.unix_seconds)
        {
            return Err(SarosEngineError::OutsideCoverage(saros));
        }

        let mut low = 1_u16;
        let mut high = last_index;
        while low < high {
            let middle = low + (high - low) / 2;
            let metadata = section.record(middle)?.metadata()?;
            if metadata.unix_seconds <= at.epoch_seconds() {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let previous_sequence = low - 1;
        let previous = section.record(previous_sequence)?.metadata()?;
        let next = section.record(low)?.metadata()?;
        let interval = interval_from_metadata(saros, previous_sequence, previous, low, next)?;
        let clock = clock_reading(interval, at, precision)?;
        let next_flip_at = timestamp_at_boundary(interval, clock.next_flip)?;

        Ok(SarosReading {
            saros,
            at,
            previous: EclipseIdentity {
                saros,
                sequence: previous_sequence,
                unix_seconds: previous.unix_seconds,
            },
            next: EclipseIdentity {
                saros,
                sequence: low,
                unix_seconds: next.unix_seconds,
            },
            clock,
            next_flip_at,
        })
    }

    pub fn pulse_at(
        &self,
        anchor_saros: u16,
        at: Timestamp,
    ) -> Result<SarosPulse, SarosEngineError> {
        let reading = self.reading_at(
            anchor_saros,
            at,
            BitPrecision::new(fractonica_temporal_core::REALTIME_PULSE_BITS)?,
        )?;
        let interval = interval_from_identities(reading.previous, reading.next)?;
        let pulse = pulse_reading_10(interval, at)?;
        Ok(SarosPulse {
            anchor_saros,
            reading,
            glyphs: pulse.glyphs,
        })
    }

    pub fn path(&self, saros: u16, sequence: u16) -> Result<EclipsePath, SarosEngineError> {
        let section = self.section(saros)?;
        let record = section.record(sequence).map_err(|error| match error {
            GeoError::RecordOutOfRange => SarosEngineError::EclipseUnavailable { saros, sequence },
            other => SarosEngineError::Geometry(other),
        })?;
        let mut polygons = Vec::<Vec<GeometryPoint>>::new();
        let mut current = Vec::<GeometryPoint>::new();
        let metadata = record.visit_geometry(&mut |event| match event {
            GeometryEvent::BeginPolygon { point_count } => {
                current = Vec::with_capacity(usize::from(point_count));
            }
            GeometryEvent::Point(point) => current.push(point),
            GeometryEvent::EndPolygon => polygons.push(mem::take(&mut current)),
        })?;
        if metadata.path_point_count > MAX_PATH_POINTS {
            return Err(SarosEngineError::PathTooLarge);
        }
        Ok(EclipsePath {
            identity: EclipseIdentity {
                saros,
                sequence,
                unix_seconds: metadata.unix_seconds,
            },
            metadata,
            polygons,
        })
    }

    fn section(
        &self,
        saros: u16,
    ) -> Result<fractonica_saros_geo::Section<'static>, SarosEngineError> {
        if !self.geometry_available(saros) {
            return Err(SarosEngineError::GeometryUnavailable(saros));
        }
        self.geometry.section(saros).map_err(|error| match error {
            GeoError::SeriesNotFound => SarosEngineError::GeometryUnavailable(saros),
            other => SarosEngineError::Geometry(other),
        })
    }
}

fn validate_release_manifest(
    release: &GeometryRelease,
    bytes: &[u8],
) -> Result<(), SarosEngineError> {
    if release.schema_version != 1
        || release.dataset_id != REVIEWED_DATASET_ID
        || release.artifact.file != "reviewed-101-161.eclp"
        || release.artifact.format != "saros-geo-eclp-v1"
        || release.artifact.bytes != bytes.len()
        || release.review.status != "reviewed"
        || release.review.included_series
            != (SeriesRange {
                start: 101,
                end: 161,
            })
        || release.source.source_input_sha256 != REVIEWED_SOURCE_INPUT_SHA256
        || release.source.source_file_count != REVIEWED_SOURCE_FILE_COUNT
        || release.source.source_bytes != REVIEWED_SOURCE_BYTES
        || release.source.imported_at != REVIEWED_IMPORTED_AT
        || release.source.source_license.notice_url != REVIEWED_SOURCE_LICENSE_URL
        || release.source.source_license.status.is_empty()
        || release.source.source_license.attribution.is_empty()
    {
        return Err(SarosEngineError::ManifestMismatch);
    }
    let hash = sha256_hex(bytes);
    if hash != release.artifact.sha256 {
        return Err(SarosEngineError::ManifestMismatch);
    }
    Ok(())
}

fn validate_coverage(
    geometry: &SingleFile<'_>,
    release: &GeometryRelease,
) -> Result<(), SarosEngineError> {
    let mut eclipse_count = 0_u32;
    let mut point_count = 0_u32;
    let mut first = None;
    let mut last = None;
    for saros in release.review.included_series.start..=release.review.included_series.end {
        let section = geometry.section(saros)?;
        for sequence in 0..section.record_count() {
            let metadata = section.record(sequence)?.metadata()?;
            eclipse_count = eclipse_count
                .checked_add(1)
                .ok_or(SarosEngineError::ManifestMismatch)?;
            point_count = point_count
                .checked_add(metadata.path_point_count)
                .ok_or(SarosEngineError::ManifestMismatch)?;
            first = Some(first.map_or(metadata.unix_seconds, |value: i64| {
                value.min(metadata.unix_seconds)
            }));
            last = Some(last.map_or(metadata.unix_seconds, |value: i64| {
                value.max(metadata.unix_seconds)
            }));
        }
    }
    if eclipse_count != release.coverage.eclipse_count
        || point_count != release.coverage.path_point_count
        || first != Some(release.coverage.first_unix_seconds)
        || last != Some(release.coverage.last_unix_seconds)
    {
        return Err(SarosEngineError::ManifestMismatch);
    }
    Ok(())
}

fn interval_from_metadata(
    saros: u16,
    previous_sequence: u16,
    previous: EclipseMetadata,
    next_sequence: u16,
    next: EclipseMetadata,
) -> Result<Interval, SarosEngineError> {
    let saros_u8 = u8::try_from(saros).map_err(|_| SarosEngineError::UnsupportedSeries(saros))?;
    let previous_sequence_u8 =
        u8::try_from(previous_sequence).map_err(|_| SarosEngineError::UnsupportedSequence {
            sequence: previous_sequence,
        })?;
    let next_sequence_u8 =
        u8::try_from(next_sequence).map_err(|_| SarosEngineError::UnsupportedSequence {
            sequence: next_sequence,
        })?;
    Ok(Interval {
        saros: saros_u8,
        previous: EclipsePoint {
            index: previous_sequence,
            epoch_seconds: previous.unix_seconds,
            saros: saros_u8,
            sequence: previous_sequence_u8,
            type_code: previous.type_index,
        },
        next: EclipsePoint {
            index: next_sequence,
            epoch_seconds: next.unix_seconds,
            saros: saros_u8,
            sequence: next_sequence_u8,
            type_code: next.type_index,
        },
    })
}

fn interval_from_identities(
    previous: EclipseIdentity,
    next: EclipseIdentity,
) -> Result<Interval, SarosEngineError> {
    let saros = u8::try_from(previous.saros)
        .map_err(|_| SarosEngineError::UnsupportedSeries(previous.saros))?;
    let previous_sequence =
        u8::try_from(previous.sequence).map_err(|_| SarosEngineError::UnsupportedSequence {
            sequence: previous.sequence,
        })?;
    let next_sequence =
        u8::try_from(next.sequence).map_err(|_| SarosEngineError::UnsupportedSequence {
            sequence: next.sequence,
        })?;
    Ok(Interval {
        saros,
        previous: EclipsePoint {
            index: previous.sequence,
            epoch_seconds: previous.unix_seconds,
            saros,
            sequence: previous_sequence,
            type_code: 0,
        },
        next: EclipsePoint {
            index: next.sequence,
            epoch_seconds: next.unix_seconds,
            saros,
            sequence: next_sequence,
            type_code: 0,
        },
    })
}

fn timestamp_at_boundary(
    interval: Interval,
    boundary: PhaseBoundary,
) -> Result<Timestamp, SarosEngineError> {
    interval.validate()?;
    let duration_seconds =
        i128::from(interval.next.epoch_seconds) - i128::from(interval.previous.epoch_seconds);
    let duration_nanoseconds = u128::try_from(duration_seconds)
        .map_err(|_| SarosEngineError::TimestampOverflow)?
        .checked_mul(u128::from(fractonica_temporal_core::NANOSECONDS_PER_SECOND))
        .ok_or(SarosEngineError::TimestampOverflow)?;
    let numerator = duration_nanoseconds
        .checked_mul(boundary.numerator())
        .ok_or(SarosEngineError::TimestampOverflow)?;
    let denominator = boundary.denominator();
    let offset_nanoseconds = numerator
        .checked_add(denominator - 1)
        .ok_or(SarosEngineError::TimestampOverflow)?
        / denominator;
    let seconds_offset =
        offset_nanoseconds / u128::from(fractonica_temporal_core::NANOSECONDS_PER_SECOND);
    let nanosecond = u32::try_from(
        offset_nanoseconds % u128::from(fractonica_temporal_core::NANOSECONDS_PER_SECOND),
    )
    .map_err(|_| SarosEngineError::TimestampOverflow)?;
    let seconds_offset =
        i64::try_from(seconds_offset).map_err(|_| SarosEngineError::TimestampOverflow)?;
    let epoch_seconds = interval
        .previous
        .epoch_seconds
        .checked_add(seconds_offset)
        .ok_or(SarosEngineError::TimestampOverflow)?;
    Ok(Timestamp::new(epoch_seconds, nanosecond)?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_the_reviewed_release_and_validates_its_manifest() {
        let engine = SarosEngine::embedded_reviewed().expect("engine");
        assert_eq!(engine.semantics_version(), SEMANTICS_VERSION);
        assert_eq!(engine.geometry_release().coverage.eclipse_count, 2044);
        assert!(engine.geometry_available(141));
        assert!(!engine.geometry_available(162));
    }

    #[test]
    fn resolves_an_exact_anchor_pulse() {
        let engine = SarosEngine::embedded_reviewed().expect("engine");
        let at = Timestamp::from_epoch_seconds(-11_253_795_384);
        let pulse = engine.pulse_at(141, at).expect("pulse");
        assert_eq!(pulse.reading.previous.sequence, 0);
        assert_eq!(pulse.reading.next.sequence, 1);
        assert_eq!(pulse.glyphs.most_significant, [0; 5]);
    }

    #[test]
    fn materialises_a_reviewed_path() {
        let engine = SarosEngine::embedded_reviewed().expect("engine");
        let path = engine.path(141, 0).expect("path");
        assert_eq!(path.identity.saros, 141);
        assert!(path.metadata.path_point_count > 2);
        assert!(!path.polygons.is_empty());
    }

    #[test]
    fn reports_geometry_outside_the_reviewed_boundary() {
        let engine = SarosEngine::embedded_reviewed().expect("engine");
        assert!(matches!(
            engine.path(162, 0),
            Err(SarosEngineError::GeometryUnavailable(162))
        ));
    }
}
