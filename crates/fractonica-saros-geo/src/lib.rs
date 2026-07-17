#![no_std]
//! Bounded, allocation-free access to Fractonica's compact solar-eclipse
//! geometry assets.
//!
//! The reader intentionally borrows its backing bytes. Nodes can memory-map or
//! retain an immutable release asset, while embedded devices can point it at
//! flash/PROGMEM-backed storage through their platform adapter.

use core::fmt;

const MAGIC: &[u8; 4] = b"ECLP";
const VERSION: u8 = 1;
const DIRECTORY_ENTRY_BYTES: usize = 8;
const RECORD_TYPE_BITS: u8 = 5;
const RECORD_UNIX_BITS: u8 = 35;
const RECORD_SUN_ALTITUDE_BITS: u8 = 7;
const RECORD_MAGNITUDE_BITS: u8 = 14;
const RECORD_GAMMA_BITS: u8 = 15;
const RECORD_DURATION_BITS: u8 = 10;
const RECORD_WIDTH_BITS: u8 = 11;
const RECORD_POLYGON_COUNT_BITS: u8 = 5;
const RECORD_POINT_COUNT_BITS: u8 = 13;
const COORDINATE_SCALE: i32 = 1_000_000;

/// An error returned for malformed, unsupported, or out-of-range geometry
/// data. Errors contain no heap-allocated diagnostic so the reader can stay
/// suitable for constrained targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeoError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u8),
    EmptyDirectory,
    InvalidDirectory,
    SeriesNotFound,
    RecordOutOfRange,
    InvalidRecordOffsets,
    InvalidField,
    InvalidCoordinate,
    ArithmeticOverflow,
}

impl fmt::Display for GeoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Truncated => "geometry asset is truncated",
            Self::InvalidMagic => "geometry asset has an invalid magic value",
            Self::UnsupportedVersion(_) => "geometry asset version is unsupported",
            Self::EmptyDirectory => "geometry asset has no Saros sections",
            Self::InvalidDirectory => "geometry asset directory is invalid",
            Self::SeriesNotFound => "Saros series is not present in geometry asset",
            Self::RecordOutOfRange => "eclipse record is not present in geometry asset",
            Self::InvalidRecordOffsets => "eclipse record offsets are invalid",
            Self::InvalidField => "eclipse record contains an invalid field",
            Self::InvalidCoordinate => "eclipse path contains an invalid coordinate",
            Self::ArithmeticOverflow => "geometry asset calculation overflowed",
        };
        formatter.write_str(message)
    }
}

/// Quantised geographic coordinate in microdegrees.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeometryPoint {
    pub longitude_e6: i32,
    pub latitude_e6: i32,
}

/// Compact metadata associated with one eclipse path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EclipseMetadata {
    pub type_index: u8,
    pub unix_seconds: i64,
    pub latitude_e6: i32,
    pub longitude_e6: i32,
    pub sun_altitude_degrees: u8,
    pub magnitude_e4: u16,
    pub gamma_e4: i16,
    pub central_duration_seconds: Option<u16>,
    pub central_width_km: Option<u16>,
    pub polygon_count: u8,
    pub path_point_count: u32,
}

/// Streaming geometry event. A polygon always contains one ring in the v1
/// asset, so callers receive a begin marker, exactly `point_count` points, and
/// an end marker for every polygon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeometryEvent {
    BeginPolygon { point_count: u16 },
    Point(GeometryPoint),
    EndPolygon,
}

/// Validated, borrowed `ECLP` v1 single-file geometry asset.
#[derive(Clone, Copy, Debug)]
pub struct SingleFile<'a> {
    bytes: &'a [u8],
    directory_start: usize,
    section_count: u16,
    payload_start: usize,
}

impl<'a> SingleFile<'a> {
    /// Opens the lightweight container header and validates its directory.
    /// Call [`Self::validate`] once at startup to deep-validate every record.
    pub fn open(bytes: &'a [u8]) -> Result<Self, GeoError> {
        if bytes.len() < 8 {
            return Err(GeoError::Truncated);
        }
        if &bytes[..4] != MAGIC {
            return Err(GeoError::InvalidMagic);
        }
        if bytes[4] != VERSION {
            return Err(GeoError::UnsupportedVersion(bytes[4]));
        }

        let section_count = read_u16_le(bytes, 6)?;
        if section_count == 0 {
            return Err(GeoError::EmptyDirectory);
        }
        let directory_bytes = usize::from(section_count)
            .checked_mul(DIRECTORY_ENTRY_BYTES)
            .ok_or(GeoError::ArithmeticOverflow)?;
        let payload_start = 8_usize
            .checked_add(directory_bytes)
            .ok_or(GeoError::ArithmeticOverflow)?;
        if payload_start > bytes.len() {
            return Err(GeoError::Truncated);
        }

        let file = Self {
            bytes,
            directory_start: 8,
            section_count,
            payload_start,
        };
        file.validate_directory()?;
        Ok(file)
    }

    #[must_use]
    pub const fn section_count(self) -> u16 {
        self.section_count
    }

    /// Returns a section in O(log N) time.
    pub fn section(self, saros: u16) -> Result<Section<'a>, GeoError> {
        let mut low = 0_u16;
        let mut high = self.section_count;
        while low < high {
            let middle = low + (high - low) / 2;
            let entry = self.directory_entry(middle)?;
            if entry.saros < saros {
                low = middle + 1;
            } else {
                high = middle;
            }
        }

        if low == self.section_count {
            return Err(GeoError::SeriesNotFound);
        }
        let entry = self.directory_entry(low)?;
        if entry.saros != saros {
            return Err(GeoError::SeriesNotFound);
        }
        self.section_at(low, entry)
    }

    /// Deep-validates every section and record. Intended for a node's startup
    /// integrity gate, not the hot path.
    pub fn validate(self) -> Result<(), GeoError> {
        for index in 0..self.section_count {
            let section = self.section_at(index, self.directory_entry(index)?)?;
            section.validate()?;
        }
        Ok(())
    }

    fn validate_directory(self) -> Result<(), GeoError> {
        let payload_len = self.bytes.len() - self.payload_start;
        let mut previous_saros = None;
        let mut previous_offset = None;
        for index in 0..self.section_count {
            let entry = self.directory_entry(index)?;
            if entry.record_count == 0 || entry.bit_offset % 8 != 0 {
                return Err(GeoError::InvalidDirectory);
            }
            if let Some(previous) = previous_saros
                && entry.saros <= previous
            {
                return Err(GeoError::InvalidDirectory);
            }
            if let Some(previous) = previous_offset
                && entry.bit_offset <= previous
            {
                return Err(GeoError::InvalidDirectory);
            }
            let byte_offset =
                usize::try_from(entry.bit_offset / 8).map_err(|_| GeoError::ArithmeticOverflow)?;
            if byte_offset >= payload_len {
                return Err(GeoError::InvalidDirectory);
            }
            previous_saros = Some(entry.saros);
            previous_offset = Some(entry.bit_offset);
        }
        Ok(())
    }

    fn directory_entry(self, index: u16) -> Result<DirectoryEntry, GeoError> {
        if index >= self.section_count {
            return Err(GeoError::InvalidDirectory);
        }
        let offset = self
            .directory_start
            .checked_add(usize::from(index) * DIRECTORY_ENTRY_BYTES)
            .ok_or(GeoError::ArithmeticOverflow)?;
        Ok(DirectoryEntry {
            saros: read_u16_le(self.bytes, offset)?,
            record_count: read_u16_le(self.bytes, offset + 2)?,
            bit_offset: read_u32_le(self.bytes, offset + 4)?,
        })
    }

    fn section_at(self, index: u16, entry: DirectoryEntry) -> Result<Section<'a>, GeoError> {
        let start = self
            .payload_start
            .checked_add(
                usize::try_from(entry.bit_offset / 8).map_err(|_| GeoError::ArithmeticOverflow)?,
            )
            .ok_or(GeoError::ArithmeticOverflow)?;
        let end = if index + 1 < self.section_count {
            let next = self.directory_entry(index + 1)?;
            self.payload_start
                .checked_add(
                    usize::try_from(next.bit_offset / 8)
                        .map_err(|_| GeoError::ArithmeticOverflow)?,
                )
                .ok_or(GeoError::ArithmeticOverflow)?
        } else {
            self.bytes.len()
        };
        if start >= end || end > self.bytes.len() {
            return Err(GeoError::InvalidDirectory);
        }
        Section::open(entry.saros, entry.record_count, &self.bytes[start..end])
    }
}

#[derive(Clone, Copy, Debug)]
struct DirectoryEntry {
    saros: u16,
    record_count: u16,
    bit_offset: u32,
}

/// Borrowed view of a single Saros-series section.
#[derive(Clone, Copy, Debug)]
pub struct Section<'a> {
    saros: u16,
    record_count: u16,
    offsets_bytes: &'a [u8],
    data: &'a [u8],
}

impl<'a> Section<'a> {
    fn open(saros: u16, record_count: u16, bytes: &'a [u8]) -> Result<Self, GeoError> {
        let offset_bytes = (usize::from(record_count) + 1)
            .checked_mul(4)
            .ok_or(GeoError::ArithmeticOverflow)?;
        if bytes.len() <= offset_bytes {
            return Err(GeoError::Truncated);
        }
        let section = Self {
            saros,
            record_count,
            offsets_bytes: &bytes[..offset_bytes],
            data: &bytes[offset_bytes..],
        };
        section.validate_offsets()?;
        Ok(section)
    }

    #[must_use]
    pub const fn saros(self) -> u16 {
        self.saros
    }

    #[must_use]
    pub const fn record_count(self) -> u16 {
        self.record_count
    }

    pub fn record(self, index: u16) -> Result<RecordRef<'a>, GeoError> {
        if index >= self.record_count {
            return Err(GeoError::RecordOutOfRange);
        }
        let start = self.offset(index)?;
        let end = self.offset(index + 1)?;
        if start >= end {
            return Err(GeoError::InvalidRecordOffsets);
        }
        Ok(RecordRef {
            saros: self.saros,
            sequence: index,
            data: self.data,
            start_bit: start,
            end_bit: end,
        })
    }

    pub fn validate(self) -> Result<(), GeoError> {
        for index in 0..self.record_count {
            self.record(index)?.validate()?;
        }
        Ok(())
    }

    fn validate_offsets(self) -> Result<(), GeoError> {
        let mut previous = None;
        let data_bits = self
            .data
            .len()
            .checked_mul(8)
            .ok_or(GeoError::ArithmeticOverflow)?;
        for index in 0..=self.record_count {
            let offset = self.offset(index)?;
            if offset > data_bits {
                return Err(GeoError::InvalidRecordOffsets);
            }
            if let Some(previous) = previous
                && offset < previous
            {
                return Err(GeoError::InvalidRecordOffsets);
            }
            previous = Some(offset);
        }
        if self.offset(0)? != 0 || self.offset(self.record_count)? == 0 {
            return Err(GeoError::InvalidRecordOffsets);
        }
        Ok(())
    }

    fn offset(self, index: u16) -> Result<usize, GeoError> {
        let byte_offset = usize::from(index)
            .checked_mul(4)
            .ok_or(GeoError::ArithmeticOverflow)?;
        usize::try_from(read_u32_le(self.offsets_bytes, byte_offset)?)
            .map_err(|_| GeoError::ArithmeticOverflow)
    }
}

/// Borrowed path record. Its methods do not allocate and keep all bit reads
/// within the record's own offset range.
#[derive(Clone, Copy, Debug)]
pub struct RecordRef<'a> {
    saros: u16,
    sequence: u16,
    data: &'a [u8],
    start_bit: usize,
    end_bit: usize,
}

impl<'a> RecordRef<'a> {
    #[must_use]
    pub const fn saros(self) -> u16 {
        self.saros
    }

    #[must_use]
    pub const fn sequence(self) -> u16 {
        self.sequence
    }

    pub fn metadata(self) -> Result<EclipseMetadata, GeoError> {
        let mut reader = BitReader::new(self.data, self.start_bit, self.end_bit);
        let header = RecordHeader::read(&mut reader)?;
        let path_point_count = scan_geometry(&mut reader, header.polygon_count, None)?;
        if reader.position() != self.end_bit {
            return Err(GeoError::InvalidField);
        }
        Ok(EclipseMetadata {
            type_index: header.type_index,
            unix_seconds: header.unix_seconds,
            latitude_e6: header.latitude_e6,
            longitude_e6: header.longitude_e6,
            sun_altitude_degrees: header.sun_altitude_degrees,
            magnitude_e4: header.magnitude_e4,
            gamma_e4: header.gamma_e4,
            central_duration_seconds: header.central_duration_seconds,
            central_width_km: header.central_width_km,
            polygon_count: header.polygon_count,
            path_point_count,
        })
    }

    pub fn visit_geometry(
        self,
        visitor: &mut impl FnMut(GeometryEvent),
    ) -> Result<EclipseMetadata, GeoError> {
        let mut reader = BitReader::new(self.data, self.start_bit, self.end_bit);
        let header = RecordHeader::read(&mut reader)?;
        let path_point_count = scan_geometry(&mut reader, header.polygon_count, Some(visitor))?;
        if reader.position() != self.end_bit {
            return Err(GeoError::InvalidField);
        }
        Ok(EclipseMetadata {
            type_index: header.type_index,
            unix_seconds: header.unix_seconds,
            latitude_e6: header.latitude_e6,
            longitude_e6: header.longitude_e6,
            sun_altitude_degrees: header.sun_altitude_degrees,
            magnitude_e4: header.magnitude_e4,
            gamma_e4: header.gamma_e4,
            central_duration_seconds: header.central_duration_seconds,
            central_width_km: header.central_width_km,
            polygon_count: header.polygon_count,
            path_point_count,
        })
    }

    pub fn validate(self) -> Result<(), GeoError> {
        self.metadata().map(|_| ())
    }
}

#[derive(Clone, Copy, Debug)]
struct RecordHeader {
    type_index: u8,
    unix_seconds: i64,
    latitude_e6: i32,
    longitude_e6: i32,
    sun_altitude_degrees: u8,
    magnitude_e4: u16,
    gamma_e4: i16,
    central_duration_seconds: Option<u16>,
    central_width_km: Option<u16>,
    polygon_count: u8,
}

impl RecordHeader {
    fn read(reader: &mut BitReader<'_>) -> Result<Self, GeoError> {
        let type_index = u8::try_from(reader.read_uint(RECORD_TYPE_BITS)?)
            .map_err(|_| GeoError::InvalidField)?;
        if type_index >= 18 {
            return Err(GeoError::InvalidField);
        }
        let unix_seconds = reader.read_signed(RECORD_UNIX_BITS)?;
        let latitude_e6 = read_coordinate(reader, 90 * COORDINATE_SCALE)?;
        let longitude_e6 = read_coordinate(reader, 180 * COORDINATE_SCALE)?;
        let sun_altitude_degrees = u8::try_from(reader.read_uint(RECORD_SUN_ALTITUDE_BITS)?)
            .map_err(|_| GeoError::InvalidField)?;
        let magnitude_e4 = u16::try_from(reader.read_uint(RECORD_MAGNITUDE_BITS)?)
            .map_err(|_| GeoError::InvalidField)?;
        let gamma_e4 = read_signed_magnitude(reader, RECORD_GAMMA_BITS, 16_383)?;
        let central_duration_seconds = if reader.read_uint(1)? == 1 {
            Some(
                u16::try_from(reader.read_uint(RECORD_DURATION_BITS)?)
                    .map_err(|_| GeoError::InvalidField)?,
            )
        } else {
            None
        };
        let central_width_km = if reader.read_uint(1)? == 1 {
            Some(
                u16::try_from(reader.read_uint(RECORD_WIDTH_BITS)?)
                    .map_err(|_| GeoError::InvalidField)?,
            )
        } else {
            None
        };
        let polygon_count = u8::try_from(reader.read_uint(RECORD_POLYGON_COUNT_BITS)?)
            .map_err(|_| GeoError::InvalidField)?;
        Ok(Self {
            type_index,
            unix_seconds,
            latitude_e6,
            longitude_e6,
            sun_altitude_degrees,
            magnitude_e4,
            gamma_e4,
            central_duration_seconds,
            central_width_km,
            polygon_count,
        })
    }
}

fn scan_geometry(
    reader: &mut BitReader<'_>,
    polygon_count: u8,
    mut visitor: Option<&mut dyn FnMut(GeometryEvent)>,
) -> Result<u32, GeoError> {
    let mut points = 0_u32;
    for _ in 0..polygon_count {
        let point_count = u16::try_from(reader.read_uint(RECORD_POINT_COUNT_BITS)?)
            .map_err(|_| GeoError::InvalidField)?;
        if let Some(callback) = visitor.as_deref_mut() {
            callback(GeometryEvent::BeginPolygon { point_count });
        }
        for _ in 0..point_count {
            let longitude_e6 = read_coordinate(reader, 180 * COORDINATE_SCALE)?;
            let latitude_e6 = read_coordinate(reader, 90 * COORDINATE_SCALE)?;
            if let Some(callback) = visitor.as_deref_mut() {
                callback(GeometryEvent::Point(GeometryPoint {
                    longitude_e6,
                    latitude_e6,
                }));
            }
        }
        if let Some(callback) = visitor.as_deref_mut() {
            callback(GeometryEvent::EndPolygon);
        }
        points = points
            .checked_add(u32::from(point_count))
            .ok_or(GeoError::ArithmeticOverflow)?;
    }
    Ok(points)
}

fn read_coordinate(reader: &mut BitReader<'_>, maximum: i32) -> Result<i32, GeoError> {
    let sign = reader.read_uint(1)?;
    let magnitude = i32::try_from(reader.read_uint(28)?).map_err(|_| GeoError::InvalidField)?;
    if magnitude > maximum {
        return Err(GeoError::InvalidCoordinate);
    }
    if sign == 0 {
        Ok(magnitude)
    } else if sign == 1 {
        magnitude.checked_neg().ok_or(GeoError::InvalidCoordinate)
    } else {
        Err(GeoError::InvalidField)
    }
}

fn read_signed_magnitude(
    reader: &mut BitReader<'_>,
    bits: u8,
    maximum: i16,
) -> Result<i16, GeoError> {
    if bits < 2 {
        return Err(GeoError::InvalidField);
    }
    let sign = reader.read_uint(1)?;
    let magnitude =
        i16::try_from(reader.read_uint(bits - 1)?).map_err(|_| GeoError::InvalidField)?;
    if magnitude > maximum {
        return Err(GeoError::InvalidField);
    }
    if sign == 0 {
        Ok(magnitude)
    } else if sign == 1 {
        magnitude.checked_neg().ok_or(GeoError::InvalidField)
    } else {
        Err(GeoError::InvalidField)
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
    end: usize,
}

impl<'a> BitReader<'a> {
    const fn new(bytes: &'a [u8], position: usize, end: usize) -> Self {
        Self {
            bytes,
            position,
            end,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn read_uint(&mut self, bits: u8) -> Result<u64, GeoError> {
        if bits == 0 || bits > 64 {
            return Err(GeoError::InvalidField);
        }
        let end = self
            .position
            .checked_add(usize::from(bits))
            .ok_or(GeoError::ArithmeticOverflow)?;
        if end > self.end {
            return Err(GeoError::Truncated);
        }
        let mut value = 0_u64;
        for _ in 0..bits {
            let byte_index = self.position / 8;
            let bit_index = self.position % 8;
            let byte = *self.bytes.get(byte_index).ok_or(GeoError::Truncated)?;
            value = (value << 1) | u64::from((byte >> (7 - bit_index)) & 1);
            self.position += 1;
        }
        Ok(value)
    }

    fn read_signed(&mut self, bits: u8) -> Result<i64, GeoError> {
        let value = self.read_uint(bits)?;
        if bits == 64 {
            return Ok(value as i64);
        }
        let sign_bit = 1_u64 << (bits - 1);
        if value & sign_bit == 0 {
            i64::try_from(value).map_err(|_| GeoError::InvalidField)
        } else {
            let sign_extended = value | (!0_u64 << bits);
            Ok(sign_extended as i64)
        }
    }
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, GeoError> {
    let end = offset.checked_add(2).ok_or(GeoError::ArithmeticOverflow)?;
    let source = bytes.get(offset..end).ok_or(GeoError::Truncated)?;
    Ok(u16::from_le_bytes([source[0], source[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, GeoError> {
    let end = offset.checked_add(4).ok_or(GeoError::ArithmeticOverflow)?;
    let source = bytes.get(offset..end).ok_or(GeoError::Truncated)?;
    Ok(u32::from_le_bytes([
        source[0], source[1], source[2], source[3],
    ]))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const REVIEWED: &[u8] = include_bytes!("../../../assets/saros/geo/v1/reviewed-101-161.eclp");

    #[test]
    fn validates_the_reviewed_release() {
        let file = SingleFile::open(REVIEWED).expect("open asset");
        assert_eq!(file.section_count(), 61);
        for saros in 101..=161 {
            let section = file.section(saros).expect("section");
            for sequence in 0..section.record_count() {
                if let Err(error) = section.record(sequence).expect("record").validate() {
                    panic!("series {saros}, record {sequence}: {error:?}");
                }
            }
        }
    }

    #[test]
    fn accesses_saros_141_without_allocating() {
        let file = SingleFile::open(REVIEWED).expect("open asset");
        let section = file.section(141).expect("series 141");
        assert_eq!(section.record_count(), 50);
        let record = section.record(0).expect("first eclipse");
        let metadata = record.metadata().expect("metadata");
        assert_eq!(metadata.unix_seconds, -11_253_795_384);
        assert!(metadata.path_point_count > 2);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = [0_u8; 8];
        bytes[..4].copy_from_slice(b"NOPE");
        assert!(matches!(
            SingleFile::open(&bytes),
            Err(GeoError::InvalidMagic)
        ));
    }

    #[test]
    fn reads_full_width_signed_fields_without_an_overflowing_shift() {
        let bytes = [0xff_u8; 8];
        let mut reader = BitReader::new(&bytes, 0, 64);
        assert_eq!(reader.read_signed(64), Ok(-1));
    }
}
