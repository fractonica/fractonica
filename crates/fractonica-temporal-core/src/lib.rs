#![no_std]
#![forbid(unsafe_code)]
//! Exact, allocation-free Saros temporal semantics.
//!
//! [`PhaseRatio`] is the source of truth for a position inside a half-open
//! eclipse interval. It stores an exact rational value and can stream an
//! unbounded number of most-significant octal digits without allocating.
//! [`PhaseWord64`] is a fast fixed-point *projection* of that ratio: callers
//! can request any prefix from one through 64 bits, while the original ratio
//! remains available whenever more precision is required.
//!
//! This crate deliberately has no catalog, clock, filesystem, or network
//! dependency. A catalog-facing engine resolves an [`Interval`] first, then
//! passes the interval and an explicit [`Timestamp`] here.

use core::fmt;

/// The radix used by Saros addresses.
pub const RADIX: u8 = 8;
/// Number of binary bits in one octal digit.
pub const BITS_PER_OCTAL_DIGIT: u8 = 3;
/// Number of bits in [`PhaseWord64`].
pub const PHASE_WORD_BITS: u8 = 64;
/// Number of complete octal digits represented by a 64-bit phase word.
///
/// Twenty-one digits consume 63 bits. The final word bit is retained as guard
/// precision and is not part of a complete octal digit.
pub const PHASE_WORD_OCTAL_DIGITS: usize = 21;
/// Ten octal digits are the realtime pulse: two five-digit glyphs.
pub const REALTIME_PULSE_DIGITS: usize = 10;
/// Bit precision of the realtime pulse (ten octal digits × three bits).
pub const REALTIME_PULSE_BITS: u8 = 30;
/// Backwards-readable name for the pulse's octal digit count.
pub const REALTIME_PULSE_DEPTH: usize = REALTIME_PULSE_DIGITS;
/// Number of octal digits in each pulse glyph.
pub const GLYPH_DIGITS: usize = 5;
/// The default Saros series used by the realtime pulse presentation.
pub const DEFAULT_PULSE_SAROS: u8 = 141;
/// Exact average Saros duration used for display-period calculations.
///
/// It is expressed in centiseconds so the `.04` seconds are retained without
/// a floating-point approximation.
pub const AVERAGE_SAROS_CYCLE_CENTISECONDS: u64 = 56_897_174_304;
/// Exact average Saros duration in nanoseconds.
pub const AVERAGE_SAROS_CYCLE_NANOSECONDS: u128 =
    (AVERAGE_SAROS_CYCLE_CENTISECONDS as u128) * 10_000_000;
/// Number of nanoseconds in one Unix second.
pub const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalError {
    /// A binary phase projection must contain between one and 64 bits.
    InvalidBitPrecision(u8),
    /// A phase ratio must be finite and lie in `[0, 1)`.
    InvalidPhaseRatio,
    /// A rational duration needs a nonzero denominator.
    InvalidDuration,
    /// Eclipse points must form a strictly positive interval.
    InvalidInterval,
    /// A timestamp has a nanosecond component outside `0..1_000_000_000`.
    InvalidNanosecond(u32),
    /// The instant is not inside the half-open interval `[previous, next)`.
    InstantOutsideInterval,
    /// A materialized octal address has no digits or exceeds word capacity.
    InvalidAddressLength(usize),
    /// A raw octal digit is outside `0..=7`.
    InvalidAddressDigit(u8),
    /// A materialized octal address cannot fit its declared width.
    AddressOutOfRange,
    /// The caller-provided output buffer is too small.
    BufferTooSmall,
    /// A series needs at least two eclipse points to form an interval.
    TooFewEclipses,
    /// Series eclipse points are not strictly increasing.
    UnsortedEclipses,
    /// Series eclipse points do not all belong to the same Saros series.
    MixedSarosSeries,
    /// The requested instant is outside the known half-open series coverage.
    OutsideSeriesCoverage,
}

impl fmt::Display for TemporalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBitPrecision(bits) => {
                write!(
                    formatter,
                    "phase precision must be between 1 and 64 bits, got {bits}"
                )
            }
            Self::InvalidPhaseRatio => formatter.write_str("phase ratio must lie in [0, 1)"),
            Self::InvalidDuration => formatter.write_str("duration denominator must be positive"),
            Self::InvalidInterval => formatter.write_str("eclipse interval must be positive"),
            Self::InvalidNanosecond(nanosecond) => write!(
                formatter,
                "nanosecond component must be below {NANOSECONDS_PER_SECOND}, got {nanosecond}"
            ),
            Self::InstantOutsideInterval => {
                formatter.write_str("instant is outside the half-open eclipse interval")
            }
            Self::InvalidAddressLength(length) => write!(
                formatter,
                "materialized octal address length must be between 1 and {PHASE_WORD_OCTAL_DIGITS}, got {length}"
            ),
            Self::InvalidAddressDigit(digit) => {
                write!(formatter, "octal address contains invalid digit {digit}")
            }
            Self::AddressOutOfRange => formatter.write_str("octal address is out of range"),
            Self::BufferTooSmall => formatter.write_str("output buffer is too small"),
            Self::TooFewEclipses => formatter.write_str("at least two eclipses are required"),
            Self::UnsortedEclipses => {
                formatter.write_str("eclipse timestamps must be strictly increasing")
            }
            Self::MixedSarosSeries => {
                formatter.write_str("all eclipse points must belong to one Saros series")
            }
            Self::OutsideSeriesCoverage => {
                formatter.write_str("instant is outside known Saros series coverage")
            }
        }
    }
}

/// An exact Unix timestamp with nanosecond resolution.
///
/// The fields are private so invalid nanosecond values cannot enter temporal
/// calculations. Eclipse catalog points are whole seconds; callers may use a
/// nanosecond component for an instant between two catalog entries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp {
    epoch_seconds: i64,
    nanosecond: u32,
}

impl Timestamp {
    pub fn new(epoch_seconds: i64, nanosecond: u32) -> Result<Self, TemporalError> {
        if nanosecond >= NANOSECONDS_PER_SECOND {
            return Err(TemporalError::InvalidNanosecond(nanosecond));
        }
        Ok(Self {
            epoch_seconds,
            nanosecond,
        })
    }

    #[must_use]
    pub const fn from_epoch_seconds(epoch_seconds: i64) -> Self {
        Self {
            epoch_seconds,
            nanosecond: 0,
        }
    }

    #[must_use]
    pub const fn epoch_seconds(self) -> i64 {
        self.epoch_seconds
    }

    #[must_use]
    pub const fn nanosecond(self) -> u32 {
        self.nanosecond
    }
}

/// A validated exact phase in the half-open unit interval `[0, 1)`.
///
/// It is reduced on construction, so equal phases compare equal even when they
/// originate from intervals with different durations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseRatio {
    numerator: u128,
    denominator: u128,
}

impl PhaseRatio {
    pub fn new(numerator: u128, denominator: u128) -> Result<Self, TemporalError> {
        if denominator == 0 || numerator >= denominator {
            return Err(TemporalError::InvalidPhaseRatio);
        }
        Ok(Self::from_valid_parts(numerator, denominator))
    }

    #[must_use]
    pub const fn zero() -> Self {
        Self {
            numerator: 0,
            denominator: 1,
        }
    }

    #[must_use]
    pub const fn numerator(self) -> u128 {
        self.numerator
    }

    #[must_use]
    pub const fn denominator(self) -> u128 {
        self.denominator
    }

    /// Produces the high 64 fixed-point bits of this exact phase.
    #[must_use]
    pub fn word64(self) -> PhaseWord64 {
        PhaseWord64::from_ratio(self)
    }

    /// Projects the exact phase onto the requested high-order binary bits.
    #[must_use]
    pub fn project(self, precision: BitPrecision) -> PhaseProjection {
        self.project_with_remainder(precision).0
    }

    /// Projects the exact phase and returns exact progress inside that bucket.
    ///
    /// The second result is not inferred from a floating-point subtraction;
    /// it is the remainder left after consuming the requested binary prefix.
    #[must_use]
    pub fn project_with_remainder(self, precision: BitPrecision) -> (PhaseProjection, Self) {
        let mut bits = self.bits();
        let mut prefix = 0_u64;
        for _ in 0..precision.get() {
            prefix = (prefix << 1) | u64::from(bits.next_bit());
        }

        (
            PhaseProjection { precision, prefix },
            Self::from_valid_parts(bits.remainder, bits.denominator),
        )
    }

    /// Returns an iterator over unbounded most-significant binary digits.
    #[must_use]
    pub const fn bits(self) -> PhaseBitIter {
        PhaseBitIter {
            remainder: self.numerator,
            denominator: self.denominator,
        }
    }

    /// Returns an iterator over unbounded most-significant octal digits.
    #[must_use]
    pub const fn octal_digits(self) -> OctalDigitIter {
        OctalDigitIter { bits: self.bits() }
    }

    /// Returns the zero-indexed most-significant octal digit.
    ///
    /// This deliberately has no address-depth cap. For bulk formatting use
    /// [`Self::write_octal_ascii`] to avoid repeatedly restarting iteration.
    #[must_use]
    pub fn octal_digit_msb(self, index: usize) -> u8 {
        let mut digits = self.octal_digits();
        for _ in 0..index {
            let _ = digits.next();
        }
        digits.next().unwrap_or(0)
    }

    /// Writes as many most-significant octal digits as fit in `output`.
    ///
    /// Output is ASCII (`b'0'..=b'7'`) and may be any length. This is how a
    /// caller asks for more than the 21 complete octal digits carried by a
    /// [`PhaseWord64`].
    pub fn write_octal_ascii(self, output: &mut [u8]) {
        let mut digits = self.octal_digits();
        for destination in output {
            *destination = b'0' + digits.next().unwrap_or(0);
        }
    }

    fn from_valid_parts(numerator: u128, denominator: u128) -> Self {
        let divisor = greatest_common_divisor(numerator, denominator);
        Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        }
    }
}

/// Infinite binary expansion of a [`PhaseRatio`].
///
/// It uses remainder arithmetic rather than multiplying the numerator by a
/// power of two, so even a full-width `u128` denominator cannot overflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseBitIter {
    remainder: u128,
    denominator: u128,
}

impl PhaseBitIter {
    fn next_bit(&mut self) -> u8 {
        // For 0 <= remainder < denominator, decide whether 2r crosses the
        // denominator without computing 2r when that could overflow.
        let complement = self.denominator - self.remainder;
        if self.remainder >= complement {
            self.remainder -= complement;
            1
        } else {
            self.remainder += self.remainder;
            0
        }
    }
}

impl Iterator for PhaseBitIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_bit())
    }
}

/// Infinite octal expansion of a [`PhaseRatio`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OctalDigitIter {
    bits: PhaseBitIter,
}

impl Iterator for OctalDigitIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let high = self.bits.next_bit();
        let middle = self.bits.next_bit();
        let low = self.bits.next_bit();
        Some((high << 2) | (middle << 1) | low)
    }
}

/// A 64-bit, MSB-first fixed-point projection of [`PhaseRatio`].
///
/// The top bit represents one half of an eclipse interval. The word is not a
/// claim that phase has only 64 bits of precision: it is a fast cacheable view
/// of an exact [`PhaseRatio`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseWord64(u64);

impl PhaseWord64 {
    /// Creates the high 64-bit fixed-point view of an exact phase ratio.
    #[must_use]
    pub fn from_ratio(phase: PhaseRatio) -> Self {
        let mut bits = phase.bits();
        let mut value = 0_u64;
        for _ in 0..PHASE_WORD_BITS {
            value = (value << 1) | u64::from(bits.next_bit());
        }
        Self(value)
    }

    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Returns a bit numbered from the most-significant side of the word.
    #[must_use]
    pub const fn bit_msb(self, index: u8) -> Option<u8> {
        if index >= PHASE_WORD_BITS {
            return None;
        }
        let shift = PHASE_WORD_BITS - index - 1;
        Some(((self.0 >> shift) & 1) as u8)
    }

    /// Returns a one-through-64-bit MSB projection.
    #[must_use]
    pub const fn project(self, precision: BitPrecision) -> PhaseProjection {
        let shift = PHASE_WORD_BITS - precision.get();
        PhaseProjection {
            precision,
            prefix: self.0 >> shift,
        }
    }

    /// Returns one complete octal digit from the most-significant side.
    ///
    /// A 64-bit word contains 21 complete octal digits and one remaining guard
    /// bit. Use [`PhaseRatio::octal_digits`] for an unbounded expansion.
    #[must_use]
    pub const fn octal_digit_msb(self, index: usize) -> Option<u8> {
        if index >= PHASE_WORD_OCTAL_DIGITS {
            return None;
        }
        let consumed_bits = ((index + 1) * (BITS_PER_OCTAL_DIGIT as usize)) as u8;
        let shift = PHASE_WORD_BITS - consumed_bits;
        Some(((self.0 >> shift) & ((RADIX - 1) as u64)) as u8)
    }

    /// Formats up to 21 complete octal digits from this word.
    pub fn write_octal_ascii(self, output: &mut [u8]) -> Result<(), TemporalError> {
        if output.len() > PHASE_WORD_OCTAL_DIGITS {
            return Err(TemporalError::InvalidAddressLength(output.len()));
        }
        for (index, destination) in output.iter_mut().enumerate() {
            *destination = b'0' + self.octal_digit_msb(index).unwrap_or(0);
        }
        Ok(())
    }
}

/// Validated width for a binary phase projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitPrecision(u8);

impl BitPrecision {
    pub fn new(bits: u8) -> Result<Self, TemporalError> {
        if (1..=PHASE_WORD_BITS).contains(&bits) {
            Ok(Self(bits))
        } else {
            Err(TemporalError::InvalidBitPrecision(bits))
        }
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn full_octal_digits(self) -> usize {
        (self.0 / BITS_PER_OCTAL_DIGIT) as usize
    }

    #[must_use]
    pub const fn trailing_bits(self) -> u8 {
        self.0 % BITS_PER_OCTAL_DIGIT
    }
}

/// A requested MSB prefix of a [`PhaseWord64`].
///
/// `prefix()` is right-aligned: a three-bit projection of binary `101…` has
/// the numeric value `5`. It is exactly `floor(phase * 2^bits)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseProjection {
    precision: BitPrecision,
    prefix: u64,
}

impl PhaseProjection {
    #[must_use]
    pub const fn precision(self) -> BitPrecision {
        self.precision
    }

    #[must_use]
    pub const fn prefix(self) -> u64 {
        self.prefix
    }

    #[must_use]
    pub const fn full_octal_digits(self) -> usize {
        self.precision.full_octal_digits()
    }

    #[must_use]
    pub const fn trailing_bits(self) -> u8 {
        self.precision.trailing_bits()
    }

    #[must_use]
    pub const fn denominator(self) -> u128 {
        1_u128 << self.precision.get()
    }

    /// Returns a projection bit counted from the most-significant side.
    #[must_use]
    pub const fn bit_msb(self, index: u8) -> Option<u8> {
        if index >= self.precision.get() {
            return None;
        }
        let shift = self.precision.get() - index - 1;
        Some(((self.prefix >> shift) & 1) as u8)
    }

    /// Returns one complete octal digit from the requested bit prefix.
    #[must_use]
    pub const fn octal_digit_msb(self, index: usize) -> Option<u8> {
        if index >= self.full_octal_digits() {
            return None;
        }
        let consumed_bits = ((index + 1) * (BITS_PER_OCTAL_DIGIT as usize)) as u8;
        let shift = self.precision.get() - consumed_bits;
        Some(((self.prefix >> shift) & ((RADIX - 1) as u64)) as u8)
    }

    /// Formats all complete octal digits in the projection.
    pub fn write_octal_ascii(self, output: &mut [u8]) -> Result<(), TemporalError> {
        if output.len() < self.full_octal_digits() {
            return Err(TemporalError::BufferTooSmall);
        }
        for (index, destination) in output.iter_mut().take(self.full_octal_digits()).enumerate() {
            *destination = b'0' + self.octal_digit_msb(index).unwrap_or(0);
        }
        Ok(())
    }

    /// Returns the exact boundary of the next projected bucket.
    ///
    /// The final bucket returns `1/1` in its original power-of-two denominator
    /// rather than wrapping to zero.
    #[must_use]
    pub const fn next_boundary(self) -> PhaseBoundary {
        PhaseBoundary {
            numerator: (self.prefix as u128) + 1,
            denominator: self.denominator(),
        }
    }
}

/// A boundary in the closed unit interval `[0, 1]`.
///
/// Unlike [`PhaseRatio`], this type permits exactly one so a final bin's next
/// flip can be represented without lossy clamping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseBoundary {
    numerator: u128,
    denominator: u128,
}

impl PhaseBoundary {
    #[must_use]
    pub const fn numerator(self) -> u128 {
        self.numerator
    }

    #[must_use]
    pub const fn denominator(self) -> u128 {
        self.denominator
    }

    #[must_use]
    pub const fn is_interval_end(self) -> bool {
        self.numerator == self.denominator
    }
}

/// A materialized numeric octal prefix.
///
/// This compatibility helper holds up to 21 complete digits because that is
/// the largest complete-octal prefix that fits a `u64`. It is intentionally
/// not the source of truth for phase precision; use [`PhaseRatio`] to generate
/// arbitrary-length prefixes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OctalAddress {
    value: u64,
    digits: u8,
}

impl OctalAddress {
    pub fn new(value: u64, digits: u8) -> Result<Self, TemporalError> {
        let length = usize::from(digits);
        let bin_count =
            octal_power_u64(length).ok_or(TemporalError::InvalidAddressLength(length))?;
        if value >= bin_count {
            return Err(TemporalError::AddressOutOfRange);
        }
        Ok(Self { value, digits })
    }

    pub fn from_octal_ascii(digits: &[u8]) -> Result<Self, TemporalError> {
        if digits.is_empty() || digits.len() > PHASE_WORD_OCTAL_DIGITS {
            return Err(TemporalError::InvalidAddressLength(digits.len()));
        }

        let mut value = 0_u64;
        for ascii in digits {
            if !(b'0'..=b'7').contains(ascii) {
                return Err(TemporalError::InvalidAddressDigit(*ascii));
            }
            value = (value << BITS_PER_OCTAL_DIGIT) | u64::from(*ascii - b'0');
        }
        Self::new(value, digits.len() as u8)
    }

    /// Materializes the complete octal portion of a bit projection.
    pub fn from_projection(projection: PhaseProjection) -> Result<Self, TemporalError> {
        let digits = projection.full_octal_digits();
        if digits == 0 {
            return Err(TemporalError::InvalidAddressLength(0));
        }
        let value = projection.prefix() >> projection.trailing_bits();
        Self::new(value, digits as u8)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }

    #[must_use]
    pub const fn digits(self) -> u8 {
        self.digits
    }

    #[must_use]
    pub const fn digit_msb(self, index: u8) -> Option<u8> {
        if index >= self.digits {
            return None;
        }
        let shift = (self.digits - index - 1) * BITS_PER_OCTAL_DIGIT;
        Some(((self.value >> shift) & ((RADIX - 1) as u64)) as u8)
    }

    pub fn write_ascii(self, output: &mut [u8]) -> Result<(), TemporalError> {
        if output.len() < usize::from(self.digits) {
            return Err(TemporalError::BufferTooSmall);
        }
        for (index, destination) in output.iter_mut().take(usize::from(self.digits)).enumerate() {
            *destination = b'0' + self.digit_msb(index as u8).unwrap_or(0);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RarityFamily {
    Common = 0,
    Triplex = 3,
    Duplex = 4,
    Simplex = 5,
    Nihil = 6,
}

impl RarityFamily {
    #[must_use]
    pub const fn wire_id(self) -> &'static str {
        match self {
            Self::Common => "common",
            Self::Triplex => "triplex",
            Self::Duplex => "duplex",
            Self::Simplex => "simplex",
            Self::Nihil => "nihil",
        }
    }

    #[must_use]
    pub const fn wildcard_prefix(self) -> Option<usize> {
        match self {
            Self::Common => None,
            Self::Triplex => Some(3),
            Self::Duplex => Some(2),
            Self::Simplex => Some(1),
            Self::Nihil => Some(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rarity {
    pub family: RarityFamily,
    /// `1..=7` for a named rarity digit, or `0` for `Common`.
    pub digit: u8,
}

impl Rarity {
    #[must_use]
    pub const fn digit_name(self) -> &'static str {
        match self.digit {
            1 => "Alpha",
            2 => "Beta",
            3 => "Gamma",
            4 => "Delta",
            5 => "Epsilon",
            6 => "Digamma",
            7 => "Omega",
            _ => "Common",
        }
    }
}

/// Classifies a materialized octal address using MSB-first digits.
#[must_use]
pub fn classify_rarity(address: OctalAddress) -> Rarity {
    if address.value == 0 {
        return omega_nihil();
    }

    let adjusted = if address.value.is_multiple_of(u64::from(RADIX)) {
        address.value - 1
    } else {
        address.value
    };
    let repeated_digit = (adjusted % u64::from(RADIX)) as u8;
    let mut remaining = adjusted;
    let mut suffix_length = 0_usize;

    while suffix_length < usize::from(address.digits)
        && remaining % u64::from(RADIX) == u64::from(repeated_digit)
    {
        suffix_length += 1;
        remaining /= u64::from(RADIX);
    }

    rarity_from_suffix(usize::from(address.digits) - suffix_length, repeated_digit)
}

/// Classifies an arbitrary-length raw octal digit slice.
///
/// The value at a flip is classified as its immediately preceding address, so
/// a trailing `0` borrows through the prefix exactly as an integer decrement
/// would. All-zero input is the distinguished Omega Nihil boundary.
pub fn classify_rarity_digits(digits: &[u8]) -> Result<Rarity, TemporalError> {
    if digits.is_empty() {
        return Err(TemporalError::InvalidAddressLength(0));
    }
    for digit in digits {
        if *digit >= RADIX {
            return Err(TemporalError::InvalidAddressDigit(*digit));
        }
    }
    if digits.iter().all(|digit| *digit == 0) {
        return Ok(omega_nihil());
    }

    let decrement_index = if digits[digits.len() - 1] == 0 {
        digits.iter().rposition(|digit| *digit != 0)
    } else {
        None
    };
    let repeated_digit = if decrement_index.is_some() {
        RADIX - 1
    } else {
        digits[digits.len() - 1]
    };

    let mut suffix_length = 0_usize;
    for index in (0..digits.len()).rev() {
        let adjusted = match decrement_index {
            Some(decrement) if index > decrement => RADIX - 1,
            Some(decrement) if index == decrement => digits[index] - 1,
            _ => digits[index],
        };
        if adjusted != repeated_digit {
            break;
        }
        suffix_length += 1;
    }

    Ok(rarity_from_suffix(
        digits.len() - suffix_length,
        repeated_digit,
    ))
}

/// Returns the spacing, in addresses, between repdigit flips at `digits`.
#[must_use]
pub fn repdigit_stride(family: RarityFamily, digits: usize) -> Option<u128> {
    let wildcard_prefix = family.wildcard_prefix()?;
    if digits <= wildcard_prefix {
        return None;
    }
    octal_power_u128(digits - wildcard_prefix)
}

/// Returns the offset of one nonzero repdigit within its repeating stride.
#[must_use]
pub fn repdigit_offset(family: RarityFamily, digit: u8, digits: usize) -> Option<u128> {
    if !(1..=7).contains(&digit) {
        return None;
    }
    let stride = repdigit_stride(family, digits)?;
    Some(u128::from(digit) * ((stride - 1) / 7))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EclipsePoint {
    pub index: u16,
    pub epoch_seconds: i64,
    pub saros: u8,
    pub sequence: u8,
    pub type_code: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interval {
    pub saros: u8,
    pub previous: EclipsePoint,
    pub next: EclipsePoint,
}

impl Interval {
    /// Validates static interval invariants.
    pub fn validate(self) -> Result<(), TemporalError> {
        if self.previous.saros != self.saros || self.next.saros != self.saros {
            return Err(TemporalError::MixedSarosSeries);
        }
        if self.previous.epoch_seconds >= self.next.epoch_seconds {
            return Err(TemporalError::InvalidInterval);
        }
        Ok(())
    }

    /// Returns the exact phase at `at`, enforcing `[previous, next)`.
    pub fn phase_at(self, at: Timestamp) -> Result<PhaseRatio, TemporalError> {
        self.validate()?;

        let previous = Timestamp::from_epoch_seconds(self.previous.epoch_seconds);
        let next = Timestamp::from_epoch_seconds(self.next.epoch_seconds);
        if at < previous || at >= next {
            return Err(TemporalError::InstantOutsideInterval);
        }

        let elapsed_seconds = i128::from(at.epoch_seconds) - i128::from(previous.epoch_seconds);
        let total_seconds = i128::from(next.epoch_seconds) - i128::from(previous.epoch_seconds);
        let elapsed_nanoseconds = (elapsed_seconds as u128) * u128::from(NANOSECONDS_PER_SECOND)
            + u128::from(at.nanosecond);
        let total_nanoseconds = (total_seconds as u128) * u128::from(NANOSECONDS_PER_SECOND);
        PhaseRatio::new(elapsed_nanoseconds, total_nanoseconds)
    }
}

/// An exact clock reading for a selected binary projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockReading {
    /// Exact position inside the resolved interval.
    pub phase: PhaseRatio,
    /// Fast high-64-bit projection of `phase`.
    pub word: PhaseWord64,
    /// Requested one-through-64-bit view of `word`.
    pub projection: PhaseProjection,
    /// Exact fractional progress through `projection`'s current bucket.
    pub progress_within_projection: PhaseRatio,
    /// Exact phase boundary of the next bucket.
    pub next_flip: PhaseBoundary,
}

/// Calculates an exact temporal reading for a validated half-open interval.
pub fn clock_reading(
    interval: Interval,
    at: Timestamp,
    precision: BitPrecision,
) -> Result<ClockReading, TemporalError> {
    let phase = interval.phase_at(at)?;
    let word = phase.word64();
    let (projection, progress_within_projection) = phase.project_with_remainder(precision);
    Ok(ClockReading {
        phase,
        word,
        projection,
        progress_within_projection,
        next_flip: projection.next_boundary(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PulseAddress10 {
    /// First glyph: the five most-significant octal digits.
    pub most_significant: [u8; GLYPH_DIGITS],
    /// Second glyph: the next five octal digits.
    pub least_significant: [u8; GLYPH_DIGITS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PulseReading10 {
    /// The same exact reading projected to 30 bits / ten octal digits.
    pub clock: ClockReading,
    pub glyphs: PulseAddress10,
}

/// Calculates the standard ten-digit realtime pulse for an interval.
pub fn pulse_reading_10(
    interval: Interval,
    at: Timestamp,
) -> Result<PulseReading10, TemporalError> {
    let phase = interval.phase_at(at)?;
    Ok(pulse_from_phase(phase))
}

/// Calculates the standard ten-digit realtime pulse from an exact phase.
#[must_use]
pub fn pulse_from_phase(phase: PhaseRatio) -> PulseReading10 {
    let precision = BitPrecision::new(REALTIME_PULSE_BITS)
        .expect("the realtime pulse precision is a compile-time valid width");
    let word = phase.word64();
    let (projection, progress_within_projection) = phase.project_with_remainder(precision);
    let clock = ClockReading {
        phase,
        word,
        projection,
        progress_within_projection,
        next_flip: projection.next_boundary(),
    };

    let mut most_significant = [0_u8; GLYPH_DIGITS];
    let mut least_significant = [0_u8; GLYPH_DIGITS];
    for index in 0..GLYPH_DIGITS {
        most_significant[index] = projection.octal_digit_msb(index).unwrap_or(0);
        least_significant[index] = projection
            .octal_digit_msb(index + GLYPH_DIGITS)
            .unwrap_or(0);
    }

    PulseReading10 {
        clock,
        glyphs: PulseAddress10 {
            most_significant,
            least_significant,
        },
    }
}

/// Resolves the half-open interval `[eclipse[i], eclipse[i + 1])` containing
/// `at_epoch_seconds`.
///
/// The first eclipse is included; the final eclipse has no successor and is
/// therefore outside coverage. The function never clamps an out-of-coverage
/// instant to an edge interval.
pub fn series_bracket(
    eclipses: &[EclipsePoint],
    at_epoch_seconds: i64,
) -> Result<Interval, TemporalError> {
    if eclipses.len() < 2 {
        return Err(TemporalError::TooFewEclipses);
    }

    let saros = eclipses[0].saros;
    for pair in eclipses.windows(2) {
        if pair[0].saros != saros || pair[1].saros != saros {
            return Err(TemporalError::MixedSarosSeries);
        }
        if pair[0].epoch_seconds >= pair[1].epoch_seconds {
            return Err(TemporalError::UnsortedEclipses);
        }
    }

    let last_index = eclipses.len() - 1;
    if at_epoch_seconds < eclipses[0].epoch_seconds
        || at_epoch_seconds >= eclipses[last_index].epoch_seconds
    {
        return Err(TemporalError::OutsideSeriesCoverage);
    }

    let mut low = 1_usize;
    let mut high = last_index;
    while low < high {
        let middle = low + (high - low) / 2;
        if eclipses[middle].epoch_seconds <= at_epoch_seconds {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    Ok(Interval {
        saros,
        previous: eclipses[low - 1],
        next: eclipses[low],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalPeriod {
    Tera,
    Giga,
    Mega,
    Kilo,
    Saros,
    Mili,
    Nano,
}

impl TemporalPeriod {
    #[must_use]
    pub const fn exponent(self) -> usize {
        match self {
            Self::Tera => 3,
            Self::Giga => 4,
            Self::Mega => 5,
            Self::Kilo => 6,
            Self::Saros => 7,
            Self::Mili => 8,
            Self::Nano => 9,
        }
    }

    /// Exact average duration, expressed as a rational nanosecond count.
    #[must_use]
    pub fn average_duration(self) -> RationalDuration {
        RationalDuration::from_nonzero_parts(
            AVERAGE_SAROS_CYCLE_NANOSECONDS,
            octal_power_u128(self.exponent()).unwrap_or(1),
        )
    }
}

/// A positive duration represented in nanoseconds without rounding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RationalDuration {
    numerator_nanoseconds: u128,
    denominator: u128,
}

impl RationalDuration {
    pub fn new(numerator_nanoseconds: u128, denominator: u128) -> Result<Self, TemporalError> {
        if denominator == 0 {
            return Err(TemporalError::InvalidDuration);
        }
        Ok(Self::from_nonzero_parts(numerator_nanoseconds, denominator))
    }

    fn from_nonzero_parts(numerator_nanoseconds: u128, denominator: u128) -> Self {
        let divisor = greatest_common_divisor(numerator_nanoseconds, denominator);
        Self {
            numerator_nanoseconds: numerator_nanoseconds / divisor,
            denominator: denominator / divisor,
        }
    }

    #[must_use]
    pub const fn numerator_nanoseconds(self) -> u128 {
        self.numerator_nanoseconds
    }

    #[must_use]
    pub const fn denominator(self) -> u128 {
        self.denominator
    }

    #[must_use]
    pub const fn floor_nanoseconds(self) -> u128 {
        self.numerator_nanoseconds / self.denominator
    }
}

const fn omega_nihil() -> Rarity {
    Rarity {
        family: RarityFamily::Nihil,
        digit: 7,
    }
}

const fn rarity_from_suffix(wildcard_prefix: usize, repeated_digit: u8) -> Rarity {
    let family = match wildcard_prefix {
        3 => RarityFamily::Triplex,
        2 => RarityFamily::Duplex,
        1 => RarityFamily::Simplex,
        0 => RarityFamily::Nihil,
        _ => RarityFamily::Common,
    };
    Rarity {
        family,
        digit: if matches!(family, RarityFamily::Common) {
            0
        } else {
            repeated_digit
        },
    }
}

const fn greatest_common_divisor(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

const fn octal_power_u64(exponent: usize) -> Option<u64> {
    if exponent == 0 || exponent > PHASE_WORD_OCTAL_DIGITS {
        return None;
    }
    let mut result = 1_u64;
    let mut index = 0_usize;
    while index < exponent {
        match result.checked_mul(RADIX as u64) {
            Some(value) => result = value,
            None => return None,
        }
        index += 1;
    }
    Some(result)
}

const fn octal_power_u128(exponent: usize) -> Option<u128> {
    let mut result = 1_u128;
    let mut index = 0_usize;
    while index < exponent {
        match result.checked_mul(RADIX as u128) {
            Some(value) => result = value,
            None => return None,
        }
        index += 1;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn eclipse(index: u16, epoch_seconds: i64) -> EclipsePoint {
        EclipsePoint {
            index,
            epoch_seconds,
            saros: DEFAULT_PULSE_SAROS,
            sequence: index as u8,
            type_code: 0,
        }
    }

    fn interval() -> Interval {
        Interval {
            saros: DEFAULT_PULSE_SAROS,
            previous: eclipse(0, 0),
            next: eclipse(1, 1_024),
        }
    }

    #[test]
    fn calculates_an_exact_msb_first_address() {
        let precision = BitPrecision::new(9).expect("precision");
        let reading = clock_reading(interval(), Timestamp::from_epoch_seconds(512), precision)
            .expect("reading");
        let address = OctalAddress::from_projection(reading.projection).expect("address");
        let mut ascii = [0_u8; 3];
        address.write_ascii(&mut ascii).expect("address");

        assert_eq!(reading.phase, PhaseRatio::new(1, 2).expect("phase"));
        assert_eq!(reading.projection.prefix(), 256);
        assert_eq!(&ascii, b"400");
        assert_eq!(reading.word.raw(), 0x8000_0000_0000_0000);
    }

    #[test]
    fn enforces_half_open_interval_boundaries() {
        let at_start = interval()
            .phase_at(Timestamp::from_epoch_seconds(0))
            .expect("start");
        let before_end = interval()
            .phase_at(Timestamp::new(1_023, 999_999_999).expect("timestamp"))
            .expect("before end");

        assert_eq!(at_start, PhaseRatio::zero());
        assert!(before_end.numerator() < before_end.denominator());
        assert_eq!(
            interval().phase_at(Timestamp::from_epoch_seconds(1_024)),
            Err(TemporalError::InstantOutsideInterval)
        );
        assert_eq!(
            interval().phase_at(Timestamp::from_epoch_seconds(-1)),
            Err(TemporalError::InstantOutsideInterval)
        );
    }

    #[test]
    fn supports_every_phase_word_projection_width() {
        let phase = PhaseRatio::new(5, 8).expect("phase");
        let word = phase.word64();
        assert_eq!(word.raw(), 0xa000_0000_0000_0000);

        for bits in 1..=PHASE_WORD_BITS {
            let precision = BitPrecision::new(bits).expect("precision");
            let direct = phase.project(precision);
            let from_word = word.project(precision);
            assert_eq!(direct, from_word);
            assert_eq!(direct.precision().get(), bits);
        }

        assert_eq!(
            BitPrecision::new(0),
            Err(TemporalError::InvalidBitPrecision(0))
        );
        assert_eq!(
            BitPrecision::new(65),
            Err(TemporalError::InvalidBitPrecision(65))
        );
        assert_eq!(
            phase
                .project(BitPrecision::new(3).expect("precision"))
                .prefix(),
            5
        );
    }

    #[test]
    fn streams_arbitrary_length_msb_octal_prefixes() {
        let phase = PhaseRatio::new(1, 3).expect("phase");
        let mut output = [0_u8; 32];
        phase.write_octal_ascii(&mut output);

        assert_eq!(&output, b"25252525252525252525252525252525");
        assert_eq!(phase.octal_digit_msb(100), 2);
        assert_eq!(phase.octal_digit_msb(101), 5);
    }

    #[test]
    fn formats_complete_octal_projection_and_retains_guard_bit() {
        let phase = PhaseRatio::new(1, 8).expect("phase");
        let word = phase.word64();
        let mut word_digits = [0_u8; PHASE_WORD_OCTAL_DIGITS];
        word.write_octal_ascii(&mut word_digits)
            .expect("word digits");
        assert_eq!(&word_digits[..4], b"1000");
        assert_eq!(
            word.write_octal_ascii(&mut [0_u8; 22]),
            Err(TemporalError::InvalidAddressLength(22))
        );

        let projection = phase.project(BitPrecision::new(32).expect("precision"));
        assert_eq!(projection.full_octal_digits(), 10);
        assert_eq!(projection.trailing_bits(), 2);
        let mut projected_digits = [0_u8; 10];
        projection
            .write_octal_ascii(&mut projected_digits)
            .expect("projection digits");
        assert_eq!(&projected_digits[..4], b"1000");
    }

    #[test]
    fn uses_a_thirty_bit_view_for_the_ten_digit_pulse() {
        let target = 0o1234567012_u128;
        let phase = PhaseRatio::new(target, 1_u128 << REALTIME_PULSE_BITS).expect("phase");
        let reading = pulse_from_phase(phase);

        assert_eq!(
            reading.clock.projection.precision().get(),
            REALTIME_PULSE_BITS
        );
        assert_eq!(reading.clock.projection.prefix(), target as u64);
        assert_eq!(reading.glyphs.most_significant, [1, 2, 3, 4, 5]);
        assert_eq!(reading.glyphs.least_significant, [6, 7, 0, 1, 2]);
    }

    #[test]
    fn preserves_exact_arithmetic_for_extreme_intervals() {
        let extreme = Interval {
            saros: DEFAULT_PULSE_SAROS,
            previous: eclipse(0, i64::MIN),
            next: eclipse(1, i64::MAX),
        };
        let reading = clock_reading(
            extreme,
            Timestamp::from_epoch_seconds(0),
            BitPrecision::new(64).expect("precision"),
        )
        .expect("reading");

        assert_eq!(reading.word.raw(), 0x8000_0000_0000_0000);
        assert_eq!(reading.projection.prefix(), 0x8000_0000_0000_0000);
    }

    #[test]
    fn reports_exact_progress_and_next_boundary() {
        let phase = PhaseRatio::new(5, 16).expect("phase");
        let (projection, progress) =
            phase.project_with_remainder(BitPrecision::new(3).expect("precision"));

        assert_eq!(projection.prefix(), 2);
        assert_eq!(progress, PhaseRatio::new(1, 2).expect("progress"));
        assert_eq!(projection.next_boundary().numerator(), 3);
        assert_eq!(projection.next_boundary().denominator(), 8);
    }

    #[test]
    fn classifies_repdigit_families_from_arbitrary_digits() {
        let cases = [
            (b"0001111".as_slice(), RarityFamily::Triplex),
            (b"0011111".as_slice(), RarityFamily::Duplex),
            (b"0111111".as_slice(), RarityFamily::Simplex),
            (b"1111111".as_slice(), RarityFamily::Nihil),
        ];

        for (digits, expected) in cases {
            let raw = digits
                .iter()
                .map(|digit| *digit - b'0')
                .collect::<std::vec::Vec<_>>();
            let rarity = classify_rarity_digits(&raw).expect("rarity");
            assert_eq!(rarity.family, expected);
            assert_eq!(rarity.digit, 1);
        }
    }

    #[test]
    fn classifies_flips_using_the_preceding_address() {
        let at_flip = [0, 0, 0, 1, 1, 2, 0];
        let preceding = [0, 0, 0, 1, 1, 1, 7];
        assert_eq!(
            classify_rarity_digits(&at_flip).expect("flip"),
            classify_rarity_digits(&preceding).expect("preceding")
        );
        assert_eq!(
            classify_rarity_digits(&[0, 0, 0, 0]).expect("zero"),
            omega_nihil()
        );
    }

    #[test]
    fn preserves_repdigit_spacing_without_u32_limits() {
        assert_eq!(repdigit_stride(RarityFamily::Triplex, 7), Some(4_096));
        assert_eq!(repdigit_offset(RarityFamily::Triplex, 1, 7), Some(585));
        assert_eq!(repdigit_offset(RarityFamily::Triplex, 7, 7), Some(4_095));
        assert_eq!(repdigit_stride(RarityFamily::Nihil, 21), Some(1_u128 << 63));
        assert_eq!(RarityFamily::Triplex.wire_id(), "triplex");
    }

    #[test]
    fn brackets_exact_interior_eclipse_as_previous() {
        let eclipses = [eclipse(0, 100), eclipse(1, 200), eclipse(2, 300)];
        let bracket = series_bracket(&eclipses, 200).expect("bracket");

        assert_eq!(bracket.previous.epoch_seconds, 200);
        assert_eq!(bracket.next.epoch_seconds, 300);
        assert_eq!(
            series_bracket(&eclipses, 300),
            Err(TemporalError::OutsideSeriesCoverage)
        );
        assert_eq!(
            series_bracket(&eclipses, 99),
            Err(TemporalError::OutsideSeriesCoverage)
        );
    }

    #[test]
    fn keeps_average_periods_as_exact_rational_durations() {
        let saros = TemporalPeriod::Saros.average_duration();
        let mili = TemporalPeriod::Mili.average_duration();

        // The public values are reduced fractions, so compare them by cross
        // multiplication instead of relying on an implementation denominator.
        assert_eq!(
            saros.numerator_nanoseconds() * (1_u128 << 21),
            AVERAGE_SAROS_CYCLE_NANOSECONDS * saros.denominator()
        );
        assert_eq!(
            mili.numerator_nanoseconds() * (1_u128 << 24),
            AVERAGE_SAROS_CYCLE_NANOSECONDS * mili.denominator()
        );
        assert_eq!(
            saros.numerator_nanoseconds() * mili.denominator(),
            mili.numerator_nanoseconds() * saros.denominator() * 8
        );
        assert!(saros.floor_nanoseconds() > mili.floor_nanoseconds());
    }
}
