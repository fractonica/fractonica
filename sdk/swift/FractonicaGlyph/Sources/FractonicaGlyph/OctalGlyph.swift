import CoreGraphics
import Foundation

/// Public version and coordinate metadata shared with the Rust, JS, and C adapters.
public enum FractonicaGlyphMetadata {
    public static let grammarVersion = GlyphSpec.grammarVersion
    public static let geometryVersion = GlyphSpec.geometryVersion
    public static let specSHA256 = GlyphSpec.sourceSHA256
    public static let fontID = GlyphSpec.fontID
    public static let fontVersion = GlyphSpec.fontVersion
    public static let radix = GlyphSpec.radix
    public static let minimumDepth = GlyphSpec.minimumDigits
    public static let maximumDepth = GlyphSpec.maximumDigits
    public static let defaultDepth = GlyphSpec.defaultDigits
}

/// A point in Fractonica's positive-Y-down glyph coordinate system.
public struct GlyphPoint: Equatable, Sendable {
    public let x: CGFloat
    public let y: CGFloat

    public init(x: CGFloat, y: CGFloat) {
        self.x = x
        self.y = y
    }
}

/// Coordinate system used by font arm outlines. Fractonica's canonical grammar
/// is independent from the visual font, but the built-in renderer currently
/// supports socket-local outlines only.
public enum GlyphArmsCoordinateMode: String, CaseIterable, Sendable {
    case socket
}

/// One visual outline for a semantic octal digit.
public struct GlyphArmOutline: Equatable, Sendable {
    public let digit: UInt8
    public let points: [GlyphPoint]

    public init(digit: UInt8, points: [GlyphPoint]) {
        self.digit = digit
        self.points = points
    }
}

/// A data-only visual font for Fractonica's invariant octal grammar.
///
/// A font controls contours, metrics, and frame-grid spacing. It cannot alter
/// digit parsing, MSB socket order, or the `1 | 2 | 4` semantic mask.
public struct GlyphFont: Equatable, Sendable {
    public let id: String
    public let name: String
    public let fontVersion: String
    public let geometryVersion: String
    public let grammarVersion: String
    /// Optional digest of the complete font artifact used to make this font.
    public let sourceSHA256: String?
    public let units: CGFloat
    public let armsCoordinateMode: GlyphArmsCoordinateMode
    public let socketWidth: CGFloat
    public let coreRadius: CGFloat
    public let insetThickness: CGFloat
    public let gridSize: CGFloat
    public let paddingCells: CGFloat
    public let legacyCoreOuterDepth: Int
    public let legacyCoreOuter: [GlyphPoint]
    public let legacyCoreHoleDepth: Int
    public let legacyCoreHole: [GlyphPoint]
    /// Exactly eight digit-indexed outlines, from zero through seven.
    public let arms: [GlyphArmOutline]

    /// Creates a visual font compatible with the generated octal grammar.
    ///
    /// The depth-six exact contours are optional only in the sense that a font
    /// may choose a different supported depth; every supplied legacy contour
    /// is validated so arm endpoints can share its exact core vertices.
    public init(
        id: String,
        name: String,
        fontVersion: String,
        geometryVersion: String,
        grammarVersion: String,
        sourceSHA256: String? = nil,
        units: CGFloat,
        armsCoordinateMode: GlyphArmsCoordinateMode = .socket,
        socketWidth: CGFloat,
        coreRadius: CGFloat,
        insetThickness: CGFloat,
        gridSize: CGFloat,
        paddingCells: CGFloat,
        legacyCoreOuterDepth: Int,
        legacyCoreOuter: [GlyphPoint],
        legacyCoreHoleDepth: Int,
        legacyCoreHole: [GlyphPoint],
        arms: [GlyphArmOutline],
    ) throws {
        guard !id.isEmpty, !name.isEmpty, !fontVersion.isEmpty, !geometryVersion.isEmpty else {
            throw GlyphFontError.invalidMetadata
        }
        if let sourceSHA256,
           sourceSHA256.utf8.count != 64 || sourceSHA256.utf8.contains(where: { byte in
               !((48...57).contains(byte) || (97...102).contains(byte))
           }) {
            throw GlyphFontError.invalidSourceSHA256
        }
        guard grammarVersion == GlyphSpec.grammarVersion, armsCoordinateMode == .socket else {
            throw GlyphFontError.incompatibleGrammar
        }
        let metrics = [units, socketWidth, coreRadius, insetThickness, gridSize, paddingCells]
        guard metrics.allSatisfy({ $0.isFinite && $0 > 0 }) else {
            throw GlyphFontError.invalidMetrics
        }
        guard (GlyphSpec.minimumDigits...GlyphSpec.maximumDigits).contains(legacyCoreOuterDepth),
              legacyCoreOuter.count == legacyCoreOuterDepth * 2,
              legacyCoreOuter.allSatisfy({ $0.x.isFinite && $0.y.isFinite })
        else {
            throw GlyphFontError.invalidLegacyOuter
        }
        guard (GlyphSpec.minimumDigits...GlyphSpec.maximumDigits).contains(legacyCoreHoleDepth),
              legacyCoreHole.count >= 3,
              legacyCoreHole.allSatisfy({ $0.x.isFinite && $0.y.isFinite })
        else {
            throw GlyphFontError.invalidLegacyHole
        }
        guard arms.count == GlyphSpec.radix else {
            throw GlyphFontError.invalidArms
        }
        for (index, arm) in arms.enumerated() {
            let minimumPoints = index == 0 ? 2 : 3
            guard arm.digit == UInt8(index), arm.points.count >= minimumPoints,
                  arm.points.allSatisfy({ $0.x.isFinite && $0.y.isFinite })
            else {
                throw GlyphFontError.invalidArms
            }
        }

        self.id = id
        self.name = name
        self.fontVersion = fontVersion
        self.geometryVersion = geometryVersion
        self.grammarVersion = grammarVersion
        self.sourceSHA256 = sourceSHA256
        self.units = units
        self.armsCoordinateMode = armsCoordinateMode
        self.socketWidth = socketWidth
        self.coreRadius = coreRadius
        self.insetThickness = insetThickness
        self.gridSize = gridSize
        self.paddingCells = paddingCells
        self.legacyCoreOuterDepth = legacyCoreOuterDepth
        self.legacyCoreOuter = legacyCoreOuter
        self.legacyCoreHoleDepth = legacyCoreHoleDepth
        self.legacyCoreHole = legacyCoreHole
        self.arms = arms
    }

    /// The generated Fractonica Hex v2 font bundled with this SDK.
    public static let `default`: GlyphFont = {
        do {
            return try GlyphFont(
                id: GlyphSpec.fontID,
                name: "Hex octal glyph font v2",
                fontVersion: GlyphSpec.fontVersion,
                geometryVersion: GlyphSpec.geometryVersion,
                grammarVersion: GlyphSpec.grammarVersion,
                sourceSHA256: GlyphSpec.sourceSHA256,
                units: GlyphSpec.units,
                socketWidth: GlyphSpec.socketWidth,
                coreRadius: GlyphSpec.coreRadius,
                insetThickness: GlyphSpec.insetThickness,
                gridSize: GlyphSpec.gridSize,
                paddingCells: GlyphSpec.paddingCells,
                legacyCoreOuterDepth: GlyphSpec.legacyCoreOuterDepth,
                legacyCoreOuter: GlyphSpec.legacyCoreOuter,
                legacyCoreHoleDepth: GlyphSpec.legacyCoreHoleDepth,
                legacyCoreHole: GlyphSpec.legacyCoreHole,
                arms: GlyphSpec.arms.enumerated().map { index, points in
                    GlyphArmOutline(digit: UInt8(index), points: points)
                },
            )
        } catch {
            preconditionFailure("Generated Fractonica Hex v2 font is invalid: \(error)")
        }
    }()

    /// Returns the complete visual outline for an octal digit.
    public func arm(for digit: UInt8) -> GlyphArmOutline? {
        guard arms.indices.contains(Int(digit)) else { return nil }
        return arms[Int(digit)]
    }
}

/// Validation failures for a custom visual font.
public enum GlyphFontError: Error, Equatable, LocalizedError {
    case invalidMetadata
    case invalidSourceSHA256
    case incompatibleGrammar
    case invalidMetrics
    case invalidLegacyOuter
    case invalidLegacyHole
    case invalidArms

    public var errorDescription: String? {
        switch self {
        case .invalidMetadata:
            return "Glyph font identity and version fields must not be empty."
        case .invalidSourceSHA256:
            return "Glyph font sourceSHA256 must be a lowercase 64-character SHA-256 digest when supplied."
        case .incompatibleGrammar:
            return "Glyph font must use the current Fractonica grammar and socket-local arm coordinates."
        case .invalidMetrics:
            return "Glyph font metrics must be finite positive numbers."
        case .invalidLegacyOuter:
            return "Glyph font legacy outer contour must have exactly two points per supported socket."
        case .invalidLegacyHole:
            return "Glyph font legacy hole contour is invalid."
        case .invalidArms:
            return "Glyph font must define finite digit-indexed outlines for all eight octal digits."
        }
    }
}

/// Stable bounds for all possible values at a particular glyph depth.
public struct GlyphFrame: Equatable, Sendable {
    public let x: CGFloat
    public let y: CGFloat
    public let width: CGFloat
    public let height: CGFloat

    public var aspectRatio: CGFloat { width / height }
}

/// The fill rule needed for a compound glyph primitive.
public enum GlyphFillRule: String, CaseIterable, Sendable {
    case evenOdd = "evenodd"
    case nonZero = "nonzero"
}

/// One closed contour in a glyph primitive.
public struct GlyphContour: Equatable, Sendable {
    public let points: [GlyphPoint]

    public init(points: [GlyphPoint]) {
        self.points = points
    }
}

/// A semantic filled shape. The core is a compound even-odd ring; a nonzero
/// octal digit emits exactly one complete font arm outline.
public enum GlyphPrimitiveKind: String, CaseIterable, Sendable {
    case core
    case arm
}

/// One filled primitive in paint order.
public struct GlyphPrimitive: Equatable, Sendable {
    public let kind: GlyphPrimitiveKind
    public let fillRule: GlyphFillRule
    public let socketIndex: Int?
    public let digitIndex: Int?
    public let digit: UInt8?
    public let contours: [GlyphContour]
}

/// Fully resolved, reusable geometry for one MSB-first octal glyph.
public struct OctalGlyphPlan: Equatable, Sendable {
    public let grammarVersion: String
    public let geometryVersion: String
    public let specSHA256: String
    public let fontID: String
    public let fontVersion: String
    public let normalizedValue: String
    public let depth: Int
    public let frame: GlyphFrame
    public let primitives: [GlyphPrimitive]
}

public enum OctalGlyphError: Error, Equatable, LocalizedError {
    case invalidDepth(Int)
    case emptyValue
    case inputTooLong(length: Int, depth: Int)
    case invalidOctalByte(index: Int, byte: UInt8)
    case invalidLayout

    public var errorDescription: String? {
        switch self {
        case let .invalidDepth(depth):
            return "Glyph depth must be between \(GlyphSpec.minimumDigits) and \(GlyphSpec.maximumDigits), got \(depth)."
        case .emptyValue:
            return "Glyph value must contain at least one octal digit."
        case let .inputTooLong(length, depth):
            return "Glyph value has \(length) digits but depth is \(depth)."
        case let .invalidOctalByte(index, byte):
            return "Glyph byte \(index) must be ASCII octal 0 through 7, got \(byte)."
        case .invalidLayout:
            return "Glyph centre, scale, and rotation must be finite; scale must be positive."
        }
    }
}

/// Allocation-backed Swift value for the same strict octal grammar as the Rust core.
public struct OctalGlyph: Equatable, Sendable {
    public static let leftStroke = GlyphSpec.leftStroke
    public static let centreStroke = GlyphSpec.centreStroke
    public static let rightStroke = GlyphSpec.rightStroke

    public let depth: Int
    private let digits: [UInt8]

    /// Parses one-through-depth ASCII octal digits and left-pads short values.
    public init(_ octal: String, depth: Int = FractonicaGlyphMetadata.defaultDepth) throws {
        try Self.validateDepth(depth)
        let input = Array(octal.utf8)
        guard !input.isEmpty else { throw OctalGlyphError.emptyValue }
        guard input.count <= depth else {
            throw OctalGlyphError.inputTooLong(length: input.count, depth: depth)
        }
        for (index, byte) in input.enumerated() {
            guard (Character("0").asciiValue!...Character("7").asciiValue!).contains(byte) else {
                throw OctalGlyphError.invalidOctalByte(index: index, byte: byte)
            }
        }
        self.depth = depth
        self.digits = Array(repeating: 0, count: depth - input.count) + input.map { $0 - Character("0").asciiValue! }
    }

    public var normalizedValue: String {
        String(decoding: digits.map { $0 + Character("0").asciiValue! }, as: UTF8.self)
    }

    public func digit(at index: Int) -> UInt8? {
        digits.indices.contains(index) ? digits[index] : nil
    }

    /// Socket zero is the MSB; subsequent sockets walk from the LSB backward.
    public static func digitIndex(forSocket socketIndex: Int, depth: Int) throws -> Int {
        try validateDepth(depth)
        guard (0..<depth).contains(socketIndex) else {
            throw OctalGlyphError.invalidDepth(socketIndex)
        }
        return socketIndex == 0 ? 0 : depth - socketIndex
    }

    /// Returns the `1 | 2 | 4` stroke mask for a valid octal digit.
    public static func strokeMask(for digit: UInt8) -> UInt8? {
        digit < UInt8(GlyphSpec.radix) ? digit : nil
    }

    /// Builds compound-outline geometry with the supplied visual font. Positive
    /// rotation is clockwise in the positive-Y-down glyph plane.
    public func plan(
        center: GlyphPoint = GlyphPoint(x: 0, y: 0),
        radius: CGFloat = 1,
        rotationRadians: CGFloat = 0,
        font: GlyphFont = .default,
    ) throws -> OctalGlyphPlan {
        let layout = try GlyphLayout(center: center, radius: radius, rotationRadians: rotationRadians)
        let primitives = Self.buildPrimitives(depth: depth, digits: digits, layout: layout, font: font)
        let frame = Self.stableFrame(depth: depth, layout: layout, font: font)
        return OctalGlyphPlan(
            grammarVersion: font.grammarVersion,
            geometryVersion: font.geometryVersion,
            specSHA256: font.sourceSHA256 ?? GlyphSpec.grammarSHA256,
            fontID: font.id,
            fontVersion: font.fontVersion,
            normalizedValue: normalizedValue,
            depth: depth,
            frame: frame,
            primitives: primitives,
        )
    }

    private static func validateDepth(_ depth: Int) throws {
        guard (GlyphSpec.minimumDigits...GlyphSpec.maximumDigits).contains(depth) else {
            throw OctalGlyphError.invalidDepth(depth)
        }
    }

    private static func buildPrimitives(depth: Int, digits: [UInt8], layout: GlyphLayout, font: GlyphFont) -> [GlyphPrimitive] {
        let outer = makeCoreOuter(depth: depth, layout: layout, font: font)
        let hole = makeCoreHole(depth: depth, layout: layout, outer: outer, font: font)
        var primitives: [GlyphPrimitive] = [
            GlyphPrimitive(
                kind: .core,
                fillRule: .evenOdd,
                socketIndex: nil,
                digitIndex: nil,
                digit: nil,
                contours: [GlyphContour(points: outer), GlyphContour(points: hole)],
            ),
        ]

        for socketIndex in 0..<depth {
            let digitIndex = socketIndex == 0 ? 0 : depth - socketIndex
            let digit = digits[digitIndex]
            guard digit != 0 else { continue }
            let points = transformArm(depth: depth, socketIndex: socketIndex, digit: digit, layout: layout, font: font)
            guard points.count >= 3 else { continue }
            primitives.append(
                GlyphPrimitive(
                    kind: .arm,
                    fillRule: .nonZero,
                    socketIndex: socketIndex,
                    digitIndex: digitIndex,
                    digit: digit,
                    contours: [GlyphContour(points: points)],
                ),
            )
        }
        return primitives
    }

    private static func stableFrame(depth: Int, layout: GlyphLayout, font: GlyphFont) -> GlyphFrame {
        let outer = makeCoreOuter(depth: depth, layout: layout, font: font)
        let hole = makeCoreHole(depth: depth, layout: layout, outer: outer, font: font)
        var points = outer + hole
        for socketIndex in 0..<depth {
            for digit in 0..<GlyphSpec.radix {
                points += transformArm(depth: depth, socketIndex: socketIndex, digit: UInt8(digit), layout: layout, font: font)
            }
        }
        let minX = points.map(\.x).min() ?? layout.center.x
        let maxX = points.map(\.x).max() ?? layout.center.x
        let minY = points.map(\.y).min() ?? layout.center.y
        let maxY = points.map(\.y).max() ?? layout.center.y
        let grid = font.gridSize * layout.radius
        let padding = grid * font.paddingCells
        let halfWidth = (max(abs(minX - layout.center.x), abs(maxX - layout.center.x)) / grid).rounded(.up) * grid + padding
        let halfHeight = (max(abs(minY - layout.center.y), abs(maxY - layout.center.y)) / grid).rounded(.up) * grid + padding
        return GlyphFrame(
            x: layout.center.x - halfWidth,
            y: layout.center.y - halfHeight,
            width: halfWidth * 2,
            height: halfHeight * 2,
        )
    }

    private static func makeCoreOuter(depth: Int, layout: GlyphLayout, font: GlyphFont) -> [GlyphPoint] {
        if depth == font.legacyCoreOuterDepth {
            return font.legacyCoreOuter.map { transformGlobal($0, layout: layout) }
        }
        return (0..<depth).flatMap { socketIndex -> [GlyphPoint] in
            let socket = makeSocketFrame(depth: depth, socketIndex: socketIndex, layout: layout, font: font)
            return [
                socket.localToWorld(tangent: -socket.length / 2, outward: 0),
                socket.localToWorld(tangent: socket.length / 2, outward: 0),
            ]
        }
    }

    private static func makeCoreHole(depth: Int, layout: GlyphLayout, outer: [GlyphPoint], font: GlyphFont) -> [GlyphPoint] {
        if depth == font.legacyCoreHoleDepth {
            return font.legacyCoreHole.map { transformGlobal($0, layout: layout) }
        }
        return insetConvexPolygon(outer, thickness: font.insetThickness * layout.radius)
    }

    private static func transformArm(depth: Int, socketIndex: Int, digit: UInt8, layout: GlyphLayout, font: GlyphFont) -> [GlyphPoint] {
        guard let arm = font.arm(for: digit), arm.points.count >= 2 else { return [] }
        let socket = makeSocketFrame(depth: depth, socketIndex: socketIndex, layout: layout, font: font)
        return arm.points.enumerated().map { index, point in
            if index == 0 {
                return socket.chordStart ?? socket.localToWorld(tangent: -socket.length / 2, outward: 0)
            }
            if index + 1 == arm.points.count {
                return socket.chordEnd ?? socket.localToWorld(tangent: socket.length / 2, outward: 0)
            }
            return socket.localToWorld(tangent: point.x * layout.radius, outward: point.y * layout.radius)
        }
    }

    private static func makeSocketFrame(depth: Int, socketIndex: Int, layout: GlyphLayout, font: GlyphFont) -> GlyphSocketFrame {
        if depth == font.legacyCoreOuterDepth {
            let endpointIndex = socketIndex * 2
            let start = transformGlobal(font.legacyCoreOuter[endpointIndex], layout: layout)
            let end = transformGlobal(font.legacyCoreOuter[endpointIndex + 1], layout: layout)
            let center = GlyphPoint(x: (start.x + end.x) / 2, y: (start.y + end.y) / 2)
            let chord = GlyphPoint(x: end.x - start.x, y: end.y - start.y)
            let length = (chord.x * chord.x + chord.y * chord.y).squareRoot()
            let tangent = GlyphPoint(x: chord.x / length, y: chord.y / length)
            let clockwiseNormal = GlyphPoint(x: tangent.y, y: -tangent.x)
            let radial = GlyphPoint(x: center.x - layout.center.x, y: center.y - layout.center.y)
            let outward = dot(clockwiseNormal, radial) >= 0
                ? clockwiseNormal
                : scaled(clockwiseNormal, -1)
            return GlyphSocketFrame(
                center: center,
                tangent: tangent,
                outward: outward,
                length: length,
                chordStart: start,
                chordEnd: end,
            )
        }

        let angle = layout.rotationRadians + (2 * .pi * CGFloat(socketIndex) / CGFloat(depth))
        let tangent = GlyphPoint(x: cos(angle), y: sin(angle))
        // Positive socket indices rotate clockwise from the top arm. This is
        // the historic Fractonica orientation: at depth six, socket one is
        // the upper-right arm rather than the upper-left arm.
        let outward = GlyphPoint(x: sin(angle), y: -cos(angle))
        let center = add(layout.center, scaled(outward, font.coreRadius * layout.radius))
        return GlyphSocketFrame(
            center: center,
            tangent: tangent,
            outward: outward,
            length: font.socketWidth * layout.radius,
            chordStart: nil,
            chordEnd: nil,
        )
    }
}

private struct GlyphLayout {
    let center: GlyphPoint
    let radius: CGFloat
    let rotationRadians: CGFloat

    init(center: GlyphPoint, radius: CGFloat, rotationRadians: CGFloat) throws {
        guard center.x.isFinite, center.y.isFinite, radius.isFinite, radius > 0, rotationRadians.isFinite else {
            throw OctalGlyphError.invalidLayout
        }
        self.center = center
        self.radius = radius
        self.rotationRadians = rotationRadians
    }
}

private struct GlyphSocketFrame {
    let center: GlyphPoint
    let tangent: GlyphPoint
    let outward: GlyphPoint
    let length: CGFloat
    /// Exact transformed endpoints, present for the rounded legacy six-socket core.
    let chordStart: GlyphPoint?
    let chordEnd: GlyphPoint?

    func localToWorld(tangent tangentDistance: CGFloat, outward outwardDistance: CGFloat) -> GlyphPoint {
        add(add(center, scaled(tangent, tangentDistance)), scaled(outward, outwardDistance))
    }
}

private func transformGlobal(_ point: GlyphPoint, layout: GlyphLayout) -> GlyphPoint {
    let x = point.x * layout.radius
    let y = point.y * layout.radius
    let cosine = cos(layout.rotationRadians)
    let sine = sin(layout.rotationRadians)
    return GlyphPoint(
        x: layout.center.x + x * cosine - y * sine,
        y: layout.center.y + x * sine + y * cosine,
    )
}

private func insetConvexPolygon(_ points: [GlyphPoint], thickness: CGFloat) -> [GlyphPoint] {
    guard points.count >= 3, thickness > 0 else { return points }
    let inwardSign: CGFloat = signedArea(points) >= 0 ? 1 : -1
    let lines: [(point: GlyphPoint, direction: GlyphPoint)] = points.enumerated().map { index, point in
        let next = points[(index + 1) % points.count]
        let dx = next.x - point.x
        let dy = next.y - point.y
        let length = max((dx * dx + dy * dy).squareRoot(), 0.001)
        let normal = GlyphPoint(x: (-dy / length) * inwardSign, y: (dx / length) * inwardSign)
        return (point: add(point, scaled(normal, thickness)), direction: GlyphPoint(x: dx, y: dy))
    }
    return points.enumerated().map { index, point in
        let previous = lines[(index + lines.count - 1) % lines.count]
        let current = lines[index]
        return intersectLines(
            pointA: previous.point,
            directionA: previous.direction,
            pointB: current.point,
            directionB: current.direction,
        ) ?? point
    }
}

private func signedArea(_ points: [GlyphPoint]) -> CGFloat {
    points.enumerated().reduce(0) { area, item in
        let (index, point) = item
        let next = points[(index + 1) % points.count]
        return area + point.x * next.y - next.x * point.y
    }
}

private func intersectLines(
    pointA: GlyphPoint,
    directionA: GlyphPoint,
    pointB: GlyphPoint,
    directionB: GlyphPoint,
) -> GlyphPoint? {
    let cross = directionA.x * directionB.y - directionA.y * directionB.x
    guard abs(cross) >= 0.000_001 else { return nil }
    let delta = GlyphPoint(x: pointB.x - pointA.x, y: pointB.y - pointA.y)
    let t = (delta.x * directionB.y - delta.y * directionB.x) / cross
    return GlyphPoint(x: pointA.x + directionA.x * t, y: pointA.y + directionA.y * t)
}

private func add(_ lhs: GlyphPoint, _ rhs: GlyphPoint) -> GlyphPoint {
    GlyphPoint(x: lhs.x + rhs.x, y: lhs.y + rhs.y)
}

private func scaled(_ point: GlyphPoint, _ scalar: CGFloat) -> GlyphPoint {
    GlyphPoint(x: point.x * scalar, y: point.y * scalar)
}

private func dot(_ lhs: GlyphPoint, _ rhs: GlyphPoint) -> CGFloat {
    lhs.x * rhs.x + lhs.y * rhs.y
}
