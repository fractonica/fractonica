import XCTest
@testable import FractonicaGlyph

final class OctalGlyphTests: XCTestCase {
    func testMSBFirstSocketOrderAndPadding() throws {
        let glyph = try OctalGlyph("17", depth: 5)
        XCTAssertEqual(glyph.normalizedValue, "00017")
        XCTAssertEqual(try OctalGlyph.digitIndex(forSocket: 0, depth: 5), 0)
        XCTAssertEqual(try OctalGlyph.digitIndex(forSocket: 1, depth: 5), 4)
        XCTAssertEqual(try OctalGlyph.digitIndex(forSocket: 4, depth: 5), 1)
    }

    func testHexV2UsesCompoundCoreAndCompleteArmOutline() throws {
        let plan = try OctalGlyph("700", depth: 3).plan()
        XCTAssertEqual(plan.primitives.map(\.kind), [.core, .arm])

        let core = try XCTUnwrap(plan.primitives.first)
        XCTAssertEqual(core.fillRule, .evenOdd)
        XCTAssertEqual(core.contours.count, 2)
        XCTAssertEqual(core.contours[0].points.count, 6)
        XCTAssertEqual(core.contours[1].points.count, 6)

        let arm = try XCTUnwrap(plan.primitives.last)
        XCTAssertEqual(arm.fillRule, .nonZero)
        XCTAssertEqual(arm.socketIndex, 0)
        XCTAssertEqual(arm.digitIndex, 0)
        XCTAssertEqual(arm.digit, 7)
        XCTAssertEqual(arm.contours.count, 1)
        XCTAssertEqual(arm.contours[0].points.count, 8)
    }

    func testDepthSixUsesGeneratedLegacyCoreContours() throws {
        let plan = try OctalGlyph("0", depth: 6).plan()
        let core = try XCTUnwrap(plan.primitives.first)
        XCTAssertEqual(core.contours.count, 2)
        XCTAssertEqual(core.contours[0].points.count, 12)
        XCTAssertEqual(core.contours[0].points.first, GlyphPoint(x: -8, y: -41.57))
        XCTAssertEqual(core.contours[1].points.count, 7)
        XCTAssertEqual(core.contours[1].points.first, GlyphPoint(x: 8, y: 0))
    }

    func testDepthSixSocketOneUsesHistoricClockwiseOrientation() throws {
        // The LSB is rendered at socket one for a six-digit glyph. Its first
        // arm point is the socket chord's left endpoint.
        let plan = try OctalGlyph("000007", depth: 6).plan()
        let arm = try XCTUnwrap(plan.primitives.first(where: { $0.kind == .arm }))
        let start = try XCTUnwrap(arm.contours.first?.points.first)
        XCTAssertEqual(arm.socketIndex, 1)
        XCTAssertEqual(start, GlyphPoint(x: 32, y: -27.71))
    }

    func testFrameDoesNotDependOnValueAndUsesHexV2Metadata() throws {
        let zero = try OctalGlyph("0", depth: 5).plan()
        let all = try OctalGlyph("77777", depth: 5).plan()
        XCTAssertEqual(zero.frame, all.frame)
        XCTAssertEqual(FractonicaGlyphMetadata.grammarVersion, "1.0.0")
        XCTAssertEqual(FractonicaGlyphMetadata.geometryVersion, "2.1.0")
        XCTAssertEqual(FractonicaGlyphMetadata.fontID, "fractonica-hex-v2")
        XCTAssertEqual(all.geometryVersion, "2.1.0")
        XCTAssertEqual(all.fontVersion, "1.0.0")
    }

    func testCustomFontChangesOnlyVisualGeometryAndPlanMetadata() throws {
        let base = GlyphFont.default
        let custom = try GlyphFont(
            id: "example-outline",
            name: "Example outline",
            fontVersion: "0.1.0",
            geometryVersion: "example-geometry-1",
            grammarVersion: base.grammarVersion,
            sourceSHA256: String(repeating: "a", count: 64),
            units: base.units,
            armsCoordinateMode: base.armsCoordinateMode,
            socketWidth: base.socketWidth,
            coreRadius: 80,
            insetThickness: base.insetThickness,
            gridSize: base.gridSize,
            paddingCells: base.paddingCells,
            legacyCoreOuterDepth: base.legacyCoreOuterDepth,
            legacyCoreOuter: base.legacyCoreOuter,
            legacyCoreHoleDepth: base.legacyCoreHoleDepth,
            legacyCoreHole: base.legacyCoreHole,
            arms: base.arms,
        )

        let plan = try OctalGlyph("700", depth: 3).plan(font: custom)
        let core = try XCTUnwrap(plan.primitives.first)
        XCTAssertEqual(plan.fontID, "example-outline")
        XCTAssertEqual(plan.fontVersion, "0.1.0")
        XCTAssertEqual(plan.geometryVersion, "example-geometry-1")
        XCTAssertEqual(plan.specSHA256, String(repeating: "a", count: 64))
        XCTAssertEqual(core.contours[0].points.first, GlyphPoint(x: -8, y: -80))
        XCTAssertEqual(OctalGlyph.strokeMask(for: 7), 7)
    }

    func testBinaryStrokeGrammarRemainsSemantic() {
        XCTAssertEqual(OctalGlyph.strokeMask(for: 1), OctalGlyph.leftStroke)
        XCTAssertEqual(OctalGlyph.strokeMask(for: 2), OctalGlyph.centreStroke)
        XCTAssertEqual(OctalGlyph.strokeMask(for: 4), OctalGlyph.rightStroke)
        XCTAssertEqual(OctalGlyph.strokeMask(for: 7), 7)
        XCTAssertNil(OctalGlyph.strokeMask(for: 8))
    }
}
