#if canImport(SwiftUI)
import SwiftUI

/// SwiftUI Canvas adapter for a reusable canonical glyph plan.
///
/// The compound core is filled with the even-odd rule, so its aperture stays
/// transparent when no background is supplied and correctly reveals an
/// explicitly painted background when one is supplied.
@available(iOS 15.0, macOS 12.0, tvOS 15.0, watchOS 8.0, *)
public struct OctalGlyphView: View {
    public let plan: OctalGlyphPlan
    public let foreground: Color
    public let background: Color?

    public init(plan: OctalGlyphPlan, foreground: Color = .primary, background: Color? = nil) {
        self.plan = plan
        self.foreground = foreground
        self.background = background
    }

    public var body: some View {
        Canvas { context, size in
            let transform = GlyphCanvasTransform(frame: plan.frame, size: size)
            if let background {
                context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(background))
            }
            for primitive in plan.primitives {
                context.fill(
                    path(for: primitive, transform: transform),
                    with: .color(foreground),
                    style: FillStyle(eoFill: primitive.fillRule == .evenOdd),
                )
            }
        }
        .aspectRatio(plan.frame.aspectRatio, contentMode: .fit)
        .accessibilityLabel("Octal glyph \(plan.normalizedValue)")
    }
}

@available(iOS 15.0, macOS 12.0, tvOS 15.0, watchOS 8.0, *)
private struct GlyphCanvasTransform {
    let frame: GlyphFrame
    let scale: CGFloat
    let offsetX: CGFloat
    let offsetY: CGFloat

    init(frame: GlyphFrame, size: CGSize) {
        scale = min(size.width / frame.width, size.height / frame.height)
        offsetX = (size.width - frame.width * scale) / 2
        offsetY = (size.height - frame.height * scale) / 2
        self.frame = frame
    }

    func project(_ point: GlyphPoint) -> CGPoint {
        CGPoint(
            x: offsetX + (point.x - frame.x) * scale,
            y: offsetY + (point.y - frame.y) * scale,
        )
    }
}

@available(iOS 15.0, macOS 12.0, tvOS 15.0, watchOS 8.0, *)
private func path(for primitive: GlyphPrimitive, transform: GlyphCanvasTransform) -> Path {
    var path = Path()
    for contour in primitive.contours {
        guard let first = contour.points.first else { continue }
        path.move(to: transform.project(first))
        for point in contour.points.dropFirst() {
            path.addLine(to: transform.project(point))
        }
        path.closeSubpath()
    }
    return path
}
#endif
