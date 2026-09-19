import AppKit
let destination = CommandLine.arguments[1]
let sizes = [(16, "icon_16x16"), (32, "icon_16x16@2x"), (32, "icon_32x32"), (64, "icon_32x32@2x"), (128, "icon_128x128"), (256, "icon_128x128@2x"), (256, "icon_256x256"), (512, "icon_256x256@2x"), (512, "icon_512x512"), (1024, "icon_512x512@2x")]
for (size, name) in sizes {
    let image = NSImage(size: NSSize(width: size, height: size))
    image.lockFocus()
    let transform = AffineTransform(scale: CGFloat(size) / 1024)
    (transform as NSAffineTransform).concat()
    NSColor(calibratedRed: 0.10, green: 0.14, blue: 0.13, alpha: 1).setFill()
    NSBezierPath(roundedRect: NSRect(x: 70, y: 70, width: 884, height: 884), xRadius: 205, yRadius: 205).fill()
    for y in [290, 460, 630] {
        NSColor(calibratedRed: 0.91, green: 0.93, blue: 0.89, alpha: 1).setFill()
        NSBezierPath(roundedRect: NSRect(x: 220, y: y, width: 584, height: 120), xRadius: 28, yRadius: 28).fill()
        NSColor(calibratedRed: 0.10, green: 0.14, blue: 0.13, alpha: 1).setFill()
        NSBezierPath(roundedRect: NSRect(x: 270, y: y + 48, width: 260, height: 24), xRadius: 12, yRadius: 12).fill()
        NSColor(calibratedRed: 0.23, green: 0.63, blue: 0.36, alpha: 1).setFill()
        NSBezierPath(ovalIn: NSRect(x: 710, y: y + 40, width: 40, height: 40)).fill()
    }
    image.unlockFocus()
    let rep = NSBitmapImageRep(data: image.tiffRepresentation!)!
    try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: destination).appendingPathComponent(name + ".png"))
}
