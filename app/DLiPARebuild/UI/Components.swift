import SwiftUI
import UIKit

struct EmptyStateView: View {
    let title: String
    let systemImage: String
    var detail: String? = nil

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.system(size: 42, weight: .light))
                .foregroundColor(.secondary)
            Text(title)
                .font(.headline)
                .foregroundColor(.secondary)
            if let detail {
                Text(detail)
                    .font(.footnote)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// A system-styled wait HUD: the system activity indicator on a system material
/// background. Used for the search, licence and sign-in waits so they read as
/// one of the OS's own progress surfaces rather than a hand-drawn card.
struct SystemWaitHUD: View {
    let text: String
    var done = false

    var body: some View {
        VStack(spacing: 10) {
            ZStack {
                if done {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 24, weight: .semibold))
                        .foregroundColor(.green)
                        .transition(.scale.combined(with: .opacity))
                } else {
                    // UIKit's indicator is the actual system spinner; SwiftUI's
                    // ProgressView maps to it, but wrapping it keeps the intent
                    // explicit and the style consistent across iOS 15+.
                    ProgressView()
                        .progressViewStyle(.circular)
                }
            }
            .frame(height: 26)

            Text(text)
                .font(.subheadline)
                .foregroundColor(.primary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 18)
        .padding(.horizontal, 20)
        .frame(maxWidth: 240)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .animation(.spring(response: 0.32, dampingFraction: 0.62), value: done)
    }
}

/// Shares a file through the system sheet. Wrapped because SwiftUI has no
/// native equivalent that covers iOS 15.
struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
