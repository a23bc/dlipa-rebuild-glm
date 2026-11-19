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

/// The wait surface TrollStore uses: a system `UIAlertController` with a system
/// `UIActivityIndicatorView` in it. This is a real system alert, not a drawn card,
/// so it reads as one of the OS's own progress dialogs. Bound to a `Bool`: while
/// true the alert is presented, when it flips false the alert dismisses itself.
struct SystemWaitAlert: UIViewControllerRepresentable {
    let isPresented: Binding<Bool>
    let text: String

    func makeUIViewController(context: Context) -> UIViewController {
        UIViewController()
    }

    func updateUIViewController(_ controller: UIViewController, context: Context) {
        let shouldShow = isPresented.wrappedValue
        if shouldShow && context.coordinator.alert == nil {
            let alert = UIAlertController(title: text, message: nil, preferredStyle: .alert)
            let spinner = UIActivityIndicatorView(style: .medium)
            spinner.translatesAutoresizingMaskIntoConstraints = false
            spinner.startAnimating()
            alert.view.addSubview(spinner)
            NSLayoutConstraint.activate([
                spinner.centerXAnchor.constraint(equalTo: alert.view.centerXAnchor),
                spinner.bottomAnchor.constraint(equalTo: alert.view.bottomAnchor, constant: -12)
            ])
            context.coordinator.alert = alert
            controller.present(alert, animated: true)
        } else if !shouldShow && context.coordinator.alert != nil {
            controller.dismiss(animated: true)
            context.coordinator.alert = nil
        } else if let alert = context.coordinator.alert {
            alert.title = text
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator {
        var alert: UIAlertController?
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
