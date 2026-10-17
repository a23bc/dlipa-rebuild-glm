import UIKit

/// Minimal shell implementing the original DLiPA workflow: sign in, search,
/// download. Built programmatically so there is no storyboard to keep in sync.
final class MainViewController: UIViewController {

    private let client = AppStoreClient()
    private var signer: SAPSigner?
    private var bag: StoreBag?
    private var account: AppStoreClient.Account?

    private let statusLabel = UILabel()
    private let emailField = UITextField()
    private let passwordField = UITextField()
    private let searchField = UITextField()
    private let signInButton = UIButton(type: .system)
    private let searchButton = UIButton(type: .system)
    private let logView = UITextView()
    private let shareLogButton = UIButton(type: .system)

    deinit {
        // Release the Go-side signer and its Unicorn engine when this controller
        // is torn down. Without this the engine and ~119 MB of guest memory wait
        // for Go's finalizer, which on iOS may not run promptly.
        signer?.close()
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        print("[DLiPA] MainViewController.viewDidLoad start")
        title = "DLiPA"
        view.backgroundColor = .systemBackground
        buildLayout()
        signInButton.isEnabled = false
        print("[DLiPA] MainViewController.viewDidLoad buildLayout done")

        // Staging the assets takes a while on a cold start. Report
        // progress and only allow sign-in once the bridge can sign.
        var lastBucket = -1
        AssetStaging.stageIfNeeded(progress: { fraction in
            let percent = Int((fraction * 100).rounded())
            let bucket = percent / 10
            if bucket != lastBucket {
                lastBucket = bucket
                AppLog.debug("staging " + String(percent) + "%", .assets)
            }
        }) { error in
            if let error {
                self.log("Assets failed to stage: " + error.localizedDescription)
            } else {
                let size = ByteCountFormatter.string(
                    fromByteCount: Int64(AssetStaging.totalBytes), countStyle: .file)
                self.log(NSLocalizedString("assets_ready", comment: "Assets staged")
                         + " (" + size + ")")
            }
            self.signInButton.isEnabled = true
        }
        log("Staging signing assets...")
        AppLog.onUpdate { entries in
            // The view controller owns logView, so the update has to be
            // re-armed after a rotation. Re-reading the buffer each time
            // keeps it simple and the cost is bounded at 500 entries.
            self.logView.text = entries.map { $0.plainText }.joined(separator: "\n")
            let bottom = NSMakeRange(self.logView.text.count - 1, 1)
            self.logView.scrollRangeToVisible(bottom)
        }
    }

    // MARK: Layout

    private func buildLayout() {
        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false

        statusLabel.text = NSLocalizedString("ap_signin_first", comment: "Status shown before sign-in")
        statusLabel.font = .preferredFont(forTextStyle: .headline)
        statusLabel.textAlignment = .center

        emailField.placeholder = NSLocalizedString("alert_signin_with_appleid", comment: "Apple ID field")
        emailField.borderStyle = .roundedRect
        emailField.autocapitalizationType = .none
        emailField.keyboardType = .emailAddress

        passwordField.placeholder = NSLocalizedString("alert_password_placeholder", comment: "Password field")
        passwordField.borderStyle = .roundedRect
        passwordField.isSecureTextEntry = true

        signInButton.setTitle(NSLocalizedString("alert_sign_in", comment: "Sign in button"), for: .normal)
        signInButton.addTarget(self, action: #selector(signIn), for: .touchUpInside)

        searchField.placeholder = NSLocalizedString("search_placeholder", comment: "Search field")
        searchField.borderStyle = .roundedRect
        searchField.autocapitalizationType = .none

        searchButton.setTitle(NSLocalizedString("search_title", comment: "Search button"), for: .normal)
        searchButton.addTarget(self, action: #selector(search), for: .touchUpInside)
        searchButton.isEnabled = false

        shareLogButton.setTitle(NSLocalizedString("log_share", comment: "Share the log"), for: .normal)
        shareLogButton.addTarget(self, action: #selector(shareLog), for: .touchUpInside)
        logView.isEditable = false
        logView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        logView.layer.borderWidth = 1
        logView.layer.borderColor = UIColor.separator.cgColor

        for view in [statusLabel, emailField, passwordField,
                     shareLogButton, signInButton, searchField, searchButton, logView] {
            stack.addArrangedSubview(view)
        }

        self.view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -16),
            logView.heightAnchor.constraint(equalToConstant: 260),
        ])
    }

    // MARK: Actions

    @objc private func signIn() {
        guard let email = emailField.text, !email.isEmpty,
              let password = passwordField.text, !password.isEmpty else {
            log(NSLocalizedString("ap_email_password_required", comment: "Validation error"))
            return
        }

        guard AssetStaging.isReady else {
            log("Waiting for the signing assets to finish staging...")
            AppLog.info("sign-in attempted before staging finished", .app)
            return
        }

        signInButton.isEnabled = false
        Task {
            await doSignIn(email: email, password: password, authCode: nil)
            await MainActor.run { self.signInButton.isEnabled = true }
        }
    }

    @objc private func search() {
        guard let term = searchField.text, !term.isEmpty else { return }
        Task { await doSearch(term: term) }
    }

    // MARK: Work

    private func doSignIn(email: String, password: String, authCode: String?) async {
        let hardware = HardwareIdentity.stable()
        log("Device GUID: \(hardware.guid)")

        do {
            let fetched = try await client.fetchBag(guid: hardware.guid)
            bag = fetched
            log("Bag: sign-sap-setup=\(fetched.signSapSetup ?? "none")")

            guard fetched.hasSAPConfiguration,
                  let setup = fetched.signSapSetup,
                  let cert = fetched.signSapSetupCert,
                  let authenticate = fetched.authenticateAccount else {
                log("Bag did not advertise the SAP endpoints; cannot sign in.")
                return
            }

            // Reuse the existing signer when the SAP handshake has already
            // succeeded for this session. The second stage (with 2FA) must
            // not create a new signer or the SAP session state is lost.
            if self.signer == nil {
                let newSigner = try SAPSigner(setupURL: setup,
                                               certURL: cert,
                                               version: fetched.signSapVersion,
                                               hardware: hardware)
                self.signer = newSigner
                log("SAP handshake complete; requests will be signed.")
            }
            guard let signer = self.signer else {
                log("Signer unavailable; cannot authenticate.")
                return
            }

            let newAccount = try await client.authenticate(
                email: email, password: password, authCode: authCode,
                guid: hardware.guid, endpoint: authenticate, signer: signer)
            account = newAccount

            statusLabel.text = "Signed in as \(newAccount.email)"
            searchButton.isEnabled = true
            log("Authenticated. DSID \(newAccount.dsid), storefront \(newAccount.storefront)")
        } catch StoreError.twoFactorRequired {
            // Apple requires a 2FA code. Prompt the user and retry with the
            // code appended to the password. The signer is reused so the SAP
            // session established above stays alive.
            log(NSLocalizedString("alert_2f_auth_message", comment: "2FA prompt"))
            let code = await promptFor2FACode()
            guard let code, !code.isEmpty else {
                log("Sign-in cancelled: no 2FA code entered.")
                return
            }
            await doSignIn(email: email, password: password, authCode: code)
        } catch let error as StoreError {
            // The alert text is short and localised; the detail goes to the log.
            AppLog.error("sign-in failed: " + error.localizedDescription + " [" + error.detail + "]", .auth)
            log("Sign-in failed: " + error.localizedDescription)
        } catch {
            AppLog.error("sign-in failed: " + error.localizedDescription, .auth)
            log("Sign-in failed: " + error.localizedDescription)
        }
    }

    /// Presents a 2FA code entry alert and resumes with the entered code.
    private func promptFor2FACode() async -> String? {
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async {
                let alert = UIAlertController(
                    title: NSLocalizedString("alert_2f_auth", comment: "2FA title"),
                    message: NSLocalizedString("alert_2f_auth_message", comment: "2FA message"),
                    preferredStyle: .alert)
                alert.addTextField { tf in
                    tf.placeholder = NSLocalizedString("alert_2f_auth_placeholder", comment: "2FA placeholder")
                    tf.keyboardType = .numberPad
                }
                alert.addAction(UIAlertAction(title: NSLocalizedString("alert_send", comment: "Send"), style: .default) { _ in
                    continuation.resume(returning: alert.textFields?.first?.text)
                })
                alert.addAction(UIAlertAction(title: NSLocalizedString("alert_reset", comment: "Cancel"), style: .cancel) { _ in
                    continuation.resume(returning: nil)
                })
                self.present(alert, animated: true)
            }
        }
    }

    private func doSearch(term: String) async {
        log("Searching for \(term)...")
        // iTunes search needs no signature; it is the public catalog API.
        guard let encoded = term.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
              let url = URL(string:
                "https://itunes.apple.com/search?entity=software,iPadSoftware&media=software&limit=25&term=\(encoded)")
        else { return }

        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            let results = json?["results"] as? [[String: Any]] ?? []
            log("Found \(results.count) result(s).")

            for item in results.prefix(10) {
                let name = item["trackName"] as? String ?? "?"
                let id = item["trackId"] as? Int ?? 0
                log("  \(name)  id=\(id)")
            }
        } catch {
            log("Search failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Share log

    /// Puts the in-app log in a share sheet, which is the only way a user
    /// can send it back without a cable attached to Console.app.
    @objc private func shareLog() {
        let text = AppLog.exportText()
        guard !text.isEmpty else {
            log(NSLocalizedString("log_empty", comment: "Nothing to share yet"))
            return
        }
        let sheet = UIActivityViewController(activityItems: [text], applicationActivities: nil)
        if let pop = sheet.popoverPresentationController {
            pop.sourceView = shareLogButton
            pop.sourceRect = shareLogButton.bounds
        }
        present(sheet, animated: true)
    }

    // MARK: Logging

    /// UI status line. The same text goes to AppLog so it lands in Console
    /// and in the shareable log, not just on screen.
    private func log(_ message: String, level: AppLog.Level = .info,
                    category: AppLog.Category = .app) {
        switch level {
        case .debug: AppLog.debug(message, category)
        case .info:  AppLog.info(message, category)
        case .warn:  AppLog.warn(message, category)
        case .error: AppLog.error(message, category)
        }
        statusLabel.text = message
    }
}
