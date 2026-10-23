import Combine
import SwiftUI

/// The account screen: the sign-in flow the original DLiPA had, rebuilt in
/// SwiftUI. It owns the SAP signer for the session, because the signer is
/// stateful and re-creating it between the password step and the 2FA retry
/// would lose the SAP session.
struct AccountsScreen: View {
    @StateObject private var model = AccountsModel()
    @State private var showingSignIn = false
    /// Non-nil once Apple has asked for a verification code. It drives the
    /// second modal; the password sheet is already gone by then.
    @State private var twoFactor: TwoFactorChallenge?

    var body: some View {
        NavigationView {
            Group {
                if let account = model.account {
                    List {
                        Section("Signed in") {
                            // LabeledContent is iOS 16+. The deployment
                            // target is 15.0, so the row is built by hand.
                            detailRow("Apple ID", account.email, caption: "the account's email address")
                            // DSID is Apple's own numeric id for the account.
                            // It is not derived from the email and does not
                            // change when the email does, which is why it is
                            // worth showing: it is what the store keys
                            // purchases and downloads to.
                            detailRow("DSID", account.dsid,
                                      caption: "Apple's numeric account id; purchases belong to it")
                            // The header is a region id, not a country code.
                            detailRow("Storefront", Storefront.label(account.storefront),
                                      caption: Storefront.detail(account.storefront)
                                          ?? "which country's store this account uses")
                        }
                        Section {
                            Button("Sign out", role: .destructive) {
                                model.signOut()
                            }
                        } footer: {
                            Text("Only one account is kept at a time. Signing in again replaces this one.")
                        }
                    }
                } else {
                    EmptyStateView(
                        title: "No Accounts",
                        systemImage: "person.crop.circle",
                        detail: "Add an Apple ID to sign in. Credentials stay on this device."
                    )
                }
            }
            .navigationTitle("Accounts")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    // A real button, not a bare Image: the previous version
                    // rendered the glyph and attached no action, so tapping it
                    // did nothing at all.
                    Button {
                        // One account is held at a time, so this replaces the
                        // current one. The old HTTP session is dropped first;
                        // its cookies belong to whoever signed in last.
                        model.beginNewSignIn()
                        showingSignIn = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .disabled(model.busy)
                    .accessibilityLabel("Add account")
                }
            }
            .sheet(isPresented: $showingSignIn) {
                SignInView(model: model) { email, password in
                    // SwiftUI will not stack two sheets from the same
                    // presenter, so the code modal opens once the password
                    // sheet has finished going away.
                    showingSignIn = false
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                        twoFactor = TwoFactorChallenge(email: email, password: password)
                    }
                }
            }
            .sheet(item: $twoFactor, onDismiss: { twoFactor = nil }) { challenge in
                TwoFactorView(model: model, challenge: challenge)
            }
            .overlay {
                if model.busy {
                    ProgressView(model.status.isEmpty ? "Working..." : model.status)
                        .padding()
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
            }
        }
        .onReceive(NotificationCenter.default.publisher(
            for: HardwareIdentity.didChangeNotification)) { _ in
            // Settings replaced the device identity, so the live SAP session,
            // the cached bag and the signed-in account all describe a machine
            // that no longer exists.
            model.handleIdentityChange()
        }
        .onDisappear {
            // The tab stays alive for the session, but the emulator holds
            // tens of megabytes of guest memory. Release it when the screen
            // goes away rather than waiting for deallocation.
            model.shutdown()
        }
    }

    /// A title, a value right-aligned, and an optional caption underneath that
    /// says what the value actually means. The values on this screen are Apple's
    /// internal identifiers, so without the caption they read as noise.
    private func detailRow(_ title: String, _ value: String,
                           caption: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline) {
                Text(title)
                Spacer()
                Text(value)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.trailing)
            }
            if let caption {
                Text(caption)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Model

@MainActor
final class AccountsModel: ObservableObject {
    @Published var account: AppStoreClient.Account?
    @Published var busy = false
    @Published var status = ""

    private let client = AppStoreClient()
    private var signer: SAPSigner?
    private var bag: StoreBag?

    /// Refreshed when the identity is regenerated from Settings, so the next
    /// sign-in uses the new one rather than the value captured at init.
    private(set) var hardware = HardwareIdentity.current()

    /// One sign-in attempt. Apple answers the first password step with either
    /// an account or a 2FA challenge; the challenge case re-enters with the
    /// code appended, reusing the signer so the SAP session survives.
    func signIn(email: String, password: String, authCode: String? = nil) async throws {
        busy = true
        status = "Preparing the SAP session..."
        defer { busy = false }

        // The bag carries the SAP endpoints and the protocol version. It needs
        // no signature, so it is fetched before any guest code runs.
        if bag == nil {
            let fetched = try await client.fetchBag(guid: hardware.guid)
            bag = fetched
            AppLog.info("bag: sign-sap-version=" + String(fetched.signSapVersion), .sap)
            guard fetched.hasSAPConfiguration,
                  let setup = fetched.signSapSetup,
                  let cert = fetched.signSapSetupCert,
                  let authenticate = fetched.authenticateAccount else {
                throw StoreError.noBagEndpoint
            }
            status = "Running the SAP handshake..."
            // This is where the emulator starts. Throwing here means the
            // container did not load, the initialiser failed, or one of the
            // exchange legs did not reach its expected state.
            signer = try SAPSigner(setupURL: setup, certURL: cert,
                                   version: fetched.signSapVersion,
                                   hardware: hardware)
            AppLog.info("SAP handshake complete", .sap)
        }

        guard let bag, let signer,
              let endpoint = bag.authenticateAccount else {
            throw StoreError.noBagEndpoint
        }

        status = "Signing in..."
        AppLog.info("authenticate: posting to " + endpoint, .auth)
        // The signature is computed inside this call and it is the first time
        // the guest runs since the handshake. Log around it so a crash here
        // says which half of the request it died in.
        // A request carrying a verification code is Apple's second attempt:
        // the counter must advance with it.
        let result = try await client.authenticate(
            email: email, password: password, authCode: authCode,
            guid: hardware.guid, endpoint: endpoint, signer: signer,
            attempt: (authCode?.isEmpty == false) ? 2 : 1)
        account = result
        status = ""
        AppLog.info("authenticated, DSID " + result.dsid, .auth)
    }

    func signOut() {
        signer?.close()
        signer = nil
        account = nil
        bag = nil
        client.resetSession()
    }

    /// Clears the per-account state before a different Apple ID is tried.
    ///
    /// Only one account is held at a time, so signing in again replaces the
    /// current one. What must go is the HTTP session: the cookies and the pod
    /// address belong to the account that produced them, and sending them with
    /// somebody else's credentials is what made the second account fail the
    /// moment it was submitted.
    ///
    /// The SAP signer stays. It is a machine-level session, not an account one,
    /// and closing it here would break the still-signed-in account if the user
    /// backs out of the sheet.
    func beginNewSignIn() {
        client.resetSession()
        hardware = HardwareIdentity.current()
    }

    /// The identity changed under us: everything derived from it is stale.
    func handleIdentityChange() {
        signer?.close()
        signer = nil
        account = nil
        bag = nil
        client.resetSession()
        hardware = HardwareIdentity.current()
    }

    /// deinit cannot touch actor-isolated state, so the signer is released
    /// here instead. The view calls this when it disappears.
    func shutdown() {
        signer?.close()
        signer = nil
    }
}

// MARK: - Sign in sheet

/// Collects the Apple ID and password only. When Apple answers with a 2FA
/// challenge the sheet closes and a separate modal takes over: a code field
/// that appears underneath the password fields is easy to miss, and it leaves
/// the password visible on screen while the user goes to fetch the code.
struct SignInView: View {
    @ObservedObject var model: AccountsModel

    /// Called instead of dismissing when Apple wants a verification code. The
    /// credentials are carried up so the second modal does not make the user
    /// type them again.
    let onTwoFactorRequired: (String, String) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var email = ""
    @State private var password = ""
    @State private var errorText = ""

    var body: some View {
        NavigationView {
            Form {
                Section {
                    TextField("Apple ID", text: $email)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                        .disableAutocorrection(true)
                    SecureField("Password", text: $password)
                }
                if !errorText.isEmpty {
                    Section {
                        Text(errorText).foregroundColor(.red)
                    }
                }
                Section {
                    Button("Sign in") { submit() }
                        .disabled(model.busy || email.isEmpty || password.isEmpty)
                }
            }
            .navigationTitle("Add Account")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func submit() {
        errorText = ""
        Task {
            do {
                try await model.signIn(email: email, password: password, authCode: nil)
                dismiss()
            } catch StoreError.twoFactorRequired {
                onTwoFactorRequired(email, password)
                dismiss()
            } catch {
                errorText = error.localizedDescription
                AppLog.error("sign-in failed: " + error.localizedDescription, .auth)
            }
        }
    }
}

// MARK: - Two-factor modal

/// What the second modal needs: the credentials already accepted, so only the
/// code is missing.
struct TwoFactorChallenge: Identifiable {
    let id = UUID()
    let email: String
    let password: String
}

/// The verification-code modal. It reuses the model's existing SAP signer, so
/// the guest session started for the password step is not thrown away.
struct TwoFactorView: View {
    @ObservedObject var model: AccountsModel
    let challenge: TwoFactorChallenge

    @Environment(\.dismiss) private var dismiss

    @State private var code = ""
    @State private var errorText = ""

    var body: some View {
        NavigationView {
            Form {
                Section {
                    Text("Enter the verification code Apple sent to your other devices.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                    TextField("Verification code", text: $code)
                        .keyboardType(.numberPad)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                }
                if !errorText.isEmpty {
                    Section {
                        Text(errorText).foregroundColor(.red)
                    }
                }
                Section {
                    Button("Verify") { submit() }
                        .disabled(model.busy || code.isEmpty)
                }
            }
            .navigationTitle("Two-Factor")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func submit() {
        errorText = ""
        Task {
            do {
                try await model.signIn(email: challenge.email,
                                       password: challenge.password,
                                       authCode: code)
                dismiss()
            } catch StoreError.twoFactorRequired {
                // Apple asked again: the code was wrong or had expired.
                errorText = "Apple did not accept that code. Try the newest one."
            } catch {
                errorText = error.localizedDescription
                AppLog.error("2FA failed: " + error.localizedDescription, .auth)
            }
        }
    }
}
