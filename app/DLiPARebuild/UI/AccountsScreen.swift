import SwiftUI

/// The account screen: the sign-in flow the original DLiPA had, rebuilt in
/// SwiftUI. It owns the SAP signer for the session, because the signer is
/// stateful and re-creating it between the password step and the 2FA retry
/// would lose the SAP session.
struct AccountsScreen: View {
    @StateObject private var model = AccountsModel()
    @State private var showingSignIn = false

    var body: some View {
        NavigationView {
            Group {
                if let account = model.account {
                    List {
                        Section("Signed in") {
                            // LabeledContent is iOS 16+. The deployment
                            // target is 15.0, so the row is built by hand.
                            detailRow("Apple ID", account.email)
                            detailRow("DSID", account.dsid)
                            detailRow("Storefront", account.storefront)
                        }
                        Section {
                            Button("Sign out", role: .destructive) {
                                model.signOut()
                            }
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
                        showingSignIn = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .disabled(model.busy)
                    .accessibilityLabel("Add account")
                }
            }
            .sheet(isPresented: $showingSignIn) {
                SignInView(model: model)
            }
            .overlay {
                if model.busy {
                    ProgressView(model.status.isEmpty ? nil : model.status)
                        .padding()
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
            }
        }
    }

    private func detailRow(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
        }
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

    let hardware = HardwareIdentity.stable()

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
            _ = authenticate
        }

        guard let bag, let signer,
              let endpoint = bag.authenticateAccount else {
            throw StoreError.noBagEndpoint
        }

        status = "Signing in..."
        let result = try await client.authenticate(
            email: email, password: password, authCode: authCode,
            guid: hardware.guid, endpoint: endpoint, signer: signer)
        account = result
        status = ""
        AppLog.info("authenticated, DSID " + result.dsid, .auth)
    }

    func signOut() {
        signer?.close()
        signer = nil
        account = nil
        bag = nil
    }

    deinit {
        // sap_guest_free releases the emulator and the container. Without this
        // they wait for the next launch.
        signer?.close()
    }
}

// MARK: - Sign in sheet

struct SignInView: View {
    @ObservedObject var model: AccountsModel
    @Environment(.dismiss) private var dismiss

    @State private var email = ""
    @State private var password = ""
    @State private var code = ""
    @State private var needsCode = false
    @State private var errorText = ""

    var body: some View {
        NavigationView {
            Form {
                Section {
                    TextField("Apple ID", text: $email)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                        .autocorrectionDisabled()
                    SecureField("Password", text: $password)
                }
                if needsCode {
                    Section("Two-factor code") {
                        TextField("Code", text: $code)
                            .keyboardType(.numberPad)
                    }
                }
                if !errorText.isEmpty {
                    Section {
                        Text(errorText).foregroundColor(.red)
                    }
                }
                Section {
                    Button(needsCode ? "Submit code" : "Sign in") { submit() }
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
        .navigationViewStyle(.stack)
    }

    private func submit() {
        errorText = ""
        Task {
            do {
                try await model.signIn(email: email, password: password,
                                       authCode: needsCode ? code : nil)
                dismiss()
            } catch StoreError.twoFactorRequired {
                needsCode = true
                errorText = ""
            } catch {
                errorText = error.localizedDescription
                AppLog.error("sign-in failed: " + error.localizedDescription, .auth)
            }
        }
    }
}
