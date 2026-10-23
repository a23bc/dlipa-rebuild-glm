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
    /// Which row is showing its identifiers. Only one at a time, and only via
    /// the disclosure control: tapping the row itself selects the account.
    @State private var expandedID: String?

    var body: some View {
        NavigationView {
            Group {
                if model.accounts.isEmpty {
                    EmptyStateView(
                        title: "No Accounts",
                        systemImage: "person.crop.circle",
                        detail: "Add an Apple ID to sign in. Credentials stay on this device."
                    )
                } else {
                    List {
                        ForEach(model.accounts) { account in
                            AccountRow(
                                account: account,
                                isActive: account.id == model.activeAccount?.id,
                                isExpanded: expandedID == account.id,
                                onSelect: { model.select(account.id) },
                                onToggleExpand: {
                                    expandedID = (expandedID == account.id) ? nil : account.id
                                })
                        }
                        .onDelete { model.remove(at: $0) }
                    }
                    .listStyle(.insetGrouped)
                }
            }
            .navigationTitle("Accounts")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    // A real button, not a bare Image: the previous version
                    // rendered the glyph and attached no action, so tapping it
                    // did nothing at all.
                    Button {
                        // Drop the previous account's HTTP session before
                        // somebody else's credentials go over it.
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

}

// MARK: - Account row

/// One account in the list.
///
/// The row is two hit targets: the body selects the account, and the control on
/// the right is the only thing that expands it. Keeping them as separate
/// buttons is what makes that split reliable inside a List -- a tap gesture on
/// the row would otherwise swallow the disclosure taps.
private struct AccountRow: View {
    let account: StoreAccount
    let isActive: Bool
    let isExpanded: Bool
    let onSelect: () -> Void
    let onToggleExpand: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 4) {
                Button(action: onSelect) {
                    HStack(alignment: .center, spacing: 8) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(account.displayName)
                                .foregroundColor(.primary)
                            Text(account.email)
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                        }
                        Spacer(minLength: 8)
                        if isActive {
                            Image(systemName: "checkmark")
                                .font(.body.weight(.semibold))
                                .foregroundColor(.accentColor)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)

                Button(action: onToggleExpand) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.forward")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(.secondary)
                        .frame(width: 32, height: 32)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(isExpanded ? "Hide account details" : "Show account details")
            }

            if isExpanded {
                VStack(alignment: .leading, spacing: 2) {
                    Text("DSID: " + account.dsid)
                    Text("Storefront: " + Storefront.label(account.storefront))
                }
                .font(.caption)
                .foregroundColor(.secondary)
                .padding(.leading, 2)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Model

@MainActor
final class AccountsModel: ObservableObject {
    /// Every signed-in Apple ID, in the order they were added.
    @Published private(set) var accounts: [StoreAccount] = []

    /// Which one the rest of the app acts as.
    @Published private(set) var activeID: String?

    @Published var busy = false
    @Published var status = ""

    private let client = AppStoreClient()
    private var signer: SAPSigner?
    private var bag: StoreBag?

    /// The account the app is currently acting as.
    var activeAccount: StoreAccount? {
        guard let activeID else { return accounts.first }
        return accounts.first { $0.id == activeID }
    }

    init() {
        // Restored on launch; without this the list was empty every time the
        // app started, whatever had been signed in before.
        accounts = AccountStore.loadAccounts()
        activeID = AccountStore.loadActiveID()
        if activeID == nil || !accounts.contains(where: { $0.id == activeID }) {
            activeID = accounts.first?.id
        }
    }

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
                  fetched.authenticateAccount != nil else {
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
        // Signing in again with the same Apple ID refreshes its stored copy
        // rather than adding a duplicate row: the DSID identifies the account,
        // and the token and storefront can change between sign-ins.
        upsert(StoreAccount(result))
        activeID = result.dsid
        persist()
        status = ""
        AppLog.info("authenticated, DSID " + result.dsid, .auth)
    }

    // MARK: - The list

    func select(_ id: String) {
        guard accounts.contains(where: { $0.id == id }) else { return }
        activeID = id
        persist()
    }

    func remove(at offsets: IndexSet) {
        let removed = offsets.map { accounts[$0].id }
        accounts.remove(atOffsets: offsets)
        if let activeID, removed.contains(activeID) {
            // The selected account went away; fall back to whatever is left.
            self.activeID = accounts.first?.id
        }
        persist()
    }

    private func upsert(_ account: StoreAccount) {
        if let index = accounts.firstIndex(where: { $0.id == account.id }) {
            accounts[index] = account
        } else {
            accounts.append(account)
        }
    }

    private func persist() {
        AccountStore.save(accounts, active: activeID)
    }

    /// Clears the per-account HTTP state before a different Apple ID is tried.
    ///
    /// The cookies and the pod address belong to the account that produced
    /// them, and sending them with somebody else's credentials is what made a
    /// second account fail the moment it was submitted.
    ///
    /// The SAP signer stays: it is a machine-level session, not an account
    /// one, and closing it would break the accounts already signed in.
    func beginNewSignIn() {
        client.resetSession()
        hardware = HardwareIdentity.current()
    }

    /// The identity changed under us: everything derived from it is stale.
    func handleIdentityChange() {
        signer?.close()
        signer = nil
        bag = nil
        client.resetSession()
        // The stored accounts were signed against the old device identity and
        // their tokens cannot be renewed with the new one.
        accounts = []
        activeID = nil
        persist()
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
