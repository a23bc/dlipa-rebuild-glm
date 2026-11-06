import Combine
import SwiftUI

/// The account screen: the sign-in flow the original DLiPA had, rebuilt in
/// SwiftUI. The SAP session lives in AppSession so that sign-in, search and the
/// download path all drive the same signer.
struct AccountsScreen: View {
    @ObservedObject private var model = AppSession.shared
    @State private var showingSignIn = false
    /// Non-nil once Apple has asked for a verification code. It drives the
    /// second modal; the password sheet is already gone by then.
    @State private var twoFactor: TwoFactorChallenge?
    /// Which row is showing its identifiers. Only one at a time, and only via
    /// the disclosure control: tapping the row itself selects the account.
    @State private var expanded: Set<String> = []

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
                                isExpanded: expanded.contains(account.id),
                                onSelect: { model.select(account.id) },
                                onToggleExpand: {
                                    // Deliberately not animated. The detail block is a dozen
                    // rows being inserted into a List, and animating that reads
                    // as a twitch rather than a transition: every row animates
                    // its own height at once. The chevron animates instead,
                    // which is the part that can move smoothly.
                    if expanded.contains(account.id) {
                    expanded.remove(account.id)
                } else {
                    expanded.insert(account.id)
                }
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
        // Deliberately no onDisappear teardown. The SAP signer is a
        // machine-level session shared by search and downloads, and closing it
        // from a view's lifetime meant that leaving the tab made every later
        // sign-in fail with an endpoint error: the bag stayed cached while the
        // signer was gone. It now lives for the process, which is what a
        // machine-level session is.
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
                // No .plain: that suppresses the system's cell highlight, which
                // is the press feedback the other rows get for free.

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
                    // The raw value goes with the label. The label is derived from the
                            // leading number, and two accounts with different regions can
                            // share it -- so the part that actually names the store is the
                            // tail, and hiding it lets the row claim a country Apple did
                            // not give.
                            Text("Storefront: " + Storefront.label(account.storefront)
                                 + (account.storefront.isEmpty ? "" : "  (" + account.storefront + ")"))
                }
                .font(.caption)
                .foregroundColor(.secondary)
                .padding(.leading, 2)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Sign in sheet

/// Collects the Apple ID and password only. When Apple answers with a 2FA
/// challenge the sheet closes and a separate modal takes over: a code field
/// that appears underneath the password fields is easy to miss, and it leaves
/// the password visible on screen while the user goes to fetch the code.
struct SignInView: View {
    @ObservedObject var model: AppSession

    /// Called instead of dismissing when Apple wants a verification code. The
    /// credentials are carried up so the second modal does not make the user
    /// type them again.
    let onTwoFactorRequired: (String, String) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var email = ""
    @State private var password = ""
    @State private var errorText = ""
    /// The notice that the handshake needs the signing components and nobody
    /// has agreed to fetch them. Shown instead of a refusal: this is the screen
    /// a first-time user reaches, and the launch question deliberately does not
    /// ask them (RootTabView) because nobody wants a 212 MB modal before they
    /// have chosen an account.
    @State private var needsAssetFetch = false
    @State private var fetchingAssets = false

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
                // Asked here rather than assumed: signing in opens the signer,
                // and the signer is the first thing that loads the binaries.
                if needsAssetFetch {
                    Section {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("DLiPA has to open the signing runtime before Apple "
                                 + "will look at these credentials, and this build does not "
                                 + "carry the four components it runs. Taking them from "
                                 + "Apple's restore image costs about 212 MB, once, and takes "
                                 + "around a minute on a phone.")
                                .font(.footnote)
                            Button(fetchingAssets ? "Fetching..." : "Fetch and sign in") {
                                fetchAssets()
                            }
                            .disabled(fetchingAssets)
                        }
                    }
                }
                Section {
                    Button("Sign in") { submit() }
                        .disabled(model.busy || email.isEmpty || password.isEmpty
                                  || fetchingAssets)
                }
            }
            .navigationTitle("Add Account")
            // Sheets default to an inline title, which puts the form right
            // under the bar. A large title gives the same gap Settings has.
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func submit() {
        errorText = ""

        // Asked before anything is sent. Attempting the handshake anyway would
        // only turn a question into an error line, and the bridge refuses
        // while nobody has agreed, so nothing here can spend the data by
        // accident.
        if AssetStaging.needsConsent() {
            needsAssetFetch = true

            return
        }

        signIn()
    }

    /// Permission granted inside the sheet: fetch, then carry on with the
    /// sign-in that was already asked for.
    private func fetchAssets() {
        fetchingAssets = true

        Task {
            do {
                _ = try await AssetStaging.resolveFromApple()
            } catch {
                fetchingAssets = false
                errorText = error.localizedDescription
                AppLog.error("asset fetch from the sign-in sheet failed: "
                                + error.localizedDescription, .assets)

                return
            }

            fetchingAssets = false
            needsAssetFetch = false
            signIn()
        }
    }

    /// One sign-in attempt, shared by the button and by the fetch that has to
    /// come first on a device without the binaries.
    private func signIn() {
        Task {
            do {
                try await model.signIn(email: email, password: password, authCode: nil)
                dismiss()
            } catch StoreError.twoFactorRequired {
                onTwoFactorRequired(email, password)
                dismiss()
            } catch StoreError.assetsNotFetched {
                // The launch question is deliberately not asked of a device
                // with no account, so this is where that person hears it.
                needsAssetFetch = true
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
    @ObservedObject var model: AppSession
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
            .navigationBarTitleDisplayMode(.large)
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
