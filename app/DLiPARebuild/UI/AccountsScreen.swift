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
