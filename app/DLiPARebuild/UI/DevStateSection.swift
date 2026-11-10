import SwiftUI

/// The developer-only window onto persisted state, on the Diagnostics tab.
///
/// Its own view rather than lines inside `DiagnosticsScreen.body`: the body is
/// already a `Form` with six toggles, and a row that carries a custom `Binding`
/// and a `ForEach` over a struct is the kind of expression this project has
/// watched the compiler time out on.
///
/// Everything here is temporary scaffolding for the sign-in investigation --
/// `docs/probes/developer-state.md` says when it comes out.
struct DevStateSection: View {
    @AppStorage(DevState.key) private var enabled = false
    @State private var items: [DevState.Entry] = []
    @State private var listed = false
    @State private var drafts: [UUID: String] = [:]
    @State private var email = ""
    @State private var secret = ""
    @State private var guid = ""
    @State private var endpointOverride = ""
    @State private var userAgentOverride = ""

    var body: some View {
        Section {
            Toggle("Developer state: log requests in clear text", isOn: $enabled)
                .onChange(of: enabled) { value in
                    // Say it at the moment it becomes true, because the thing
                    // this switch unlocks is a log that carries the Apple ID
                    // password, and the same button that shares the log is two
                    // rows below it.
                    guard value else { return }

                    AppLog.warn("developer state on: the log now carries credentials "
                                + "in clear text, including the sign-in password -- "
                                + "share it only to yourself", .app)
                }

            Button("Dump persisted state to the log") { DevState.dump() }

            Button("List keychain items") {
                items = DevState.keychainEntries()
                listed = true
                AppLog.info("dev state: " + String(items.count) + " keychain item(s)", .app)
            }

            Button("Delete every cookie", role: .destructive) {
                let count = DevState.deleteAllCookies()
                AppLog.warn("dev state: deleted " + String(count) + " cookie(s)", .app)
            }

            passwordRow

            identityRow

            overridesRow

            if listed {
                if items.isEmpty {
                    Text("no keychain items visible to this app")
                        .font(.system(.caption2, design: .monospaced))
                }

                ForEach(items) { item in row(item) }
            }
        } header: {
            Text("Developer state")
        } footer: {
            Text("Development scaffolding: values print in clear text and any row "
                 + "can be deleted or overwritten. Comes out before a release build "
                 + "is ever cut.")
                .font(.system(.caption2, design: .monospaced))
        }
    }

    /// The half of "control what we write" that editing existing rows cannot
    /// reach: a row that does not exist yet.
    ///
    /// The password slot is the one worth having, because a sign-in is the only
    /// thing that ever writes it and sign-in is exactly what is broken -- so
    /// without this, the 2034 refresh path cannot be driven at all. It goes
    /// through `Keychain.save` rather than a second write of its own, so what
    /// this produces is byte-for-byte what a successful sign-in would produce,
    /// including the accessibility attribute.
    private var passwordRow: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("write the password slot (the row a successful sign-in would create)")
                .font(.system(.caption2, design: .monospaced))

            HStack {
                TextField("apple id", text: $email)
                    .font(.system(.caption2, design: .monospaced))
                TextField("password", text: $secret)
                    .font(.system(.caption2, design: .monospaced))
                    .autocapitalization(.none)
                Button("Save") {
                    Keychain.save(secret, for: email)
                    AppLog.warn("dev state: asked to keep a password for that apple id", .app)
                    items = DevState.keychainEntries()
                    listed = true
                }
            }
        }
    }

    /// The one persisted value that reaches the authenticate body: the hardware
    /// identity, which is also what the bag request is addressed with and what
    /// the signer opens the guest with.
    ///
    /// Written from inside this process rather than edited on disk, because a
    /// file edit can be answered by `cfprefsd` from its cache, and reinstalling
    /// -- the other way to reach this value -- wipes it and mints a new one,
    /// which is the very thing under test.
    private var identityRow: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("hardware identity stored now: " + DevState.hardwareIdentityHex())
                .font(.system(.caption2, design: .monospaced))

            HStack {
                TextField("hex, 12 digits", text: $guid)
                    .font(.system(.caption2, design: .monospaced))
                Button("Set") {
                    // Anything that is not exactly six bytes is read as absent by
                    // HardwareIdentity.current, which then mints a new identity --
                    // so a malformed write would look like a write that changed
                    // nothing.
                    let written = DevState.setPreferenceBytes(guid,
                                                              forKey: HardwareIdentity.storageKey)

                    if written {
                        AppLog.warn("dev state: hardware identity written from hex; "
                                    + "restart the app so the signer picks it up", .app)
                    } else {
                        AppLog.error("dev state: refused to write that -- it is not an even "
                                     + "number of hex bytes", .app)
                    }
                }
            }
        }
    }

    /// The two fields that turn "where is this answered" into something that can
    /// be tried in one launch instead of one build per guess.
    ///
    /// An empty value clears the override, so the built-in behaviour is always
    /// one tap away and a capture never has to wonder which shape it was taken
    /// in: whatever is in force is printed on the row and named in the log on
    /// every request that uses it.
    private var overridesRow: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("overrides in force: " + overrideSummary)
                .font(.system(.caption2, design: .monospaced))

            HStack {
                TextField("authenticate endpoint", text: $endpointOverride)
                    .font(.system(.caption2, design: .monospaced))
                Button("Set") {
                    let value = DevState.setOverride(endpointOverride, forKey: DevState.endpointKey)

                    AppLog.warn("dev state: authenticate endpoint is now " + value, .auth)
                }
            }

            HStack {
                TextField("user agent", text: $userAgentOverride)
                    .font(.system(.caption2, design: .monospaced))
                Button("Set") {
                    let value = DevState.setOverride(userAgentOverride, forKey: DevState.userAgentKey)

                    AppLog.warn("dev state: authenticate user agent is now " + value, .auth)
                }
            }
        }
    }

    private var overrideSummary: String {
        let endpoint = DevState.endpointOverride ?? "from the bag"
        let agent = DevState.userAgentOverride ?? "built-in"

        return "endpoint " + endpoint + ", user-agent " + agent
    }

    /// One item, its stored value, and the two controls that make it a probe
    /// rather than a read-out: delete it, or put a chosen value in its place.
    private func row(_ item: DevState.Entry) -> some View {
        let draft = Binding<String>(
            get: { drafts[item.id] ?? item.value },
            set: { drafts[item.id] = $0 }
        )

        return VStack(alignment: .leading, spacing: 4) {
            Text(DevState.describeEntry(item))
                .font(.system(.caption2, design: .monospaced))

            HStack {
                TextField("value", text: draft)
                    .font(.system(.caption2, design: .monospaced))
                Button("Set") {
                    let status = DevState.write(item, value: draft.wrappedValue)
                    AppLog.warn("dev state: set " + item.service + "/" + item.account
                                + " status=" + String(status))
                }
                Button("Delete", role: .destructive) {
                    let status = DevState.delete(item)
                    AppLog.warn("dev state: delete " + item.service + "/" + item.account
                                + " status=" + String(status))
                    items = DevState.keychainEntries()
                }
            }
        }
    }
}
