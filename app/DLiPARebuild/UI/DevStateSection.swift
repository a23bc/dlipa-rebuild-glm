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
