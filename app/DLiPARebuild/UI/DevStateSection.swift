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

    var body: some View {
        Section {
            Toggle("Developer state: log requests in clear text", isOn: $enabled)

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

    /// One item, its stored value, and the two controls that make it a probe
    /// rather than a read-out: delete it, or put a chosen value in its place.
    private func row(_ item: DevState.Entry) -> some View {
        let draft = Binding<String>(
            get: { drafts[item.id] ?? item.value },
            set: { drafts[item.id] = $0 }
        )

        return VStack(alignment: .leading, spacing: 4) {
            Text(item.className + (item.dataProtection ? " [data-protection]" : " [classic]")
                 + " service=" + item.service + " account=" + item.account)
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
