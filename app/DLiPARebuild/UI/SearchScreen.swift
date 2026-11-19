import SwiftUI
import UIKit

/// What SearchScreen is presenting over itself.
///
/// One sheet drives all three. A view supports a single presentation of each
/// kind, so the previous chain of two `.sheet` modifiers held only one that
/// worked; a third would have made that worse.
/// What the screen is asking, if anything.
///
/// One alert drives both: a view supports a single presentation of each kind, and
/// two `.alert` modifiers on the same hierarchy is how the two sheets in this file
/// stopped working once.
enum SearchAlert: Identifiable {
    /// Permission to take a licence before a download starts.
    case takeLicence(StoreApp)
    /// The store refused, and its words are the only explanation there is.
    case licenceFailed(String)
    /// Permission to fetch the signing components. This build does not carry
    /// them, and the first signature needs them, so the alternative to asking
    /// is a download that quietly spends 212 MB of someone else's data.
    case fetchAssets(StoreApp)
    /// Apple refused, or the phone did. The bridge's own words, which carry the
    /// cost it reached before stopping.
    case fetchFailed(String)

    var id: String {
        switch self {
        case .takeLicence(let app):
            return "ask:" + String(app.trackId)
        case .licenceFailed(let message):
            return "failed:" + message
        case .fetchAssets(let app):
            return "assets:" + String(app.trackId)
        case .fetchFailed(let message):
            return "fetch-failed:" + message
        }
    }
}

private enum SearchSheet: Identifiable {
    case versions(StoreApp)
    case share(URL)

    var id: String {
        switch self {
        case .versions(let app):
            return "versions:" + String(app.trackId)
        case .share(let url):
            return "share:" + url.absoluteString
        }
    }
}

/// Search, and the menu every result opens.
struct SearchScreen: View {
    @StateObject private var model = SearchModel()

    /// The result whose action sheet is open.
    @State private var actionTarget: StoreApp?
    /// The sheet that is open, if any.
    @State private var sheet: SearchSheet?

    var body: some View {
        NavigationView {
            // The body is its own view so it can read the search state through
            // the environment; a view cannot see the isSearching value of the
            // .searchable modifier it applies itself.
            SearchBody(model: model) { app in actionTarget = app }
                .navigationTitle("Search")
                .searchable(text: $model.term, prompt: "App, Bundle ID, Link")
                .onSubmit(of: .search) { Task { await model.run() } }
                .onChange(of: model.term) { value in
                    // A cleared field goes back to the empty state instead of
                    // leaving the last results on screen.
                    if value.isEmpty { model.clear() }
                }
                .overlay {
                    // One card for both jobs: searching and taking a licence are
                    // the same shape of wait, and a second style would only make
                    // the screen noisier.
                    if let working = model.workingStatus {
                        WorkingCard(text: working, done: model.workingDone)
                    } else if model.busy {
                        WorkingCard(text: model.status.isEmpty ? "Working..." : model.status)
                    }
                }
                .actionSheet(item: $actionTarget) { app in
                    actionSheet(for: app)
                }
                .sheet(item: $sheet) { target in
                    sheetContent(for: target)
                }
                // Asked after the licence check and before anything is taken:
                // the alert carries the app so the two buttons know which one.
                .alert(item: $model.alert) { target in
                    alertContent(for: target)
                }
        }
        .navigationViewStyle(.stack)
    }

    // MARK: - The menu

    /// The questions this screen asks: permission before a licence is taken,
    /// permission before 212 MB is fetched from Apple, and the store's or
    /// Apple's own words when either refuses.
    ///
    /// Its own function for the same reason the action sheet is: the buttons'
    /// closures are checked here against Alert.Button instead of being inferred
    /// inside `body`.
    private func alertContent(for target: SearchAlert) -> Alert {
        switch target {
        case .takeLicence(let app):
            return Alert(title: Text("Get licence?"),
                         message: Text(app.trackName
                                       + " is not in this account's library yet. Taking the "
                                       + "free licence adds it, and the download starts "
                                       + "after that."),
                         primaryButton: .default(Text("Get and download")) {
                             Task { await model.grantLicence(app) }
                         },
                         secondaryButton: .cancel(Text("Cancel")) {
                             model.declineLicence()
                         })
        case .licenceFailed(let message):
            return Alert(title: Text("Licence"),
                         message: Text(message),
                         dismissButton: .default(Text("OK")))
        case .fetchAssets(let app):
            return Alert(title: Text("Fetch the signing components?"),
                         message: Text("This build does not carry the four Apple binaries. "
                                       + "Signing " + app.trackName + " needs them, so the app "
                                       + "takes them from Apple's macOS restore image: about "
                                       + "212 MB over roughly 450 requests, around a minute on "
                                       + "a phone. It happens once, and the download is queued "
                                       + "after it."),
                         primaryButton: .default(Text("Fetch and download")) {
                             Task { await model.grantAssets() }
                         },
                         secondaryButton: .cancel(Text("Cancel")) {
                             model.declineAssets()
                         })
        case .fetchFailed(let message):
            return Alert(title: Text("Signing components"),
                         message: Text(message),
                         dismissButton: .default(Text("OK")))
        }
    }

    /// The result menu.
    ///
    /// Built here rather than inline in `body`: that expression held a six
    /// button ActionSheet with a closure apiece, and the type checker gave up on
    /// it ("unable to type-check this expression in reasonable time") as soon as
    /// one more item joined the list.
    ///
    /// Both title lines go in the title. ActionSheet draws its message after a
    /// blank line, which is the extra empty row that was appearing above the
    /// buttons.
    private func actionSheet(for app: StoreApp) -> ActionSheet {
        ActionSheet(title: Text(app.trackName + "\n" + app.bundleId),
                    buttons: actions(for: app))
    }

    /// The button list on its own, with the array's type written down.
    ///
    /// The annotation is what does the work: with it each element is checked
    /// against one known type instead of the literal and its seven closures
    /// being inferred together.
    private func actions(for app: StoreApp) -> [ActionSheet.Button] {
        [
            .default(Text("Download")) {
                Task { await model.download(app, versionID: nil) }
            },
            .default(Text("Version history")) {
                sheet = .versions(app)
            },
            .default(Text("Get licence")) {
                Task { await model.acquireLicence(app) }
            },
            .default(Text("Copy bundle ID")) {
                UIPasteboard.general.string = app.bundleId
            },
            .default(Text("Copy app ID")) {
                UIPasteboard.general.string = String(app.trackId)
            },
            .default(Text("Share")) {
                if let url = URL(string: "https://apps.apple.com/app/id" + String(app.trackId)) {
                    sheet = .share(url)
                }
            },
            .cancel()
        ]
    }

    // MARK: - The sheets

    /// One switch for the three sheets, so `body` only names them.
    @ViewBuilder
    private func sheetContent(for target: SearchSheet) -> some View {
        switch target {
        case .versions(let app):
            VersionListView(app: app) { versionID in
                sheet = nil
                Task { await model.download(app, versionID: versionID) }
            }
        case .share(let url):
            ActivityView(activityItems: [url])
        }
    }
}

/// What the store said about one app's licence.
///
/// Its own view rather than an alert assembled in SearchScreen's body: the
/// inline `Binding(get:set:)` that drove that alert was part of what the type
/// checker could not finish, and a request needs somewhere to keep its result.
/// The waiting card, drawn over the screen while something takes a moment.
///
/// Opaque on purpose. A material let the results list read through the card, and
/// the one line that explains the wait competed with whatever was behind it --
/// which defeats the point of saying anything at all.
private struct WorkingCard: View {
    let text: String
    /// Turns the spinner into a tick. SwiftUI has no built-in success mark --
    /// `ProgressView` only draws a spinner or a bar -- so this is the usual
    /// stand-in: an SF Symbol and a spring.
    var done = false

    var body: some View {
        // Spinner above the line rather than beside it. Side by side, every
        // extra word made the card wider and it ended up a banner; a fixed width
        // keeps it a card and lets the line wrap instead.
        VStack(spacing: 10) {
            ZStack {
                if done {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 22, weight: .semibold))
                        .foregroundColor(.green)
                        .transition(.scale.combined(with: .opacity))
                } else {
                    ProgressView()
                }
            }
            // Fixed, so swapping one for the other does not move the line below.
            .frame(height: 24)

            Text(text)
                .font(.footnote)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(width: 190)
        .padding(.vertical, 18)
        .padding(.horizontal, 16)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Color(UIColor.secondarySystemGroupedBackground))
                .shadow(color: .black.opacity(0.12), radius: 10, y: 3)
        )
        .animation(.spring(response: 0.32, dampingFraction: 0.62), value: done)
    }
}

/// What sits under the search bar.
///
/// Kept separate from SearchScreen because \`isSearching\` is only populated
/// inside the view the searchable modifier is attached to.
private struct SearchBody: View {
    @ObservedObject var model: SearchModel
    let onSelect: (StoreApp) -> Void

    @Environment(\.isSearching) private var isSearching


    var body: some View {
        Group {
            if !model.results.isEmpty {
                resultsList
            } else if model.hasSearched {
                EmptyStateView(title: "No Results",
                               systemImage: "magnifyingglass",
                               detail: model.errorText)
            } else if model.history.isEmpty || !isSearching {
                // History only shows once the search field is active. Beside
                // keeping the launch screen empty, a long list here pushed the
                // search bar out of view on launch.
                EmptyStateView(
                    title: "Search",
                    systemImage: "magnifyingglass",
                    detail: "Look up an app by name, bundle identifier or App Store link.")
            } else {
                historyList
            }
        }
        // Results arriving means the user is done typing. Leaving the keyboard up
        // covers half of the list they just asked for.
        .onChange(of: model.results.count) { count in
            if count > 0 { hideKeyboard() }
        }
    }

    /// Puts the keyboard away without ending the search session.
    ///
    /// `dismissSearch` would do it in one call, but it also clears the field, and
    /// this screen keys its results off that text: the query vanished, the
    /// results were cleared, and a history tap looked like it did nothing.
    private func hideKeyboard() {
        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder),
                                        to: nil, from: nil, for: nil)
    }

    private var resultsList: some View {
        List {
            Section {
                ForEach(model.results) { app in
                    Button { onSelect(app) } label: {
                        SearchResultRow(app: app)
                    }
                }
                .onDelete { model.removeResult(at: $0) }
            } header: {
                // A grouped list upper-cases its headers by default; the
                // original shows "Results (38)".
                Text("Results (\(model.results.count))")
                    .textCase(nil)
            }
        }
        .listStyle(.insetGrouped)
    }

    private var historyList: some View {
        List {
            Section {
                ForEach(model.history, id: \.self) { entry in
                    Button {
                        model.useHistory(entry)
                        hideKeyboard()
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "clock.arrow.circlepath")
                                .foregroundColor(.secondary)
                            Text(entry)
                                .foregroundColor(.primary)
                            Spacer(minLength: 0)
                        }
                        .contentShape(Rectangle())
                    }
                }
                .onDelete { model.removeHistory(at: $0) }
            } header: {
                Text("Recent")
                    .textCase(nil)
            }
            Section {
                Button("Clear history") { model.clearHistory() }
            }
        }
        .listStyle(.insetGrouped)
    }
}

/// Wrapper so a plain URL can drive an item-based sheet.
struct ShareItem: Identifiable {
    let url: URL
    var id: String { url.absoluteString }
}

// MARK: - Row

/// Proportions follow the original app's search row: a 48 point icon, a 17
/// point semibold title that wraps to two lines, and one grey meta line under
/// it holding version, minimum iOS and download size.
private struct SearchResultRow: View {
    let app: StoreApp

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            ArtworkView(url: app.artworkUrl100 ?? app.artworkUrl60, size: 48)

            VStack(alignment: .leading, spacing: 4) {
                Text(app.trackName)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundColor(.primary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                if !app.metaText.isEmpty {
                    Text(app.metaText)
                        .font(.system(size: 13))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer(minLength: 0)
        }
        // The original's rows are about 75 points tall around a 48 point icon.
        .padding(.vertical, 12)
        .contentShape(Rectangle())
    }
}

/// Loads an icon. AsyncImage is iOS 15 and already caches through URLSession,
/// which is enough for a list that recycles rows.
private struct ArtworkView: View {
    let url: String?
    let size: CGFloat

    var body: some View {
        Group {
            if let url, let parsed = URL(string: url) {
                AsyncImage(url: parsed) { phase in
                    switch phase {
                    case .success(let image):
                        image.resizable().aspectRatio(contentMode: .fill)
                    default:
                        Rectangle().fill(Color.secondary.opacity(0.15))
                    }
                }
            } else {
                Rectangle().fill(Color.secondary.opacity(0.15))
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: size * 0.23, style: .continuous))
    }
}

// MARK: - Model

@MainActor
final class SearchModel: ObservableObject {
    @Published var term = ""
    @Published private(set) var results: [StoreApp] = []
    /// Recent search terms, newest first. Kept here rather than in the view so
    /// it survives the tab being rebuilt.
    @Published private(set) var history: [String] = []
    @Published private(set) var busy = false
    @Published private(set) var status = ""
    @Published private(set) var errorText: String?
    @Published private(set) var hasSearched = false
    /// The question on screen, if any.
    @Published var alert: SearchAlert?
    /// The line in the waiting card, for the two waits this screen owns: the
    /// licence check that precedes a download, and taking a licence outright.
    /// Search has its own (busy/status), because it was there first.
    @Published private(set) var workingStatus: String?
    /// Whether that card has finished its work, which swaps the spinner for a tick.
    @Published private(set) var workingDone = false

    private var lastQuery = ""
    private var licenceVersion: String?
    /// The download waiting behind the question about the signing components.
    private var pendingAssets: (app: StoreApp, versionID: String?)?

    private static let historyKey = "com.a23bc.dliparebuild.searchHistory"
    private static let historyLimit = 12

    init() {
        history = UserDefaults.standard.stringArray(forKey: Self.historyKey) ?? []
    }

    func record(_ term: String) {
        let trimmed = term.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        var next = history.filter { $0.caseInsensitiveCompare(trimmed) != .orderedSame }
        next.insert(trimmed, at: 0)
        if next.count > Self.historyLimit {
            next = Array(next.prefix(Self.historyLimit))
        }
        history = next
        UserDefaults.standard.set(next, forKey: Self.historyKey)
    }

    func useHistory(_ entry: String) {
        term = entry
        lastQuery = ""
        Task { await run() }
    }

    func clearHistory() {
        history = []
        UserDefaults.standard.removeObject(forKey: Self.historyKey)
    }

    func removeHistory(at offsets: IndexSet) {
        history.remove(atOffsets: offsets)
        UserDefaults.standard.set(history, forKey: Self.historyKey)
    }

    /// Drops a result from the current list. The catalogue is not modified, so
    /// the entry comes back on the next search.
    func removeResult(at offsets: IndexSet) {
        results.remove(atOffsets: offsets)
    }

    func clear() {
        results = []
        hasSearched = false
        errorText = nil
        lastQuery = ""
    }

    func run() async {
        let query = term.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return }
        guard query != lastQuery || results.isEmpty else { return }
        lastQuery = query
        busy = true
        status = "Searching..."
        errorText = nil
        defer { busy = false; status = "" }

        do {
            results = try await AppSession.shared.search(query)
            hasSearched = true
            record(query)
        } catch {
            results = []
            hasSearched = true
            errorText = error.localizedDescription
            AppLog.error("search failed: " + error.localizedDescription, .network)
        }
    }

    /// Checks the licence, then asks before taking one.
    ///
    /// The check is one plain request and answers in under a second; the licence
    /// itself is only taken when the person says yes, and the download is queued
    /// after that -- never before.
    func download(_ app: StoreApp, versionID: String?) async {
        // The question about the binaries comes before the licence check, not
        // after: that check answers by signing a request, and signing is what
        // needs them. Asking afterwards would either mean the data was already
        // spent, or mean a refusal the person cannot explain.
        if AssetStaging.needsConsent() {
            pendingAssets = (app, versionID)
            alert = .fetchAssets(app)

            return
        }

        // The card here is an indicator and nothing else: no tick, no hold, no
        // haptic. The check either lets the download start or turns into the
        // question, and either way the card has done its job the moment it ends.
        // `workingDone` is cleared because a licence taken a minute ago left it
        // set, and this card would otherwise open on someone else's tick.
        // The download's own classic answer carries the licence verdict; the
        // reference reads FailureTypeLicenseNotFound from it. A second classic
        // here only re-ran the Store proof and crashed the one guest.
        workingDone = false
        queueDownload(app, versionID: versionID)
    }

    /// Queues a download -- or asks first, if signing it would mean fetching
    /// 212 MB that is not on this device yet.
    ///
    /// `download` asks before the licence check and this is the second line at
    /// the point of handover, because the two are reached from different places:
    /// a licence taken from the alert comes back here without the first gate.
    private func queueDownload(_ app: StoreApp, versionID: String?) {
        if AssetStaging.needsConsent() {
            pendingAssets = (app, versionID)
            alert = .fetchAssets(app)

            return
        }

        DownloadManager.shared.start(app, versionID: versionID)
        status = "Queued " + app.trackName
    }

    /// Permission granted: fetch, then run the download that waited for it.
    func grantAssets() async {
        alert = nil

        guard let pending = pendingAssets else { return }
        pendingAssets = nil

        // A minute of nothing happening on screen reads as a hung app, so the
        // wait uses the card the licence wait already uses.
        workingStatus = "Fetching the signing components from Apple..."
        workingDone = false
        defer { workingStatus = nil }

        do {
            let report = try await AssetStaging.resolveFromApple()
            AppLog.info("signing components fetched before a download: " + report, .assets)
        } catch {
            AppLog.error("fetching the signing components failed: "
                            + error.localizedDescription, .assets)
            alert = .fetchFailed(error.localizedDescription)

            return
        }

        // Back in through the front door rather than straight at the manager:
        // the licence check is still owed, and it is the request that first
        // needed these bytes. The gate above cannot fire again -- the fetch is
        // either in the cache now, or allowed, and both answer "not missing".
        await download(pending.app, versionID: pending.versionID)
    }

    /// Permission refused. Nothing was fetched and nothing was queued.
    func declineAssets() {
        alert = nil
        pendingAssets = nil
        status = ""
    }

    /// Takes a licence without leaving the screen.
    func acquireLicence(_ app: StoreApp) async {
        _ = await takeLicence(app)
    }

    /// Permission granted: take the licence, then queue the same download.
    func grantLicence(_ app: StoreApp) async {
        alert = nil

        guard await takeLicence(app) else { return }

        // Through queueDownload rather than straight at the manager: the licence
        // can be the second question in a row, and the one about the signing
        // components still has to be asked.
        let versionID = licenceVersion
        licenceVersion = nil
        queueDownload(app, versionID: versionID)
    }

    /// Runs one licence request under the card, and says whether it worked.
    ///
    /// Both callers want the same thing -- the card, the tick, the store's words
    /// when it refuses -- and they used to spell it out separately, which is how
    /// one of them ended up writing the failure into `errorText`, where it belongs
    /// to search and no one would have seen it.
    private func takeLicence(_ app: StoreApp) async -> Bool {
        workingStatus = "Getting the licence for " + app.trackName + "..."
        workingDone = false
        let outcome = await AppSession.shared.acquireLicenceResult(for: app)

        guard outcome.ok else {
            workingStatus = nil
            alert = .licenceFailed(outcome.message)

            return false
        }

        // Felt before it is read, then held long enough to be read: the same
        // order a finished download uses.
        workingStatus = "Licence acquired"
        workingDone = true
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        try? await Task.sleep(nanoseconds: 1_200_000_000)
        workingStatus = nil
        workingDone = false

        return true
    }

    /// Permission refused. Nothing was requested from the store.
    func declineLicence() {
        alert = nil
        licenceVersion = nil
        status = ""
    }
}
