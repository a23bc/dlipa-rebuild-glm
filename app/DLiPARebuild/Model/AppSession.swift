import Combine
import Foundation

// MARK: - Session

@MainActor
final class AppSession: ObservableObject {

    /// One session for the whole app. The SAP signer is expensive to build and
    /// is a machine-level session, so the search and download screens must
    /// share it rather than opening their own.
    static let shared = AppSession()

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

    // MARK: - Shared with search and downloads

    /// The country whose catalogue to search: the active account's storefront,
    /// or the United States when nobody is signed in yet.
    var searchCountry: String {
        Storefront.countryCode(activeAccount?.storefront) ?? "US"
    }

    /// Makes sure the bag and the SAP session exist, then hands back what the
    /// download path needs. Throws when nobody is signed in.
    private func ensureSession() async throws -> (StoreAccount, StoreBag, SAPSigner) {
        guard let account = activeAccount else {
            AppLog.error("download requested with no account signed in", .download)
            throw StoreError.noBagEndpoint
        }
        if bag == nil {
            bag = try await client.fetchBag(guid: hardware.guid)
        }
        guard let bag else { throw StoreError.noBagEndpoint }
        if signer == nil {
            guard let setup = bag.signSapSetup, let cert = bag.signSapSetupCert else {
                throw StoreError.noBagEndpoint
            }
            AppLog.info("opening the SAP session for downloads", .sap)
            signer = try SAPSigner(setupURL: setup, certURL: cert,
                                   version: bag.signSapVersion, hardware: hardware)
        }
        guard let signer else { throw StoreError.noBagEndpoint }
        return (account, bag, signer)
    }

    /// The versions Apple still lists for an app, newest first.
    func versions(for app: StoreApp) async throws -> AppStoreClient.VersionList {
        // No signer: the version request is unsigned, the way ipatool-rs sends
        // it, and it must not open the guest just to list versions.
        let (account, bag, _) = try await ensureSession()
        return try await client.listVersions(appId: String(app.trackId),
                                             guid: hardware.guid,
                                             account: account.asAccount(),
                                             bag: bag)
    }

    /// The signed URL for an app, or for one specific version of it.
    func downloadURL(for app: StoreApp,
                     externalVersionId: String?) async throws -> URL {
        let (account, bag, signer) = try await ensureSession()
        return try await client.requestDownload(appId: String(app.trackId),
                                                externalVersionId: externalVersionId,
                                                guid: hardware.guid,
                                                account: account.asAccount(),
                                                bag: bag,
                                                signer: signer)
    }

    /// Searches the catalogue of the active account's store.
    func search(_ term: String) async throws -> [StoreApp] {
        try await client.search(term: term, country: searchCountry)
    }

    /// Fetches the signed URL and writes the file next to the app's documents.
    ///
    /// Returns where it landed. The name carries the bundle id and the version
    /// so two downloads of the same app do not collide.
    func download(_ app: StoreApp,
                  externalVersionId: String?,
                  fileName: String,
                  progress: @escaping @Sendable (Int64, Int64) -> Void) async throws -> URL {
        let url = try await downloadURL(for: app, externalVersionId: externalVersionId)
        AppLog.info("downloading " + url.absoluteString, .download)

        var request = URLRequest(url: url)
        request.setValue(AppStoreClient.downloadUserAgent,
                         forHTTPHeaderField: "User-Agent")

        let configuration = URLSessionConfiguration.default
        let session = URLSession(configuration: configuration,
                                 delegate: DownloadProgressDelegate(progress: progress),
                                 delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        let (temporary, response) = try await session.download(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw StoreError.httpError((response as? HTTPURLResponse)?.statusCode ?? -1,
                                       "download failed")
        }

        let directory = try AppSession.downloadsDirectory()
        let destination = directory.appendingPathComponent(fileName)
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.moveItem(at: temporary, to: destination)
        AppLog.info("saved " + destination.lastPathComponent, .download)
        return destination
    }

    /// Where downloaded packages are kept, created on demand.
    static func downloadsDirectory() throws -> URL {
        let documents = try FileManager.default.url(for: .documentDirectory,
                                                    in: .userDomainMask,
                                                    appropriateFor: nil,
                                                    create: true)
        let directory = documents.appendingPathComponent("Downloads", isDirectory: true)
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(at: directory,
                                                    withIntermediateDirectories: true)
        }
        return directory
    }

    /// Every file already downloaded, newest first.
    static func downloadedFiles() -> [URL] {
        guard let directory = try? downloadsDirectory(),
              let names = try? FileManager.default.contentsOfDirectory(
                at: directory, includingPropertiesForKeys: [.contentModificationDateKey]) else {
            return []
        }
        return names.sorted {
            let a = (try? $0.resourceValues(forKeys: [.contentModificationDateKey])
                .contentModificationDate) ?? .distantPast
            let b = (try? $1.resourceValues(forKeys: [.contentModificationDateKey])
                .contentModificationDate) ?? .distantPast
            return a > b
        }
    }
}

/// Turns URLSession's byte counts into a fraction, for the progress overlay.
private final class DownloadProgressDelegate: NSObject, URLSessionDownloadDelegate {
    private let progress: @Sendable (Int64, Int64) -> Void

    init(progress: @escaping @Sendable (Int64, Int64) -> Void) {
        self.progress = progress
    }

    func urlSession(_ session: URLSession,
                    downloadTask: URLSessionDownloadTask,
                    didWriteData bytesWritten: Int64,
                    totalBytesWritten: Int64,
                    totalBytesExpectedToWrite: Int64) {
        progress(totalBytesWritten, totalBytesExpectedToWrite)
    }

    func urlSession(_ session: URLSession,
                    downloadTask: URLSessionDownloadTask,
                    didFinishDownloadingTo location: URL) {}
}
