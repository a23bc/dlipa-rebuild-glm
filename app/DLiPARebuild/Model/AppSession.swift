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
        // Kept so a later session can refresh the token without asking again.
        Keychain.save(password, for: result.email)
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
        sessionBuild = nil
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
        sessionBuild = nil
        signer?.close()
        signer = nil
    }

    // MARK: - Shared with search and downloads

    /// The country whose catalogue to search: the active account's storefront,
    /// or the United States when nobody is signed in yet.
    var searchCountry: String {
        Storefront.countryCode(activeAccount?.storefront) ?? "US"
    }

    /// One machine authorisation per launch; see ensureSession.
    private var didAuthorizeMachine = false

    /// Makes sure the bag and the SAP session exist, then hands back what the
    /// download path needs. Throws when nobody is signed in.
    /// In-flight session build.
    ///
    /// ensureSession is called from several places that can overlap -- opening a
    /// version list while a download is starting, for instance -- and the body
    /// below suspends at its first await. Without this, both callers see signer
    /// == nil and each builds one, which means two emulators. iOS fits one: the
    /// second uc_open dies inside QEMU with exit(1), so the app vanishes with no
    /// crash report, and it happens fast enough that it looks like whichever
    /// button was pressed caused it.
    private var sessionBuild: Task<(StoreAccount, StoreBag, SAPSigner), Error>?

    private func ensureSession() async throws -> (StoreAccount, StoreBag, SAPSigner) {
        if let build = sessionBuild {
            return try await build.value
        }

        let build = Task { try await self.buildSession() }
        sessionBuild = build

        do {
            return try await build.value
        } catch {
            // Let the next attempt start over rather than replaying this failure.
            sessionBuild = nil
            throw error
        }
    }

    private func buildSession() async throws -> (StoreAccount, StoreBag, SAPSigner) {
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

        // authenticate proves the password and hands back a token, but it leaves
        // the store with no session: the cookie store comes back empty and every
        // download answers 2042 "Sign In to the iTunes Store". Binding the device
        // to the account is the step that is missing, so it runs once per launch
        // before the first download.
        // Printed before the call so the log says whether this build has the
        // code at all and whether the bag carries the endpoint -- an absent line
        // is otherwise indistinguishable from a build that predates it.
        // A local because AppLog's message is an escaping autoclosure, and a
        // bare property reference inside one needs explicit self.
        // authorizeMachine is not called, on purpose.
        //
        // The idea was that authenticate proves the password but leaves no store
        // session, so binding the device would supply the missing step. It has
        // now been tried with four token combinations on three different
        // identities and answered 2034 ExpiredPasswordToken every single time,
        // after a sign-in that had just succeeded. Upstream ipatool never calls
        // it at all.
        //
        // Worse, it may be the reason the download answers 2042. Each attempt
        // spends a token that authenticate just minted, and the sequence in the
        // log is always: sign-in 200, four authorise 2034, download 2042. The
        // download is then told to sign in again by a store that was signed in
        // seconds earlier.
        //
        // So this round simply does not call it, and the log says so, which is
        // also the control for the comparison: if 2042 persists without it, the
        // call was innocent and the missing piece is elsewhere.
        AppLog.info("ensureSession: skipping authorizeMachine (never accepted by "
                    + "Apple; endpoint " + (bag.authorizeMachine ?? "MISSING") + ")", .auth)

        guard let refreshed = activeAccount else { throw StoreError.noBagEndpoint }
        return (refreshed, bag, signer)
    }

    /// Gate 0 of the kbsync plan.
    ///
    /// Nothing depends on this yet. It exists to answer one question: can this
    /// device, running the x86-64 guest under TCI, produce a kbsync blob at all?
    /// If it cannot, the whole download plan stops here and that is a cheap
    /// answer. It reports the asset files it found, the byte count, the time it
    /// took and the first eight bytes, which for a real blob start 00 04.
    func diagnosticKBSync() async -> String {
        var report: [String] = []

        let assets = Bundle.main.bundleURL.appendingPathComponent("SapAssets")
        let names = (try? FileManager.default.contentsOfDirectory(atPath: assets.path)) ?? []
        report.append("assets in bundle: "
                      + (names.isEmpty ? "MISSING" : names.sorted().joined(separator: ", ")))

        do {
            if bag == nil { bag = try await client.fetchBag(guid: hardware.guid) }
            guard let bag else {
                report.append("no bag")
                return report.joined(separator: " · ")
            }
            if signer == nil {
                guard let setup = bag.signSapSetup, let cert = bag.signSapSetupCert else {
                    report.append("bag carries no SAP configuration")
                    return report.joined(separator: " · ")
                }
                signer = try SAPSigner(setupURL: setup, certURL: cert,
                                       version: bag.signSapVersion, hardware: hardware)
            }
            guard let signer else {
                report.append("no signer")
                return report.joined(separator: " · ")
            }
            guard let account = activeAccount else {
                report.append("not signed in")
                return report.joined(separator: " · ")
            }

            // The bridge reads the binaries from its own directory, so the
            // bundle copies have to be staged and BundleDir set first. This is
            // the same call the signer path uses; without it kbsync reports the
            // assets as missing even when they are in the bundle.
            if !AssetStaging.isReady {
                await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                    AssetStaging.stageIfNeeded(progress: nil) { error in
                        if let error {
                            report.append("staging failed: " + error.localizedDescription)
                        }
                        cont.resume()
                    }
                }
            }
            report.append("assets staged: " + String(AssetStaging.isReady))

            AppLog.info("kbsync gate: generating, this may take a while", .sap)
            let started = Date()
            let blob = try signer.kbsync(dsid: account.dsid)
            let seconds = Date().timeIntervalSince(started)
            let head = blob.prefix(8).map { String(format: "%02x", $0) }.joined()
            report.append("kbsync OK: " + String(blob.count) + " bytes in "
                          + String(format: "%.1f", seconds) + "s, head " + head)
        } catch {
            report.append("kbsync FAILED: " + error.localizedDescription)
        }

        for line in report { AppLog.info("kbsync gate: " + line, .sap) }
        return report.joined(separator: " · ")
    }

    /// Re-runs the sign-in with the stored password, just before authorising.
    private func signInBeforeAuthorising() async {
        guard let account = activeAccount else { return }
        guard let password = Keychain.password(for: account.email) else {
            AppLog.info("no stored credentials for a pre-authorisation sign-in", .auth)
            return
        }
        guard let bag, let signer, let endpoint = bag.authenticateAccount else {
            AppLog.warn("cannot refresh the store token: bag not ready", .auth)
            return
        }
        do {
            let fresh = try await client.authenticate(
                email: account.email, password: password, authCode: nil,
                guid: hardware.guid, endpoint: endpoint, signer: signer, attempt: 1)
            // A 2FA challenge can come back looking like a session, so the
            // clearToken has to actually be there before it replaces a real one.
            guard !fresh.clearToken.isEmpty else {
                AppLog.warn("pre-authorisation sign-in returned no clearToken; "
                            + "keeping the stored one", .auth)
                return
            }
            upsert(StoreAccount(fresh))
            activeID = fresh.dsid
            persist()
            AppLog.info("pre-authorisation sign-in ok, clearToken "
                        + String(fresh.clearToken.count) + " chars", .auth)
        } catch {
            AppLog.warn("pre-authorisation sign-in failed: "
                        + error.localizedDescription, .auth)
        }
    }

    /// The versions Apple still lists for an app, newest first.
    func versions(for app: StoreApp) async throws -> AppStoreClient.VersionList {
        let (account, bag, signer) = try await ensureSession()
        return try await client.listVersions(appId: String(app.trackId),
                                             guid: hardware.guid,
                                             account: account.asAccount(),
                                             bag: bag,
                                             signer: signer)
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
