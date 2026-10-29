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
        }

        guard let bag, bag.hasSAPConfiguration, let endpoint = bag.authenticateAccount else {
            throw StoreError.noBagEndpoint
        }

        // The signer is created when it is missing, not when the bag arrives.
        // Those were the same condition once, and it made a failed handshake
        // permanent: the bag stayed cached, the signer stayed nil, and every
        // later attempt took the "bag is already here" branch and failed the
        // guard below.
        if signer == nil {
            status = "Running the SAP handshake..."
            do {
                _ = try await ensureSigner(bag)
            } catch {
                // Never keep a bag whose handshake failed: the next attempt has
                // to start from the endpoints again, not from the cached copy
                // that produced this failure.
                self.bag = nil
                throw error
            }
            AppLog.info("SAP handshake complete", .sap)
        }

        guard let signer else {
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
        // The password is not kept. It was written here for a token refresh
        // that was never built: the only reader was a private method with no
        // callers, so this put a long-lived credential in the keychain for
        // nothing -- and remove(at:) did not take it back out.
        status = ""
        AppLog.info("authenticated, DSID " + result.dsid, .auth)
    }

    // MARK: - The list

    func select(_ id: String) {
        guard accounts.contains(where: { $0.id == id }) else { return }
        // The session belongs to the account that produced it. Selecting a
        // different one used to leave that account's cookies in place, and the
        // next download replayed them alongside the new DSID.
        if id != activeID {
            client.resetSession()
        }
        activeID = id
        persist()
    }

    func remove(at offsets: IndexSet) {
        let removedAccounts = offsets.map { accounts[$0] }
        let removed = removedAccounts.map { $0.id }
        accounts.remove(atOffsets: offsets)
        if let activeID, removed.contains(activeID) {
            // The selected account went away; fall back to whatever is left.
            self.activeID = accounts.first?.id
        }
        // Whatever was captured belongs to an account that may no longer exist.
        client.resetSession()
        // And so do anything keyed by that account: a password an earlier build
        // wrote to the keychain, and the kbsync blob, which is keyed by dsid.
        for account in removedAccounts {
            Keychain.delete(for: account.email)
            signer?.invalidateKBSync(dsid: account.id)
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
    /// Opens the SAP runtime before anything else needs it.
    ///
    /// Where in the process lifetime the emulator gets created turns out to
    /// decide whether it can be created at all. Going straight from sign-in to
    /// the version list dies inside machine.Open with "Could not allocate
    /// dynamic translator buffer"; running kbsync first, which opens the same
    /// machine minutes earlier, makes every later step work. The machine is the
    /// same, the sizes are the same -- only the order differs.
    ///
    /// So it is created at launch, right after the assets finish staging, while
    /// the process is as small as it will ever be. Nothing here needs an
    /// account: a signer is bag plus hardware identity.
    func prewarmSAPRuntime() async {
        guard signer == nil else { return }

        do {
            if bag == nil {
                bag = try await client.fetchBag(guid: hardware.guid)
            }
            guard let bag,
                  bag.signSapSetup != nil,
                  bag.signSapSetupCert != nil else {
                AppLog.info("SAP pre-warm skipped: bag carries no SAP configuration", .sap)
                return
            }

            AppLog.info("pre-warming the SAP runtime", .sap)
            // The same entry the rest of the app uses, so a pre-warm that loses
            // the race with a sign-in cannot build a second emulator.
            _ = try await ensureSigner(bag)
            AppLog.info("SAP runtime pre-warmed", .sap)
        } catch {
            // Not fatal: whichever path needs it later will try again and report
            // the failure where it matters.
            AppLog.warn("SAP pre-warm failed: " + error.localizedDescription, .sap)
        }
    }

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

    /// In-flight signer creation.
    ///
    /// The handshake suspends now that it runs off the main actor, so two
    /// callers arriving together would both see signer == nil and build two
    /// emulators -- and iOS fits one: the second dies inside QEMU with a silent
    /// kill. Same shape as sessionBuild.
    private var signerBuild: Task<SAPSigner, Error>?

    /// Creates the signer if it is missing, and only then.
    ///
    /// A failure leaves signer == nil, so the next attempt starts over instead
    /// of inheriting a half-built session.
    private func ensureSigner(_ bag: StoreBag) async throws -> SAPSigner {
        if let signer {
            return signer
        }
        if let build = signerBuild {
            return try await build.value
        }
        guard let setup = bag.signSapSetup, let cert = bag.signSapSetupCert else {
            throw StoreError.noBagEndpoint
        }
        let version = bag.signSapVersion
        let identity = hardware
        let build = Task {
            try await SAPSigner.open(setupURL: setup, certURL: cert,
                                     version: version, hardware: identity)
        }
        signerBuild = build
        do {
            let created = try await build.value
            signer = created
            signerBuild = nil
            return created
        } catch {
            // Let the next caller try again rather than replaying this failure.
            signerBuild = nil
            throw error
        }
    }

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
            AppLog.info("opening the SAP session for downloads", .sap)
        }
        let signer = try await ensureSigner(bag)

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
    /// E1-a: whether the Store runtime can be built on the machine this session
/// already has, and how long each half takes.
///
/// Only runs when the Diagnostics button is pressed. It maps around 20 MB of
/// profile pages into the guest that kbsync also uses, so a session that has
/// already produced a blob should be restarted before trusting either number.
func diagnosticStoreSmoke() async -> String {
    do {
        if bag == nil { bag = try await client.fetchBag(guid: hardware.guid) }
        guard let bag else { return "no bag" }
        guard bag.signSapSetup != nil, bag.signSapSetupCert != nil else {
            return "bag carries no SAP configuration"
        }
        let signer = try await ensureSigner(bag)

        AppLog.info("store smoke: opening the Store runtime", .sap)

        // storeSmoke() runs the emulated guest synchronously, and this class is
        // @MainActor, so calling it directly holds the main thread for the whole
        // run. Once the runtime got past initWithBag the run grew long enough
        // that the screen stopped drawing entirely, which reads as a hang rather
        // than as work in progress.
        // An empty account still runs: the Store answers an anonymous request
        // with a 200 carrying a failure plist, which is worth seeing.
        let account = activeAccount
        let dsid = account?.dsid ?? ""
        let token = account?.passwordToken ?? ""
        let storefront = account?.storefront ?? ""

        let started = Date()
        let result = try await runOffMain {
            try signer.storeSmoke(dsid: dsid, token: token, storefront: storefront)
        }
        let seconds = Int(Date().timeIntervalSince(started))
        AppLog.info("store smoke: " + result + " (wall \(seconds)s)", .sap)

        return result
    } catch {
        AppLog.error("store smoke failed: " + error.localizedDescription, .sap)
        return "failed: " + error.localizedDescription
    }
}

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
            guard bag.signSapSetup != nil, bag.signSapSetupCert != nil else {
                report.append("bag carries no SAP configuration")
                return report.joined(separator: " · ")
            }
            let signer = try await ensureSigner(bag)
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
            // Same reason as the store smoke: kbsync runs the emulated guest and
            // this class is @MainActor, so the direct call freezes the screen.
            let blob = try await runOffMain { try signer.kbsync(dsid: account.dsid) }
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

/// Runs a blocking bridge call without holding the main actor.
///
/// Every gomobile entry point executes the emulated guest synchronously on the
/// calling thread. Called straight from a @MainActor method it freezes the UI
/// for the duration, and a run that takes a minute is indistinguishable from a
/// hang. This hands the call to a background queue and resumes when it returns.
private func runOffMain<T>(_ work: @escaping () throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                continuation.resume(returning: try work())
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
