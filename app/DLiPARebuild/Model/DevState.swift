import Foundation
import Security

/// A development-only window onto everything this app keeps outside its own
/// binary: keychain items, cookies, preferences, cached blobs.
///
/// It exists because of a specific dead end. `authenticate` answers 301, 204 and
/// 404 inside one session, and rolling the app back to earlier builds -- the one
/// that introduced demand paging, the one that introduced the pre-warm -- changes
/// nothing. Persistent state that outlives the binary is the only explanation
/// that survives a rollback, and this app has four of them: a keychain password,
/// a keychain probe marker, `HTTPCookieStorage.shared` (which on iOS is stored in
/// the keychain and is shared with the download session), the preferences file,
/// and the kbsync blobs under Caches.
///
/// So the question is not "which of these is wrong" but "what is actually in
/// them, and does what a request takes from them match what the endpoint
/// expects". That is answerable only by looking, which is what this type is for:
/// read everything, delete anything, and write a value into a keychain slot that
/// would otherwise only ever be written by a successful sign-in.
///
/// Values are shown in clear text, including the stored password and every
/// cookie. That is deliberate and time-limited: this is a development build whose
/// logs are pasted into issue reports by the person they belong to, and until the
/// release question is on the table, being able to see the state is worth more
/// than protecting it from himself. `docs/probes/` carries the note saying this
/// is to be removed before a release build is ever cut.
enum DevState {
    static let key = "com.a23bc.dliparebuild.devState"

    /// Off unless the diagnostics row says otherwise, and read live rather than
    /// at launch: the whole point is to turn it on and look, in the same run.
    /// Read-only here because the row writes the same key through `@AppStorage`.
    static var enabled: Bool {
        UserDefaults.standard.object(forKey: DevState.key) as? Bool ?? false
    }

    /// One keychain item, as the store describes it.
    struct Entry: Identifiable, Hashable {
        let id = UUID()
        let className: String
        let service: String
        let account: String
        let value: String
        /// Which query found it. An item written through the data-protection
        /// keychain is not visible to a query that does not ask for it, so the
        /// flag has to travel with the row or deleting it would silently fail.
        let dataProtection: Bool
    }

    /// Every item this app can reach, in both keychain shapes, for the two
    /// password classes.
    ///
    /// Two passes because `kSecUseDataProtectionKeychain` decides what a query
    /// can see. A single unflagged query would report only the classic items --
    /// which is exactly the kind of "it is empty" answer that sends a search in
    /// the wrong direction.
    static func keychainEntries() -> [Entry] {
        var found: [Entry] = []

        for dataProtection in [false, true] {
            found.append(contentsOf: query(kSecClassGenericPassword,
                                           genericLabel, dataProtection: dataProtection))
            found.append(contentsOf: query(kSecClassInternetPassword,
                                           internetLabel, dataProtection: dataProtection))
        }

        return found
    }

    static let genericLabel = "generic password"
    static let internetLabel = "internet password"

    private static func query(_ itemClass: CFString, _ label: String,
                              dataProtection: Bool) -> [Entry] {
        var request: [String: Any] = [
            kSecClass as String: itemClass,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
        ]

        if dataProtection {
            request[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
        }

        var result: CFTypeRef?

        guard SecItemCopyMatching(request as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }

        return items.compactMap { entry(from: $0, label: label, dataProtection: dataProtection) }
    }

    /// One keychain record read out of a query result.
    ///
    /// Its own function because the field-by-field `as?`-with-a-default shape is
    /// long enough to type-check slowly inline, and this project has already paid
    /// twice for guessing at that.
    private static func entry(from item: [String: Any], label: String,
                              dataProtection: Bool) -> Entry? {
        guard let account = item[kSecAttrAccount as String] as? String else { return nil }

        let service = item[kSecAttrService as String] as? String ?? "none"
        let stored = item[kSecValueData as String] as? Data

        return Entry(className: label,
                     service: service,
                     account: account,
                     value: describe(stored),
                     dataProtection: dataProtection)
    }

    /// Removes one row. Reports the OSStatus, because "deleted" and "there was
    /// nothing to delete" are different answers here, and a silent delete is how
    /// an item that a query could not see would keep hiding.
    @discardableResult
    static func delete(_ entry: Entry) -> OSStatus {
        SecItemDelete(lookup(for: entry) as CFDictionary)
    }

    /// Writes a value into an existing row, or creates it.
    ///
    /// The control this exists to provide: a password slot can be filled with a
    /// known-wrong value to see whether the 2034 auto-relogin path is what sends
    /// the authenticate request nobody asked for, or emptied to see the refusal.
    @discardableResult
    static func write(_ entry: Entry, value: String) -> OSStatus {
        let data = Data(value.utf8)
        let query = lookup(for: entry) as CFDictionary
        let update = [kSecValueData as String: data] as CFDictionary
        let status = SecItemUpdate(query, update)

        guard status == errSecItemNotFound else { return status }

        var attributes = lookup(for: entry)
        attributes[kSecValueData as String] = data

        return SecItemAdd(attributes as CFDictionary, nil)
    }

    private static func lookup(for entry: Entry) -> [String: Any] {
        var query: [String: Any] = [
            kSecAttrAccount as String: entry.account,
        ]

        if entry.service != "none" {
            query[kSecAttrService as String] = entry.service
        }

        query[kSecClass as String] = entry.className == DevState.internetLabel
            ? kSecClassInternetPassword : kSecClassGenericPassword

        if entry.dataProtection {
            query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
        }

        return query
    }

    // MARK: - The other three stores

    /// Every cookie the shared jar holds, value included.
    ///
    /// This one matters more than it looks. `AppStoreClient` turns automatic
    /// cookies off for its own session, but the file-transfer session in
    /// AppSession runs the default policy, and both are handed the same
    /// `HTTPCookieStorage.shared` -- which iOS stores in the keychain and which
    /// therefore survives a reinstall. A cookie from the account that was signed
    /// in before is exactly the kind of state that outlives a rollback.
    static func cookieEntries() -> [String] {
        guard let cookies = HTTPCookieStorage.shared.cookies, !cookies.isEmpty else { return [] }

        return cookies.map { describeCookie($0) }
    }

    /// One keychain row, spelled the same in the log and on the screen: the
    /// shape that found it first, because the same account can exist in both and
    /// only one query can see each.
    static func describeEntry(_ entry: Entry) -> String {
        let shape = entry.dataProtection ? "data-protection" : "classic"

        return "[" + entry.className + ", " + shape + "] service=" + entry.service
            + " account=" + entry.account + " value=" + entry.value
    }

    /// One cookie on one line, with the two fields that decide whether it is
    /// still the session it looks like: its path and its expiry.
    ///
    /// Built from locals rather than as one expression, because the chained form
    /// -- a `map` over an optional date inside a `+` chain inside a closure
    /// inside a `??` -- is the shape this project has watched the compiler time
    /// out on twice now.
    private static func describeCookie(_ cookie: HTTPCookie) -> String {
        var expiry = "session"

        if let date = cookie.expiresDate {
            expiry = ISO8601DateFormatter().string(from: date)
        }

        return cookie.domain + " " + cookie.name + "=" + cookie.value
            + " (path " + cookie.path + ", expires " + expiry + ")"
    }

    @discardableResult
    static func deleteAllCookies() -> Int {
        let all = HTTPCookieStorage.shared.cookies ?? []
        for cookie in all { HTTPCookieStorage.shared.deleteCookie(cookie) }
        return all.count
    }

    /// The app's own preferences, values included -- accounts with their tokens,
    /// the replayed cookie header, the six-byte hardware identity.
    static func preferenceEntries() -> [String] {
        UserDefaults.standard.dictionaryRepresentation().keys
            .filter { $0.hasPrefix("com.a23bc.dliparebuild") }
            .sorted()
            .map { describePreference($0) }
    }

    /// One preference, printed as what it is: the account list is a JSON blob,
    /// the cookie header a string, the tokens a dictionary.
    ///
    /// Its own function for the same reason as the cookie line -- four branches
    /// of `as?` over one `Any?` is not an expression to leave inside a `map`.
    private static func describePreference(_ key: String) -> String {
        let raw = UserDefaults.standard.object(forKey: key)

        if let data = raw as? Data { return key + " = " + describe(data, cap: 4096) }

        if let text = raw as? String { return key + " = " + text }

        if let values = raw as? [String: Any] {
            return key + " = dict " + values.keys.sorted().joined(separator: ", ")
        }

        let fallback = raw.map { String(describing: $0) } ?? "nil"

        return key + " = " + fallback
    }

    /// The kbsync blobs and the staged asset names under Caches.
    static func fileEntries() -> [String] {
        let folders = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)

        guard let root = folders.first?.appendingPathComponent("dlipa"),
              let names = try? FileManager.default.contentsOfDirectory(atPath: root.path) else {
            return ["caches/dlipa: none"]
        }

        return names.sorted().map { name in
            let attributes = try? FileManager.default.attributesOfItem(atPath: root.appendingPathComponent(name).path)
            let size = (attributes?[.size] as? NSNumber)?.int64Value ?? -1

            return name + " (" + String(size) + " bytes)"
        }
    }

    // MARK: - Request overrides

    static let endpointKey = "com.a23bc.dliparebuild.devAuthEndpoint"
    static let userAgentKey = "com.a23bc.dliparebuild.devUserAgent"
    static let authAttemptsKey = "com.a23bc.dliparebuild.devAuthAttempts"
    static let contentTypeKey = "com.a23bc.dliparebuild.devAuthContentType"

    /// A typed replacement for the authenticate endpoint, and for the
    /// `User-Agent` that goes with it.
    ///
    /// These exist because of what the wire log showed on 2026-11-09: the
    /// request is well-formed -- the six payload fields, the urlencoded content
    /// type, the signature over exactly those bytes, the trailing slash the
    /// reference client normalizes to -- and `buy.itunes.apple.com` answers it
    /// with an HTML 404, an HTML 301 **carrying no Location at all**, and an
    /// empty 204, eleven requests in a row, from `Server: Apple`. Those are not
    /// application answers. So the question moved from "what do we send" to
    /// "where is it answered", and that question is asked by trying other hosts:
    /// the pod the same account was served from on 2026-11-06
    /// (`p47-buy.itunes.apple.com/…?Pod=47&PRH=47`), that host without the
    /// routing query, the generic host with it.
    ///
    /// A typed field rather than a code change because each of those is a
    /// one-request experiment, and a build costs ten minutes of it.
    ///
    /// Nothing here bypasses the checks a request still has to pass: the string
    /// goes through `trustedEndpoint`, so it must be https on an Apple host, and
    /// the password still only goes to hosts matching that rule.
    static var endpointOverride: String? {
        nonempty(UserDefaults.standard.string(forKey: DevState.endpointKey))
    }

    static var userAgentOverride: String? {
        nonempty(UserDefaults.standard.string(forKey: DevState.userAgentKey))
    }

    /// A typed replacement for the authenticate request's `Content-Type`.
    ///
    /// This one is not a guess at where the endpoint moved. It is the single
    /// header on that request where the reference client and this app
    /// demonstrably differ: upstream sets `application/x-apple-plist`
    /// (`pkg/appstore/appstore_login.go:580`) while we send
    /// `application/x-www-form-urlencoded` over a plist body -- inherited from
    /// the original Objective-C client, and good enough that Apple has answered
    /// it with HTTP 200 more than once. Running the request the way the
    /// reference client runs it is a one-request experiment, and the answer
    /// shape changes with it: from this machine, the urlencoded form drew 404
    /// and 301 HTML while `x-apple-plist` drew an empty 204 every single time,
    /// three of three, with the same body and the same valid signature.
    ///
    /// A field rather than a code change because the shipping default should
    /// stay what has been observed to work, and the comparison wants one
    /// variable, not two builds.
    static var contentTypeOverride: String? {
        nonempty(UserDefaults.standard.string(forKey: DevState.contentTypeKey))
    }

    /// How many times one authentication request is sent, when a measurement
    /// asks for more than the shipping default.
    ///
    /// The default stays what the reference client does -- three, with 10s then
    /// 20s between them -- because that is the only comparison that means
    /// anything when the probe is read. What the probe is for is the size of
    /// the instability. On 2026-11-11, from one machine, about ninety signed
    /// and well-formed posts to the authentication path answered as an
    /// application exactly once, and those posts varied every candidate at
    /// once: three hosts, both content types, with and without the action
    /// signature, the test hardware identity and the device's own, with and
    /// without cookies -- and no response carried a `Set-Cookie` at all, so
    /// there was no session to be missing. The account in those posts did not
    /// exist, which is precisely why the same measurement has to be taken
    /// against one that does: three tries against a floor like that is not a
    /// policy, it is a coin flip, and a sign-in that gives up inside three
    /// tries cannot say whether a fourth would have been answered.
    ///
    /// Capped at twenty so a mistyped value cannot turn one sign-in into
    /// several minutes of traffic to Apple.
    static var authAttemptsOverride: Int? {
        guard let raw = UserDefaults.standard.string(forKey: DevState.authAttemptsKey),
              let value = Int(raw), value > 0, value <= 20 else { return nil }

        return value
    }

    /// An empty field means "no override", not "send an empty header".
    private static func nonempty(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }

        return value
    }

    /// Sets or clears one of the two overrides, and returns what is now in force.
    @discardableResult
    static func setOverride(_ value: String, forKey key: String) -> String {
        if value.isEmpty {
            UserDefaults.standard.removeObject(forKey: key)
            return "cleared"
        }

        UserDefaults.standard.set(value, forKey: key)

        return value
    }

    // MARK: - Writing a preference

    /// Puts a chosen value back into one of this app's own preferences, as raw
    /// bytes written from hex -- which is how `hardwareIdentity` is stored.
    ///
    /// This exists for one value. The device captures put a different
    /// `hardwareIdentity` on either side of the last sign-in that worked, and
    /// that key is the only persisted thing that reaches the authenticate body.
    /// The way to find out whether it is the variable is to write the old value
    /// back -- and the only two other ways to do that both change it again:
    /// reinstalling wipes the container, and Filza edits a file that `cfprefsd`
    /// may answer from its cache instead of from disk. Writing it from inside the
    /// process is the one route that cannot be a stale read.
    ///
    /// Returns false when the hex does not parse, rather than writing something
    /// shorter than six bytes, because `HardwareIdentity.current` treats a value
    /// that is not exactly six bytes as absent and mints a new one -- which would
    /// make the experiment look like it changed nothing.
    @discardableResult
    static func setPreferenceBytes(_ hex: String, forKey key: String) -> Bool {
        let digits = hex.filter { $0.isHexDigit }

        guard digits.count.isMultiple(of: 2), !digits.isEmpty else { return false }

        var bytes: [UInt8] = []
        var at = digits.startIndex

        while at < digits.endIndex {
            let next = digits.index(at, offsetBy: 2)

            guard let byte = UInt8(digits[at..<next], radix: 16) else { return false }

            bytes.append(byte)
            at = next
        }

        UserDefaults.standard.set(Data(bytes), forKey: key)

        return true
    }

    /// The identity the guest, the bag request and the authenticate body all use,
    /// spelled the way the log spells it.
    static func hardwareIdentityHex() -> String {
        guard let saved = UserDefaults.standard.data(forKey: HardwareIdentity.storageKey) else {
            return "none"
        }

        return saved.map { String(format: "%02X", $0) }.joined() + " (" + String(saved.count) + " bytes)"
    }

    // MARK: - The log

    /// One block, four sections, every value in clear text. Written through the
    /// log so it can be shared, and so a capture from the failing device carries
    /// the state along with the failure.
    static func dump() {
        AppLog.info("===== DEV STATE BEGIN =====", .app)

        let entries = keychainEntries()
        AppLog.info("keychain: " + String(entries.count) + " item(s)", .app)
        for entry in entries {
            AppLog.info("  " + describeEntry(entry), .app)
        }

        let cookies = cookieEntries()
        AppLog.info("cookies in the shared jar: " + String(cookies.count), .app)
        for cookie in cookies { AppLog.info("  " + cookie, .app) }

        let preferences = preferenceEntries()
        AppLog.info("preferences: " + String(preferences.count) + " key(s)", .app)
        for line in preferences { AppLog.info("  " + line, .app) }

        for line in fileEntries() { AppLog.info("  caches/dlipa " + line, .app) }

        // What the app will actually send, not only what it has stored: the two
        // overrides change the request itself, so a capture that does not name
        // them cannot be compared with another one.
        AppLog.info("overrides: endpoint " + (DevState.endpointOverride ?? "from the bag")
                    + ", user-agent " + (DevState.userAgentOverride ?? "built-in"), .app)

        AppLog.info("===== DEV STATE END =====", .app)
    }

    /// A byte string for the log: text where it is text, hex where it is not, and
    /// never more than `cap` of either.
    ///
    /// The cap is a parameter because the two callers want different things. A
    /// keychain value is compared by eye against what a request carried, and 512
    /// covers any token this app mints. A preference can be the whole stored
    /// account list -- JSON, in one value, with the three tokens inside it -- and
    /// cutting that at 96 characters deletes precisely the thing the dump was
    /// asked to show.
    private static func describe(_ data: Data?, cap: Int = 512) -> String {
        guard let data, !data.isEmpty else { return "empty" }

        if let text = String(data: data, encoding: .utf8),
           text.allSatisfy({ !$0.isNewline && $0.isASCII }) {
            return text.count > cap
                ? String(text.prefix(cap)) + "… (" + String(text.count) + " chars)"
                : text
        }

        return data.prefix(2 * cap).map { String(format: "%02x", $0) }.joined()
            + " (" + String(data.count) + " bytes)"
    }
}
