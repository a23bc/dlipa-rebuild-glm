import Foundation

/// One signed-in Apple ID, in the form it survives a relaunch.
///
/// The live `AppStoreClient.Account` is what a single sign-in returns; this is
/// the stored copy plus the bits the list needs. Keyed by DSID because that is
/// what Apple uses to identify the account -- the email can change, the DSID
/// does not.
struct StoreAccount: Codable, Identifiable, Equatable {
    var id: String { dsid }

    var email: String
    var firstName: String
    var lastName: String
    var dsid: String
    var storefront: String
    var pod: String

    /// The session token the download endpoint expects in `X-Token`.
    var passwordToken: String
    /// The 32 character clearToken from the same response.
    var clearToken: String
    /// The session credential: the value of the store's own X-Token cookie.
    var sessionToken: String

    /// What the row's title shows: the person's name, or the email when Apple
    /// did not return one.
    var displayName: String {
        let full = (firstName + " " + lastName).trimmingCharacters(in: .whitespaces)
        return full.isEmpty ? email : full
    }

    init(_ account: AppStoreClient.Account) {
        email = account.email
        firstName = account.firstName
        lastName = account.lastName
        dsid = account.dsid
        storefront = account.storefront
        pod = account.pod
        passwordToken = account.passwordToken
        clearToken = account.clearToken
        sessionToken = account.sessionToken
    }

    /// Back to the shape the client works with.
    func asAccount() -> AppStoreClient.Account {
        AppStoreClient.Account(email: email,
                               passwordToken: passwordToken,
                               clearToken: clearToken,
                               sessionToken: sessionToken,
                               dsid: dsid,
                               storefront: storefront,
                               pod: pod,
                               firstName: firstName,
                               lastName: lastName)
    }
}

/// Persists the account list so signing in survives a relaunch.
///
/// The store can hold more than one account and remembers which one is
/// selected. Stored in the app's own defaults: the token is a session
/// credential for the download endpoint, not the Apple ID password, which is
/// never kept.
enum AccountStore {
    private static let accountsKey = "com.a23bc.dliparebuild.accounts"
    private static let activeKey = "com.a23bc.dliparebuild.activeAccount"

    static func loadAccounts() -> [StoreAccount] {
        guard let data = UserDefaults.standard.data(forKey: accountsKey) else {
            return []
        }
        guard let decoded = try? JSONDecoder().decode([StoreAccount].self, from: data) else {
            AppLog.warn("stored account list could not be decoded; starting empty", .auth)
            return []
        }
        return decoded
    }

    static func save(_ accounts: [StoreAccount], active: String?) {
        guard let data = try? JSONEncoder().encode(accounts) else {
            AppLog.error("could not encode the account list", .auth)
            return
        }
        UserDefaults.standard.set(data, forKey: accountsKey)
        UserDefaults.standard.set(active, forKey: activeKey)
    }

    static func loadActiveID() -> String? {
        UserDefaults.standard.string(forKey: activeKey)
    }
}
