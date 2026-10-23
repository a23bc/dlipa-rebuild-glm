import Foundation

/// Turns the `X-Set-Apple-Store-Front` header into something readable.
///
/// The header is not a country code. It looks like `143441-1,29`: the leading
/// number identifies which country's store the account belongs to, and the
/// trailing parts are internal to Apple (a store version and a language id).
/// Showing the raw string is why the account row was unreadable.
enum Storefront {

    /// The country a storefront id belongs to.
    ///
    /// Deliberately a short list of the ids that are well established rather
    /// than a guess at all of them: an unknown id is reported as a number
    /// instead of being labelled with a country it may not be.
    private static let regions: [String: String] = [
        "143441": "United States",
        "143442": "France",
        "143443": "Germany",
        "143444": "United Kingdom",
        "143445": "Austria",
        "143446": "Belgium",
        "143448": "Greece",
        "143449": "Ireland",
        "143450": "Italy",
        "143452": "Netherlands",
        "143453": "Portugal",
        "143454": "Spain",
        "143455": "Canada",
        "143456": "Sweden",
        "143457": "Norway",
        "143458": "Denmark",
        "143459": "Switzerland",
        "143460": "Australia",
        "143461": "New Zealand",
        "143462": "Japan",
        "143463": "Hong Kong",
        "143464": "Singapore",
        "143465": "China",
        "143466": "Taiwan",
        "143467": "Korea",
        "143468": "India",
        "143469": "Mexico",
        "143470": "Brazil",
        "143471": "Russia",
        "143472": "South Africa",
        "143473": "Saudi Arabia",
        "143474": "United Arab Emirates",
        "143475": "Turkey",
        "143476": "Poland",
    ]

    /// The leading id, or nil when the header is empty or malformed.
    static func regionID(_ raw: String?) -> String? {
        guard let raw, !raw.isEmpty else { return nil }
        let head = raw.split(separator: "-").first.map(String.init) ?? raw
        let digits = head.prefix { $0.isNumber }
        return digits.isEmpty ? nil : String(digits)
    }

    /// A readable label, e.g. "United States" or "Region 143999". Falls back to
    /// the raw header when there is nothing to parse, so a surprise format is
    /// shown rather than hidden.
    static func label(_ raw: String?) -> String {
        guard let id = regionID(raw) else {
            let trimmed = raw?.trimmingCharacters(in: .whitespaces) ?? ""
            return trimmed.isEmpty ? "Unknown" : trimmed
        }
        if let name = regions[id] {
            return name
        }
        return "Region " + id
    }

    /// The id on its own, for the detail line under the label.
    static func detail(_ raw: String?) -> String? {
        guard let id = regionID(raw) else { return nil }
        return "storefront " + id
    }
}
