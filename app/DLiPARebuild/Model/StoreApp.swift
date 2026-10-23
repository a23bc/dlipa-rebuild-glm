import Foundation

/// One row of iTunes search results.
///
/// The endpoint is the public catalogue, so the field set is Apple's and every
/// one of them can be missing. Only the id, bundle id and name are needed for
/// the row; the rest is shown when present.
struct StoreApp: Decodable, Identifiable, Equatable {
    let trackId: Int64
    let bundleId: String
    let trackName: String
    let version: String?
    let price: Double?
    let artworkUrl60: String?
    let artworkUrl100: String?
    let sellerName: String?
    let primaryGenreName: String?

    var id: Int64 { trackId }

    /// "1.2.3" or, when the catalogue omitted it, nothing.
    var versionText: String { version ?? "" }

    private enum CodingKeys: String, CodingKey {
        case trackId, bundleId, trackName, version, price
        case artworkUrl60, artworkUrl100, sellerName, primaryGenreName
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        // The id arrives as a number, but the catalogue has been seen to send
        // it as a string, so both are accepted.
        if let number = try? container.decode(Int64.self, forKey: .trackId) {
            trackId = number
        } else if let text = try? container.decode(String.self, forKey: .trackId),
                  let number = Int64(text) {
            trackId = number
        } else {
            throw DecodingError.dataCorruptedError(
                forKey: .trackId, in: container, debugDescription: "missing trackId")
        }
        bundleId = (try? container.decode(String.self, forKey: .bundleId)) ?? ""
        trackName = (try? container.decode(String.self, forKey: .trackName)) ?? bundleId
        version = try? container.decode(String.self, forKey: .version)
        price = try? container.decode(Double.self, forKey: .price)
        artworkUrl60 = try? container.decode(String.self, forKey: .artworkUrl60)
        artworkUrl100 = try? container.decode(String.self, forKey: .artworkUrl100)
        sellerName = try? container.decode(String.self, forKey: .sellerName)
        primaryGenreName = try? container.decode(String.self, forKey: .primaryGenreName)
    }
}

/// The envelope the search endpoint returns.
struct StoreSearchResponse: Decodable {
    let resultCount: Int
    let results: [StoreApp]
}
