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
    /// The oldest iOS the app runs on, e.g. "15.0".
    let minimumOsVersion: String?
    /// Download size in bytes, as a decimal string in the catalogue.
    let fileSizeBytes: String?

    var id: Int64 { trackId }

    /// "1.2.3" or, when the catalogue omitted it, nothing.
    var versionText: String { version ?? "" }

    private enum CodingKeys: String, CodingKey {
        case trackId, bundleId, trackName, version, price
        case artworkUrl60, artworkUrl100, sellerName, primaryGenreName
        case minimumOsVersion, fileSizeBytes
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
        minimumOsVersion = try? container.decode(String.self, forKey: .minimumOsVersion)
        // The catalogue sends this as a string in some stores and a number in
        // others, so both are accepted.
        if let text = try? container.decode(String.self, forKey: .fileSizeBytes) {
            fileSizeBytes = text
        } else if let number = try? container.decode(Int64.self, forKey: .fileSizeBytes) {
            fileSizeBytes = String(number)
        } else {
            fileSizeBytes = nil
        }
    }

    /// "v15.4.0 · iOS15.0 · 950.8 MB", the line under every row of the original
    /// app. Parts Apple did not return are dropped rather than left as gaps.
    var metaText: String {
        var parts: [String] = []
        if let version, !version.isEmpty {
            parts.append("v" + version)
        }
        if let minimumOsVersion, !minimumOsVersion.isEmpty {
            parts.append("iOS" + minimumOsVersion)
        }
        if let size = StoreApp.sizeText(fileSizeBytes) {
            parts.append(size)
        }
        return parts.joined(separator: " · ")
    }

    /// Bytes to MB or GB. Apple's figure is binary: 997245952 bytes is the
    /// 950.8 MB the App Store shows, so this divides by 1024 twice, not by
    /// 1000 twice.
    static func sizeText(_ raw: String?) -> String? {
        guard let raw, let bytes = Int64(raw), bytes > 0 else { return nil }
        let megabytes = Double(bytes) / (1024 * 1024)
        if megabytes >= 1024 {
            return String(format: "%.1f GB", megabytes / 1024)
        }
        return String(format: "%.1f MB", megabytes)
    }
}

/// The envelope the search endpoint returns.
struct StoreSearchResponse: Decodable {
    let resultCount: Int
    let results: [StoreApp]
}
