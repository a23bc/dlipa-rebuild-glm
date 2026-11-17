import Foundation

/// Upstream ipatool's fallback when `volumeStoreDownloadProduct` answers 200
/// with no items: the bag's `redownloadProduct` and `updateProduct` endpoints,
/// in that order (`appstore_download_product.go:77-139`).
///
/// The classic request is now authenticated by the SP proof, so its empty
/// songList is the "no items" case rather than a failure. This file is kept
/// separate because AppStoreClient.swift sits close to the file-length floor.
extension AppStoreClient {
    func redownloadPackageURL(session: URLSession,
                              appId: String,
                              externalVersionId: String?,
                              guid: String,
                              account: Account,
                              bag: StoreBag) async throws -> URL? {
        // Upstream uses `appExtVrsId` on both recovery endpoints; the classic
        // volume store uses `externalVersionId` (`downloadVersionKeyRedownload`
        // vs `downloadVersionKeyVolumeStore`, appstore_download_product.go:19-20).
        let endpoints: [(label: String, endpoint: String?)] = [
            ("redownload", bag.redownloadProduct),
            ("update", bag.updateProduct),
        ]

        for candidate in endpoints {
            guard let endpoint = candidate.endpoint, !endpoint.isEmpty else { continue }

            guard var components = URLComponents(
                url: try Self.trustedEndpoint(endpoint), resolvingAgainstBaseURL: false) else {
                continue
            }
            components.queryItems = [URLQueryItem(name: "guid", value: guid)]
            guard let url = components.url else { continue }

            var payload: [String: Any] = [
                "creditDisplay": "",
                "guid": guid,
                "salableAdamId": Int64(appId) ?? 0,
                "serialNumber": "0",
            ]
            if let externalVersionId {
                payload["appExtVrsId"] = externalVersionId
            }

            let body = try PropertyListSerialization.data(
                fromPropertyList: payload, format: .xml, options: 0)

            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
            request.setValue(Self.nativeUserAgent, forHTTPHeaderField: "User-Agent")
            request.setValue(account.dsid, forHTTPHeaderField: "iCloud-DSID")
            request.setValue(account.dsid, forHTTPHeaderField: "X-Dsid")
            if !account.passwordToken.isEmpty {
                request.setValue(account.passwordToken, forHTTPHeaderField: "X-Token")
            }
            if !account.storefront.isEmpty {
                request.setValue(account.storefront, forHTTPHeaderField: "X-Apple-Store-Front")
            }

            // Upstream mints a proof against each request URL before sending
            // (appstore_download_product.go:272). Reuse that shape here rather
            // than the SP proof from the volume store answer.
            let proof = try AnisetteIdentity.storeProof(endpoint: url.absoluteString, guid: guid)
            for (key, value) in proof {
                request.setValue(value, forHTTPHeaderField: key)
            }
            request.httpBody = body

            let (data, response) = try await session.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1

            guard status == 200,
                  let plist = (try? PropertyListSerialization.propertyList(
                    from: data, options: [], format: nil)) as? [String: Any] else {
                AppLog.error("download fallback [" + candidate.label + "] HTTP "
                             + String(status) + ", " + String(data.count) + " bytes", .download)
                continue
            }

            if let url = Self.packageURL(in: plist) {
                AppLog.info("download fallback [" + candidate.label + "] served the package",
                            .download)
                return url
            }

            let failure = plist["failureType"] as? String ?? ""
            AppLog.info("download fallback [" + candidate.label + "] HTTP 200, "
                        + String(data.count) + " bytes, failureType=" + failure, .download)
        }

        return nil
    }

    /// Both songList shapes, plus the bare URL string a redownload can carry.
    private static func packageURL(in plist: [String: Any]) -> URL? {
        guard let songList = plist["songList"] else { return nil }

        if let items = songList as? [Any] {
            if let text = items.first as? String, let url = URL(string: text) {
                return url
            }
            for item in items {
                if let map = item as? [String: Any],
                   let text = map["URL"] as? String, let url = URL(string: text) {
                    return url
                }
            }
            return nil
        }

        if let map = songList as? [String: Any] {
            if let text = map["URL"] as? String, let url = URL(string: text) {
                return url
            }
            for value in map.values {
                if let item = value as? [String: Any],
                   let text = item["URL"] as? String, let url = URL(string: text) {
                    return url
                }
            }
        }

        return nil
    }
}
