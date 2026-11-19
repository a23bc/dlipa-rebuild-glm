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
                              bag: StoreBag,
                              cookieHeader: String) async throws -> URL? {
        // Upstream uses `appExtVrsId` on both recovery endpoints; the classic
        // volume store uses `externalVersionId` (`downloadVersionKeyRedownload`
        // vs `downloadVersionKeyVolumeStore`, appstore_download_product.go:19-20).
        let endpoints: [(label: String, endpoint: String?)] = [
            // The same recovery order a working on-device client uses:
            // backgroundUpdateProduct first, then the two classic bag paths.
            ("background", bag.backgroundUpdateProduct),
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
            let host = url.host ?? "?"
            var detail = "download fallback [" + candidate.label + "] "
            detail += host
            detail += url.path
            detail += " cookies=" + String(cookieHeader.count) + " chars"
            AppLog.info(detail, .download)

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
            // Upstream's download client has a cookie jar, so its redownload and
            // updateProduct requests carry the sign-in session. Run 600's 403/0
            // came from sending these without it; the SP retry proved the jar
            // matters for this account.
            if !cookieHeader.isEmpty {
                request.setValue(cookieHeader, forHTTPHeaderField: "Cookie")
            }

            // Spend the proof that just earned the previous request its 200.
            // A fresh mint against the dispatch host returned nil on 600/601.
            let spent = takeBufferedStoreProof()
            if !spent.isEmpty {
                for (key, value) in spent {
                    request.setValue(value, forHTTPHeaderField: key)
                }
                AppLog.info("download fallback [" + candidate.label + "] spent "
                            + String(spent.count) + " buffered proof headers", .download)
            } else {
                do {
                    let proof = try AnisetteIdentity.storeProof(endpoint: url.absoluteString, guid: guid)
                    for (key, value) in proof {
                        request.setValue(value, forHTTPHeaderField: key)
                    }
                } catch {
                    AppLog.error("download fallback [" + candidate.label + "] proof failed: "
                                 + error.localizedDescription + "; sending without it", .download)
                }
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

    /// Answers the download endpoint's `AMD-Action: …:SP` challenge.
    ///
    /// Run 597 succeeded on the first try; run 598's retry threw
    /// `NSURLErrorCannotParseResponse` and the whole download stopped at the
    /// 287-byte challenge. Bound the attempts and name each failure instead.
    func retryWithDownloadProof(session: URLSession,
                                request: URLRequest,
                                challenge: String,
                                guid: String) async -> [String: Any]? {
        for attempt in 1...3 {
            do {
                let identity = try AnisetteIdentity.headers()
                let proof = try AnisetteIdentity.downloadProof(
                    challenge: challenge,
                    // 560 showed a proof minted against the download URL still
                    // got 2042; keep the auth URL that worked in run 597.
                    endpoint: "https://auth.itunes.apple.com/auth/v1/native",
                    identity: identity,
                    guid: guid)

                var retry = request
                for (key, value) in proof {
                    retry.setValue(value, forHTTPHeaderField: key)
                }

                let (body, response) = try await session.data(for: retry)
                let status = (response as? HTTPURLResponse)?.statusCode ?? -1
                AppLog.info("download proof retry " + String(attempt) + " HTTP "
                            + String(status) + ", " + String(body.count) + " bytes, "
                            + Self.responseDetail(from: body), .download)

                if status == 200,
                   let plist = (try? PropertyListSerialization.propertyList(
                    from: body, options: [], format: nil)) as? [String: Any],
                   plist["songList"] != nil {
                    // This proof bought the 200. Keep it for the request that
                    // follows, rather than minting a fresh one for a new URL.
                    bufferStoreProof(proof)
                    AppLog.info("download proof buffered "
                                + String(proof.count) + " headers", .download)
                    return plist
                }
            } catch {
                AppLog.error("download proof retry " + String(attempt)
                             + " failed: " + error.localizedDescription, .download)
            }
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
