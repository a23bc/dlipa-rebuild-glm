import Foundation

/// Sign-in through the Store runtime, as one exchange at a time.
///
/// The request is built by Apple's own `AMSVerifyCredentialsTask` inside the
/// guest and sent by the Go bridge; this file owns the protocol around it:
/// redirect hops, the 2FA branch, and the error taxonomy. There is no retry:
/// one user action sends one request, and an edge refusal is reported as one.
extension AppStoreClient {
    /// What the bridge returns.
    private struct NativeAnswer: Decodable {
        let status: Int
        let headers: [String: [String]]
        let bodyBase64: String
        let url: String

        var body: Data { Data(base64Encoded: bodyBase64) ?? Data() }

        func header(_ name: String) -> String? {
            for (key, values) in headers where key.caseInsensitiveCompare(name) == .orderedSame {
                return values.first
            }

            return nil
        }

        var setCookie: [String] {
            var values: [String] = []

            for (key, list) in headers where key.caseInsensitiveCompare("Set-Cookie") == .orderedSame {
                values.append(contentsOf: list)
            }

            return values
        }
    }

    /// Apple's own login client, not the Configurator UA the hand-built path
    /// uses. The task's request is the one upstream sends.
    private static var nativeUserAgent: String {
        "Configurator/2.21 (Macintosh; OS X 27.0.1; 26A434) AppleWebKit/0625.2.5.11.6"
    }

    // swiftlint:disable:next cyclomatic_complexity
    func authenticateNative(email: String,
                            password: String,
                            authCode: String?,
                            guid: String,
                            endpoint: String,
                            signer: SAPSigner,
                            reusedIdentity: [String: String]? = nil,
                            identityMode: String = "amd",
                            resetStore: Bool = false) async throws -> Account {
        let code = authCode?.replacingOccurrences(of: " ", with: "") ?? ""
        var cookie = beginNativeAuthentication(codeIsEmpty: code.isEmpty)
        var target = Self.nativeEndpoint(endpoint)
        var hops = 0
        var last: NativeAnswer?

        // The store's authenticate task is built to receive an AMD pair. It is
        // fetched once per call: the proof is time-sensitive, and the code
        // request comes through this same function with the state advanced.
        // A reprovision retry reuses the same set, because advancing the state
        // again is what RP asked us not to do.
        let identity: [String: String]

        if let reusedIdentity {
            identity = reusedIdentity
        } else {
            do {
                identity = try AnisetteIdentity.headers()
            } catch {
                throw StoreError.failureType("anisette", error.localizedDescription)
            }
        }

        while true {
            let request: [String: Any] = [
                "endpoint": target,
                "appleId": email,
                "password": password + code,
                "guid": guid,
                "cookie": cookie,
                "userAgent": Self.nativeUserAgent,
                "extraHeaders": identity,
                "identityMode": identityMode,
                "resetStore": resetStore,
                "timeoutMs": 90_000,
            ]

            let payload = try JSONSerialization.data(withJSONObject: request, options: [])
            guard let json = String(data: payload, encoding: .utf8) else {
                throw StoreError.signingFailed
            }

            AppLog.info("native authenticate to " + target
                        + (code.isEmpty ? " (no 2FA)" : " (with 2FA)"), .auth)

            let raw = try signer.authenticateOnce(json: json)
            let answer = try JSONDecoder().decode(NativeAnswer.self, from: Data(raw.utf8))
            last = answer

            AppLog.info("native authenticate returned " + String(answer.status)
                        + ", body " + String(answer.body.count) + " bytes, url " + answer.url,
                        .auth)

            cookie = captureCookieHeaderValues(answer.setCookie,
                                               host: URL(string: answer.url)?.host ?? "")

            // A pod redirect is part of one attempt: same payload, new address,
            // bounded. This is not a retry.
            if (300..<400).contains(answer.status),
               let location = answer.header("Location"),
               let base = URL(string: answer.url),
               let next = URL(string: location, relativeTo: base)?.absoluteURL {
                hops += 1

                if hops > 4 {
                    throw StoreError.httpError(answer.status, "too many authentication redirects")
                }

                target = next.absoluteString
                continue
            }

            break
        }

        guard let answer = last else {
            throw StoreError.httpError(-1, "no response")
        }

        let data = answer.body

        // Anything that is not an application answer is reported as one. A
        // code-bearing request that lands here never reached the store, which
        // is a different instruction to the person than "that code was wrong".
        if answer.status != 200 {
            if !code.isEmpty, Self.isEdgeStatus(answer.status) {
                AppLog.warn("verification code never reached the store: HTTP "
                            + String(answer.status) + ", response " + String(data.count)
                            + " bytes", .auth)
                throw StoreError.codeUnseen(answer.status)
            }

            let body = String(data: data, encoding: .utf8) ?? ""
            throw StoreError.httpError(answer.status, String(body.prefix(200)))
        }

        let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        let plist = object as? [String: Any] ?? [:]
        let failure = plist["failureType"] as? String ?? ""
        let message = plist["customerMessage"] as? String ?? ""

        // The 2FA challenge: empty failureType plus this exact message. There is
        // no failure code to match on.
        if failure.isEmpty && message == "MZFinance.BadLogin.Configurator_message" {
            if code.isEmpty {
                nativeChallengeAt = Date()
                AppLog.info("2FA required, asking for the code", .auth)
                throw StoreError.twoFactorRequired
            }

            nativeChallengeAt = nil
            AppLog.error("2FA rejected after the code was supplied", .auth)
            throw StoreError.failureType("2FA", "apple did not accept the verification code; try a fresh one")
        }

        // Any answer that is not a challenge ends the challenge session.
        nativeChallengeAt = nil

        // RP asks for a new proof without the machine headers: drop MD, MD-M
        // and MD-RINFO, keep the rest, and send the same body once more. This
        // is the first request of the two-step machine action; an SP answer
        // after the retry is a separate step.
        if message == "AMD-Action::RP", identityMode == "amd" {
            AppLog.info("AMD action RP: retrying without the MD headers", .auth)
            return try await authenticateNative(email: email,
                                                password: password,
                                                authCode: authCode,
                                                guid: guid,
                                                endpoint: endpoint,
                                                signer: signer,
                                                reusedIdentity: identity,
                                                identityMode: "reprovision")
        }

        // SP is the second half of the machine action: finish Store
        // provisioning with the challenge and a machine kbsync, mint the Store
        // AMD proof, then send the same body with that proof.
        if message == "AMD-Action::SP", identityMode != "store" {
            guard let challenge = answer.header("X-Apple-AMD-Data"), !challenge.isEmpty else {
                throw StoreError.failureType("AMD-SP", "the answer carried no provisioning data")
            }

            // The machine kbsync exists for the FairPlay keybag a download
            // needs, not for the sign-in. Generating it on the signer's
            // machine spins in StoreAgent global init and hits its own timeout,
            // so the login provisions without it and leaves the keybag to the
            // download path.
            let state = Keychain.anisetteState() ?? Data()

            AppLog.info("AMD action SP: provisioning with " + String(challenge.count)
                        + " challenge chars, no kbsync", .auth)

            let proof = try AnisetteIdentity.provisionStore(state: state,
                                                            challenge: challenge,
                                                            kbsync: Data(),
                                                            identity: identity,
                                                            guid: guid)

            return try await authenticateNative(email: email,
                                                password: password,
                                                authCode: authCode,
                                                guid: guid,
                                                endpoint: endpoint,
                                                signer: signer,
                                                reusedIdentity: proof,
                                                identityMode: "store",
                                                resetStore: true)
        }

        if !failure.isEmpty {
            AppLog.error("authenticate failed: failureType=\(failure) message=\(message)", .auth)
            throw StoreError.failureType(failure, message)
        }

        if message == "Your account is disabled." {
            throw StoreError.failureType("disabled", message)
        }

        let accountInfo = plist["accountInfo"] as? [String: Any] ?? [:]
        let address = accountInfo["address"] as? [String: Any] ?? [:]
        let passwordToken = plist["passwordToken"] as? String ?? ""
        let clearToken = plist["clearToken"] as? String ?? ""
        let dsid = plist["dsPersonId"] as? String ?? ""

        let summary = plist.keys.sorted().map { key -> String in
            switch plist[key] {
            case let value as String: return key + "(" + String(value.count) + ")"
            case let value as [String: Any]: return key + "{" + String(value.count) + "}"
            case let value as [Any]: return key + "[" + String(value.count) + "]"
            default: return key + "(?)"
            }
        }.joined(separator: ", ")
        AppLog.info("authenticate keys: " + summary, .auth)

        guard !passwordToken.isEmpty, !dsid.isEmpty else {
            AppLog.error("authenticate returned no session: passwordToken "
                         + String(passwordToken.count) + " chars, dsid "
                         + String(dsid.count) + " chars, message=\(message)", .auth)
            throw StoreError.failureType("no-session",
                                         "apple returned no usable authentication response")
        }

        let capturedSession = finishNativeAuthentication(dsid: dsid)
        AppLog.info("authenticate tokens: passwordToken " + String(passwordToken.count)
                    + ", clearToken " + String(clearToken.count)
                    + ", cookie X-Token " + String(capturedSession.count), .auth)

        return Account(
            email: accountInfo["appleId"] as? String ?? email,
            passwordToken: passwordToken,
            sessionToken: capturedSession.isEmpty ? passwordToken : capturedSession,
            clearToken: clearToken,
            dsid: dsid,
            storefront: answer.header("X-Set-Apple-Store-Front") ?? "",
            pod: answer.header("pod") ?? "",
            firstName: address["firstName"] as? String ?? "",
            lastName: address["lastName"] as? String ?? "")
    }

    private static func nativeEndpoint(_ value: String) -> String {
        // The bag's authenticate URL is the legacy buy host. Apple's native
        // verification task speaks to auth/v1/native; posting its body to the
        // legacy path is what the edge answered with 301, 400 and 503 while
        // the same bytes returned a token here.
        "https://auth.itunes.apple.com/auth/v1/native"
    }

    private static func isEdgeStatus(_ status: Int) -> Bool {
        switch status {
        case 204, 301, 302, 303, 307, 308, 403, 404, 429:
            return true
        default:
            return (500..<600).contains(status)
        }
    }
}
