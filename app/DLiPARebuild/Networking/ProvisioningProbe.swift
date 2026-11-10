import Foundation
import Security

/// Does the network this device is on let it reach what signing in needs?
///
/// Two hosts answer the question, and they answer different parts of it:
/// `gsa.apple.com/grandslam/` carries machine provisioning, which is where the
/// anisette proof is minted before a sign-in can be answered at all, and
/// `buy.itunes.apple.com` carries the authenticate request itself. A device can
/// fetch the bag from Apple's CDN all evening and still be refused by both of
/// these, and every log line that blames the guest for that is a lie about the
/// path.
///
/// What was measured matters here. On the development machine on 2026-11-11 the
/// provisioning host does not verify: curl answers "self-signed certificate in
/// certificate chain" with `issuer=CN = Apple Server Authentication CA`, and
/// Go's client reports an unknown authority -- which is exactly why the
/// reference client there died at "install Apple provisioning root: download
/// Apple root: HTTP 403" and never sent a sign-in at all. Whether a phone on
/// the same Wi-Fi sees that chain, or sees Apple's own, is the unknown this
/// row exists to close, and it decides whether the anisette work can ship on
/// this network regardless of how the emulator behaves.
///
/// The trust challenge is answered with `.performDefaultHandling` and nothing
/// else. A diagnostic that accepts a certificate the system would reject cannot
/// report whether the certificate was ever the problem, so it would answer a
/// different question than the one above the button.
enum ProvisioningProbe {
    private static let hosts: [(label: String, url: String)] = [
        ("gsa", "https://gsa.apple.com/grandslam/"),
        ("buy", "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"),
    ]

    static func run() async {
        for host in hosts {
            await probe(label: host.label, urlString: host.url)
        }
    }

    private static func probe(label: String, urlString: String) async {
        guard let url = URL(string: urlString) else {
            AppLog.error("probe " + label + ": the URL did not parse", .network)
            return
        }

        let recorder = ChainRecorder()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 20
        let session = URLSession(configuration: configuration, delegate: recorder, delegateQueue: nil)
        defer { session.invalidateAndCancel() }

        // GET, never POST: this is a reachability and trust check, and the
        // provisioning endpoint would take the request as an attempt to start a
        // machine provisioning for a throwaway identity.
        var request = URLRequest(url: url, timeoutInterval: 20)
        request.httpMethod = "GET"
        request.setValue(Self.userAgent, forHTTPHeaderField: "User-Agent")

        do {
            let (_, response) = try await session.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1

            AppLog.info("probe " + label + ": TLS verified, HTTP " + String(status)
                        + ", chain: " + recorder.chain(), .network)
        } catch {
            AppLog.error("probe " + label + ": " + Self.describe(error)
                         + ", chain seen: " + recorder.chain(), .network)
        }
    }

    /// The reference client's own user agent, so a host that filters by it
    /// answers the same way it answers a real request.
    private static let userAgent = "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) "
        + "AppleWebKit/0620.2.4.11.6"

    /// One line, with the reason in it. `NSURLErrorDomain Code=-1200` is a TLS
    /// failure and -1202 is the certificate specifically, and the difference is
    /// "something else broke" versus "this chain was refused".
    private static func describe(_ error: Error) -> String {
        let ns = error as NSError

        return "code=" + String(ns.code) + " domain=" + ns.domain
            + " description=" + ns.localizedDescription
    }

    /// Records what the server actually presented, because a subject summary of
    /// something that is not Apple's says plainly that a proxy is in the path --
    /// which is the finding, and which no error string states.
    private final class ChainRecorder: NSObject, URLSessionTaskDelegate {
        private var subjects: [String] = []

        func urlSession(_ session: URLSession, task: URLSessionTask,
                        didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLAuthenticationChallenge.Disposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.performDefaultHandling, nil)
                return
            }

            subjects = Self.subjects(of: trust)
            completionHandler(.performDefaultHandling, nil)
        }

        func chain() -> String {
            subjects.isEmpty ? "none recorded" : subjects.joined(separator: " | ")
        }

        private static func subjects(of trust: SecTrust) -> [String] {
            guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else {
                return []
            }

            return chain.map { certificate in
                (SecCertificateCopySubjectSummary(certificate) as String?) ?? "(no subject)"
            }
        }
    }
}
