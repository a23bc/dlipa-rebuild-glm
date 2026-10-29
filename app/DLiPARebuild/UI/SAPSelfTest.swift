import Foundation

/// Runs the SAP guest end to end and reports what happened, without touching
/// the account UI. This is the screen to open when the question is "does the
/// probeapp chain work on this device", which has to be answered before any
/// sign-in flow is worth wiring.
///
/// Every step is reported separately. A single "failed" line would hide the
/// difference between the image not loading, the emulator refusing to start,
/// the initialiser returning a status and the exchange not reaching state 1.
enum SAPSelfTest {

    /// Fetches the bag, builds the signer and runs the handshake. The HTTP
    /// round trip between the two exchange legs happens inside the guest's
    /// handshake, through the transport the signer installs.
    ///
    /// The callback is invoked on the main queue, which is where the view
    /// state lives. The signer work blocks its caller, so it runs on a
    /// background queue and hops back for every report line.
    static func run(report: @escaping (String) -> Void) {
        let hardware = HardwareIdentity.current()
        report("Device GUID: " + hardware.guid)

        DispatchQueue.global(qos: .userInitiated).async {
            func emit(_ line: String) {
                DispatchQueue.main.async { report(line) }
            }

            do {
                let client = AppStoreClient()
                let semaphore = DispatchSemaphore(value: 0)
                var fetchedBag: StoreBag?
                var bagError: Error?

                Task {
                    do {
                        fetchedBag = try await client.fetchBag(guid: hardware.guid)
                    } catch {
                        bagError = error
                    }
                    semaphore.signal()
                }
                semaphore.wait()

                if let bagError {
                    emit("FAILED: fetching the bag: " + bagError.localizedDescription)
                    return
                }
                guard let bag = fetchedBag else {
                    emit("FAILED: the bag came back empty")
                    return
                }

                emit("Bag: sign-sap-version=\(bag.signSapVersion)")
                emit("Bag: sign-sap-setup=\(bag.signSapSetup ?? "none")")

                guard bag.hasSAPConfiguration,
                      let setup = bag.signSapSetup,
                      let cert = bag.signSapSetupCert else {
                    emit("FAILED: the bag advertises no SAP endpoints")
                    emit("  hasSAPConfiguration=\(bag.hasSAPConfiguration)")
                    emit("  sign-sap-setup=\(bag.signSapSetup ?? "nil")")
                    emit("  sign-sap-setup-cert=\(bag.signSapSetupCert ?? "nil")")
                    emit("  sign-sap-version=\(bag.signSapVersion) (needs 200)")
                    return
                }

                emit("Building the signer...")

                // Closed on every path from here. It used to be closed only
                // after the signature came back, so a failure past the handshake
                // leaked the session: liveSessions stayed at 1 and the next
                // signer could never be created.
                //
                // Note that this diagnostic creates its own session, which needs
                // liveSessions to be 0. With the app already signed in it is 1,
                // so the constructor refuses and this reports "a SAP session is
                // already open" no matter what -- that part is still open.
                var opened: SAPSigner?
                defer { opened?.close() }

                // The signer constructor does the whole chain: load the X64I
                // container, run the initialiser, fetch the certificate, run
                // both exchange legs. Throwing here means one of those failed
                // and the error carries which.
                let signer = try SAPSigner(setupURL: setup,
                                           certURL: cert,
                                           version: bag.signSapVersion,
                                           hardware: hardware)
                opened = signer

                emit("Handshake OK")
                emit("Signing a probe body...")

                let body = Data("dlipa-self-test".utf8)
                let header = try signer.signatureHeaderValue(for: body)
                emit("Signature OK (\(header.count) hex chars)")
                emit("  \(header.prefix(64))...")
                emit("SELF TEST PASSED")
            } catch {
                emit("FAILED: \(error.localizedDescription)")
                let ns = error as NSError
                emit("  domain=\(ns.domain) code=\(ns.code)")
            }
        }
    }
}
