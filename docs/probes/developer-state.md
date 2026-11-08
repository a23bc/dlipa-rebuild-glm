# Note: the developer-state surface, and what has to happen to it before a release

Not a branch. This is a surface that lives in the app — `app/DLiPARebuild/Model/DevState.swift`, `app/DLiPARebuild/UI/DevStateSection.swift`, the `wire out` / `wire in` pair in `AppStoreClient.signedRequest`, and the Diagnostics row — added on 2026-11-09 to answer one question that a rollback could not, and scheduled to come out again.

## The question

`authenticate` answers 301, 204 and 404 inside a single session, and it does so on builds that used to work. Rolling back to the build that introduced demand paging, and to the one that introduced the pre-warm, changes nothing: the same three codes, in the same session, in an order that no single fault explains.

A rollback removes code. What it does not remove is state, and this app keeps four kinds outside its own binary:

| Store | Written by | Survives |
| --- | --- | --- |
| Keychain items | `Keychain.save` (the sign-in password, service `com.a23bc.dliparebuild.password`, account = the Apple ID) and the `KeychainProbe` markers | relaunch, upgrade — and reinstall is the open question |
| `HTTPCookieStorage.shared` | the file-transfer session, which runs the default cookie policy | relaunch, upgrade, reinstall (iOS stores the jar in the keychain) |
| `UserDefaults` | `accounts` (with `passwordToken` / `clearToken` / `sessionToken`), `cookieJar.header` / `.values`, `hardwareIdentity` | relaunch, upgrade, and a backup restore |
| `Library/Caches/dlipa` | the kbsync blobs, `kbsync-v1-<dsid>.bin` | relaunch, upgrade; wiped by uninstall |

The suspicion this surface is built to test is stated by the person doing the testing: *something we wrote to the keychain is making the requests we send wrong, so they never reach the sign-in request they should*. That is a checkable claim, not a plausible one — but only by looking at two things at once: what is stored, and what a request actually takes from it and puts on the wire.

## What it does

With the Diagnostics row **Developer state** on, and only then:

* every signed request and its response are logged whole — method, URL, every header value, both bodies, in clear text;
* **Dump persisted state to the log** writes one block covering all four stores: every keychain item this app can reach in *both* shapes, every cookie in the shared jar with its value, every `com.a23bc.dliparebuild*` preference with its value, and the cache files with their sizes;
* **List keychain items** turns the same rows into controls: `Set` overwrites (or creates) a value, `Delete` removes an item, and both report the OSStatus.

Two of these are the actual instruments, and they are worth naming:

**The wire pair**, because the 301 investigation has been reading a status code and nothing else. A `Location` that is absent, one that resolves somewhere unexpected, and one this client refused are three different faults; with the headers in hand they are one line each.

**The password slot control**, because there is one code path in the app that sends an authenticate request nobody pressed: after a 2034, `AppSession.signInAgain` reads the stored password and re-authenticates. If that slot holds something, and something re-triggers a 2034, the app produces sign-in requests on its own — with a pod, a jar and a `attempt` counter belonging to a session that ended. Setting the slot to a known-wrong value, or emptying it, tells us whether the requests in the failing captures are ours.

## What is deliberately unprotected here

Everything. `describeRequestHeaders`, the `token=…ch` lengths and the query-stripped `Location` exist to keep credentials out of a log that gets pasted into issue reports; this switch bypasses all of it, on purpose, for as long as the app is a development build. The ruling that permits it, from 2026-11-09: *we are still in development, so what the log contains does not matter — even full plaintext — and these become must-fix items only when preparing an actual release*.

The exposure is real and bounded: the device is the person's own, the log goes where they send it, and nothing here writes to a file that leaves the container. What it does not bound is the stored password itself, which the dump prints in clear text.

## Removal criterion

This comes out, entirely, before the first build that could plausibly be handed to somebody else. Concretely, all of:

1. `DevState.swift` and `DevStateSection.swift` deleted, not disabled;
2. the `logWireExchange` call and its helpers out of `AppStoreClient`;
3. the Diagnostics row and the `Developer state` section of `docs/diagnostics.md` gone, so a switch nobody can audit does not sit on the tab;
4. the four stores migrated to where they belong — which is the standing plan this note is filed alongside: tokens, the cookie jar, the device identity and the blob into the keychain, and the log redaction rules applied to whatever remains.

Leaving the surface in a release build would undo item 4 by construction: a switch that prints every credential in clear text is the same thing as no redaction, and the redaction was already paid for.

If the reading is filed and the surface is still wanted afterwards, it goes back behind a build-time flag rather than a preference — the preference is readable by anything in the container, which is fine for a development app and is not the same statement for a shipped one.
