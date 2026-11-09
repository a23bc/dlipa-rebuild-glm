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
* **List keychain items** turns the same rows into controls: `Set` overwrites (or creates) a value, `Delete` removes an item, and both report the OSStatus;
* **write the password slot** creates the keychain row a successful sign-in would create, through the same call and with the same accessibility attribute.

## What reading the code already settled

Two parts of the suspicion are answered without a device run, and they are recorded here so the run is spent on what is left.

**Nothing in the interactive sign-in path reads the keychain.** `Keychain.password(for:)` has exactly one caller, `AppSession.signInAgain` ([app/DLiPARebuild/Model/AppSession.swift:68](file:///e/Projects/dlipa/dlipa-rebuild-glm/app/DLiPARebuild/Model/AppSession.swift#L68)), which runs only when the store has just retired a session token and only if a password row exists. `Keychain.save` is reached only after a *successful* sign-in (line 178), and `Keychain.delete` from the two account-removal paths (lines 300 and 369). So on a device whose accounts were deleted in-app and where no sign-in has succeeded for a week, the slot is empty -- which means the auto-relogin cannot be the thing sending authenticate requests, and a stored-but-wrong password cannot be reaching the wire.

**A restored cookie jar cannot contaminate the first authenticate.** `AppStoreClient.init` does restore `cookieJar.header` from preferences (line 123), and the file-transfer session does run the default cookie policy against `HTTPCookieStorage.shared`; but `authenticate` clears both the persisted jar and the in-memory replay header before its first request (lines 227-229), and the signed session has `httpShouldSetCookies = false`, which stops URLSession attaching anything from the jar. What the first authenticate *does* carry from persisted state is one field: `guid`, read from `com.a23bc.dliparebuild.hardwareIdentity`.

That leaves two questions the surface was built to answer, and no others: whether the bytes on the wire match what those stores hold -- above all whether the `guid` in the body equals the `hardware` the signer reports -- and what the response's own headers say (`Location`, `Retry-After`) about where the request actually landed. A `Retry-After` beside a 204 or a 429 would mean Apple is rate-limiting rather than refusing, and until this switch nothing in the log could tell those two apart.

The password-slot writer is part of this surface for the same reason it is not an omission from it: the one path that could turn a keychain value into a sign-in request is unreachable while sign-in is broken, since a sign-in is the only thing that writes that row. Handing the path a known-wrong password is how it gets tested at all.

## Reading it

In order, on the failing device:

1. open Diagnostics, turn **Developer state** on;
2. **Dump persisted state to the log** *before* signing in -- that is the state that survived the rollback;
3. attempt the sign-in and let it fail;
4. dump again, then **Share log**.

The first dump is the one that matters and it is easy to skip: after a sign-in attempt the interesting stores have been written by the attempt.


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
