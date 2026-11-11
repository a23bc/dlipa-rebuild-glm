# Probe: how many tries does a real account need?

Branch: `probe/auth-attempts`, cut from `test/credentials-and-pregeneration`
(because that branch is what carries the transient-status handling and the
developer-state fields; `main` has neither, so a probe cut from `main` could
not measure anything). It is a measurement, not a merge candidate: the
shipping default is unchanged at three tries.

## The question

`authenticate` answers a well-formed, correctly signed sign-in with front-end
noise: an empty 204, an HTML 404, or a 301/302 that carries no `Location`. The
client currently spends three tries on that (10s, then 20s) and then reports
"the store answered with no content; sign in again". Nobody has ever measured
how many tries the other side actually needs, so nobody can say whether three
is too few, or whether the pod is refusing this client specifically.

## What was measured before asking for a device run

All from one Windows machine, through WSL, with the branch's own signer, so the
signature is the same artifact a device produces. Every post carried the six
payload fields, `application/x-www-form-urlencoded`, the reference
`Configurator/2.18` user agent, and a freshly computed
`X-Apple-ActionSignature` of 668 characters. **The account never existed**
(`probe-*@example.invalid`), which is what keeps credentials out of it and also
what limits what it can prove.

| shape varied | rounds | answered as an application |
| --- | --- | --- |
| signed, generic host, form-urlencoded | 20 | 1 (the very first probe; body was `pings`/empty `failureType`, not a credential answer) |
| signed, generic host, `x-apple-plist` | 1 | 0 (403) |
| unsigned, generic host | 10 | 0 |
| signed, device hardware identity `34EEF9D75FC4` | 20 | 0 |
| signed, `p47-buy` with `?Pod=47&PRH=47` | 6 | 0 |
| signed, `p47-buy` without the query | 6 | 0 |
| bare post, then the same post carrying `Set-Cookie` | 6 + 6 | 0 |

Statuses seen across roughly ninety posts: 204, 301, 302, 403, 404, 500, 503.
`Location` was empty on every 301 and 302, and **`Set-Cookie` appeared on no
response at all** -- so "the client is missing a session" is not available as
an explanation: there was nothing to carry.

Read honestly, that table rules out a lot and proves little. Headers, hosts,
content types, the presence of the signature, the hardware identity and
cookies are all excluded as the difference between the working reference
client and this one, for a nonexistent account. What it cannot exclude is the
one thing a machine cannot supply: an account that exists, with its consent
state and its 2FA behind it. The reference client at v2.7.0 signed this same
account in from the same machine and got an application answer, so application
answers do exist for a real account -- the open number is how far apart they
are.

## The knob

`DevState.authAttemptsOverride` (`com.a23bc.dliparebuild.devAuthAttempts`), set
from the developer-state row, accepted only between 1 and 20, default 3 --
which is what `maxAuthenticationRequestAttempts` is in the reference client.
The delays list is `[10, 20, 30]` and is indexed with a clamp, so twelve tries
wait 10s, 20s, then 30s each: about five minutes at worst, which is the reason
for the cap.

The row logs both the stored value and the value in force, because they can
disagree: a typed `100` is refused and the default stays.

## How to read it

1. Set authentication attempts to `12` on the developer-state row; the log
   confirms `stored 12, in force 12`.
2. Sign in with the real account.
3. Take the log and read the sequence of `authenticate got HTTP <n>` lines
   against the one line that means the pod answered: a plist with
   `failureType`, `customerMessage` or a session token.

| what the log shows | what it means |
| --- | --- |
| an application answer arrives at try 5-9 | the endpoint is noisy, not refusing; the fix is the retry budget, and it should be raised in the shipping default with the measured number attached |
| all twelve tries are noise, and the reference client succeeds from the same machine | something in the request still differs, and the next comparison is header-by-header against a known-good capture, not more retries |
| noise at first, then an application answer naming a `failureType` | the sign-in was reaching the application all along and the earlier failures were credential-shaped; this branch's error text needs to stop calling that "no content" |

## The third thing this build answers

Runs 506 to 508 never reached the application for a real account after 17:30Z,
and the control run on the development machine said why it cannot even try:
`gsa.apple.com` does not verify there.

```
curl: (60) SSL certificate problem: self-signed certificate in certificate chain
subject=CN = gsa.apple.com   issuer=CN = Apple Server Authentication CA
ipatool: prepare Apple authentication: install Apple provisioning root: download Apple root: HTTP 403
```

That is the machine-provisioning host the anisette proof needs, so on that path
the reference client never sends a sign-in at all. Whether a phone on the same
network sees Apple's own chain or a proxy's is not knowable from the machine,
and the answer decides whether anisette can ship on this network regardless of
how the emulator behaves -- so the build carries one more row, "Check gsa and
buy reachability", and it asks both hosts because they fail separately.

Read the two `probe gsa:` and `probe buy:` lines. The trust challenge is
answered with `.performDefaultHandling`, never by accepting anything, which is
what makes the certificate list meaningful: a subject that is not Apple's is a
proxy saying so out loud, and error code -1202 against -1200 is the difference
between "this chain was refused" and "something else in TLS broke".

Corrected on 2026-11-11, by the device run below and by a re-read of the same
control: `gsa.apple.com` does verify from here. `curl` reports `verify=19`,
self-signed certificate in chain, and the chain it prints ends at Apple Root
CA -- the Windows `openssl` in the same house reports code 19 on the identical
chain. Neither trust store on this machine holds an Apple anchor, and
`www.apple.com/appleca/AppleIncRootCertificate.cer`, which is where the
provisioning fallback goes to get one, answers 403 to every client from this
network. Point `SSL_CERT_FILE` at the system bundle with that root -- which gsa
itself serves as the third certificate in its chain -- and the same lookup
returns HTTP 401, which is the application talking. So line 84's
"does not verify there" described the anchor, not the path, and the phone's
answer to that question was never in doubt: iOS ships the Apple roots, so the
fallback that needs a blocked URL is never reached there.

## Run 511: the code went to a different pod than the one that asked for it

The first sign-in since the attempts knob, on the real account, `attempts 12`,
code typed within seconds of the prompt. The ladder did its job: the password
call needed five requests to reach the application, and the application
answered it.

| time (Z) | one call's requests, in order | what came back |
| --- | --- | --- |
| 04:22:41 – 04:24:17 | `attempt 1 (no 2FA)` | 302 no Location, 204, 301 no Location, 204, **200** |
| | | empty `failureType` + `MZFinance.BadLogin.Configurator_message` = the 2FA challenge; `itspod=7`, `mzf_in=9807024` |
| 04:24:29 – 04:26:35 | `attempt 1 (with 2FA)` | 403, 204, 204, 204, 404, **200** |
| | | the same BadLogin body, from `itspod=17`, `mzf_in=9170017` |

That is the reference client's own reading of that body: an empty `failureType`
with `customerMessage == MZFinance.BadLogin.Configurator_message` means "code
required" when no code was sent, and "apple did not complete verification; try
a fresh 2FA code" when one was (upstream `appstore_login.go:420`). The shape
matched, so this is not a parse gap -- the difference is where the two requests
went. The answer that asked for the code came from instance 9807024, the answer
that refused it from 9170017, and every line between them says `authenticate
carries cookies: none`.

`mzf_in` is written here as a number because it is not a credential: Apple
echoes the same value in the `x-apple-application-instance` response header, and
it names which WebObjects instance answered, not who is asking. The cookie
*values* still stay out of the log; only the names are printed.

Three defects, all on the code-bearing call, all mine, and each visible in the
capture:

* `AppSession.signIn` called `client.resetSession()` on entry, unconditionally,
  and that wipes the pod and the jar. The verify step is the second half of one
  sign-in, so it wiped the session whose answer had just asked for the code.
* `authenticate` then wiped the hand-copied jar a second time at its own entry
  (`capturedCookieHeader = ""`), for the same reason.
* and the authenticate request never attached the jar even when it held
  something: the reference client builds its login client with
  `CookieJar: args.CookieJar` (`appstore.go:101`), so its code goes back with
  the `itspod` and `mzf_in` that were set moments earlier. Our capture existed
  and went out through no header at all.

The last one also explains why the earlier log line read `none` while nobody
questioned it: it was drawn from `HTTPCookieStorage.shared`, and this session
sets `httpShouldSetCookies = false` on purpose -- the shared jar is *always*
empty here, so that line could only ever have said `none`. It now reads the
request's own `Cookie` header.

What the build changes: the pod and jar are carried when -- and only when --
the call carries a code, the code request replays the session cookies, and one
more line reports how old the code is by then (`code posted Ns after apple
asked for it`), because 125 seconds and six requests is also what stands
between a typed code and an application that can check it.

What this does not claim: that the account was ever unlocked by a code. It
claims the code has never been presented to the instance that minted the
challenge, and that is the thing the next capture can settle either way. If
run 512 still ends in BadLogin with `itspod=` equal on both answers, the pod
story is dead and the age line is the next suspect.

## What this probe does not do

It changes nothing about what ships: three tries is still the default. It does
not touch anisette (that line lives on `feat/anisette-login`, where the proof
now runs in this repository's own code) and it does not log credentials: the
typed value, the status numbers, the counts and the certificate subjects are the
whole record, and the password still only leaves through `trustedEndpoint`.

