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

## What this probe does not do

It changes nothing about what ships: three tries is still the default. It does
not touch anisette (that line lives on `feat/anisette-login`, where the proof
now runs in this repository's own code) and it does not log credentials: the
typed value, the status numbers, the counts and the certificate subjects are the
whole record, and the password still only leaves through `trustedEndpoint`.

