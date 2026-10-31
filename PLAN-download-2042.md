# Store download: the 2042, and what to do about it

Written 2026-10-31, at commit `a4f87c4`. This is a plan, not a report: it records
what has been ruled out, what is left, and how each remaining step is judged.

Sign-in, kbsync, signing and search all work. The download does not: every
request to the store's download endpoints is answered with `2042
AuthTokenResumeFreeBuy`, "Sign In to the iTunes Store", from a session that has
just signed in.

## 1. What the device has already ruled out

Five hypotheses, five device runs. Each one was a real candidate; each one is now
dead, with the log line that killed it.

| # | Hypothesis | Why it is dead |
|---|---|---|
| 1 | The cookie jar does not survive a restart | `replayed cookie header: 746 chars, 20 values` — the full nineteen-cookie session, replayed across a process restart, and still 2042 |
| 2 | The `X-Token` header contradicts the `X-Token` cookie Apple set | An attempt that sends no `X-Token` header returns the same 1633-byte body |
| 3 | The generic host does not serve this account | `buy.itunes.apple.com` 404s on authenticate, `p22-buy` answers 200; buyProduct was then moved onto the pod and still answered 500 |
| 4 | The pod needs `?Pod=22&PRH=22` like authenticate did | Adding them changed nothing; the 2042 body echoed them back and still refused |
| 5 | Our request headers differ from ipatool's | `[ipatool headers]` sends exactly `Content-Type`, `iCloud-DSID`, `X-Dsid` and no cookies — same 1633-byte 2042 |

The last run printed all three remaining attempts in one pass and they are byte
for byte identical:

    download attempt [cookie+passwordToken] HTTP 200, 1633 bytes
    download attempt [cookie only]          HTTP 200, 1633 bytes
    download attempt [ipatool headers]      HTTP 200, 1633 bytes

**The content of the request is not the cause.** Further header or payload
permutations have no information left in them.

Two things about the 2042 that are worth keeping in view:

- `ent/download` answers **500 with a zero-byte body** to the same session. An
  empty 500 is not a plist failure; it reads like the request never got as far
  as the store's own error handling.
- `ipatool` maps 2042 (`FailureTypeSignInRequired`) to "password token expired"
  and tells the user to log in again (`appstore_download.go`). Even the reference
  implementation does not expect this answer on this path.

## 2. What is left: three differences that cannot be copied with a header

All three sit below the request, which is why the last two rounds changed
nothing.

### 2.1 The transport is not the one the reference uses

ipatool sends this over Go's `net/http` client: its own connection pool, its own
cookie jar, and a TLS/HTTP2 fingerprint that is not CFNetwork's. We send it over
`URLSession`, which is CFNetwork underneath. The store is known to behave
differently for clients it does not recognise, and a session that was
established over one stack need not be honoured on another.

Nothing about this can be tested by editing headers. It needs either a request
path that does not go through `URLSession`, or a way to make `URLSession` look
like the reference.

### 2.2 The User-Agent on this request

Upstream does not set one on `volumeStoreDownloadProduct`, so it goes out as
`Go-http-client/1.1`. Ours goes out with whatever `URLSession` stamps on it
(`DLiPARebuild/… CFNetwork/… Darwin/…`). `ent/download` is the exception —
upstream sets `Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81)
AppleWebKit/0620.2.4.11.6` there and we do not.

Cheap to test, and worth testing before 2.1 because it is a one-line change:
send `Go-http-client/1.1` on the classic request and `Configurator/2.18 …` on
ent/download, exactly as upstream does.

### 2.3 The session may not be the one the store wants

`authenticate` succeeds and returns `passwordToken`, `clearToken`, DSID and
nineteen cookies. Apple then says "sign in" for the download. One reading is
that the store wants a *store* session established by a step we do not perform
— `authorizeMachine` is skipped in `ensureSession` because it answered
`2034 ExpiredPasswordToken` on every one of four token combinations, but that
conclusion was drawn from a different request shape than the one we now send.

Re-testing `authorizeMachine` with the current session is cheap and would settle
whether it belongs in the flow.

## 3. The decisive experiment

Run ipatool itself, on macOS, with this account:

    ipatool auth login
    ipatool download --bundle-identifier com.burbn.instagram

The result splits the problem in two, and nothing else does:

- **ipatool also gets 2042** — then the limit is the account, the region
  (`143480-2,34`, Turkey) or Apple's policy for this client, not our code. The
  download feature would then need a different route entirely, and the honest
  answer is to say so rather than keep editing headers.
- **ipatool succeeds** — then the difference is in the transport (§2.1), and the
  work is to move the download requests off `URLSession`.

Prerequisites, and why CI cannot do it: it needs the account's password and a
2FA code, which must not be put into a GitHub workflow. It has to be a machine
the owner controls. ipatool needs macOS for kbsync, so a Windows box is not
enough.

## 4. Separately: the launch crash

The run before last died during pre-warm:

    [SAP] opening guest runtime...
    [SAP]   mem_map 0x100000000 size=4096 (triggers UC_INIT on the first)
    [DLiPA] restored 20 cookies
    Could not allocate dynamic translator buffer

That is the known "iOS fits one emulator" limit, hit at pre-warm rather than at
sign-in. `AppSession.prewarmSAPRuntime()` exists because creating the machine at
launch, while the process is small, was the only order that worked; the same
reason makes it the worst place to start a second one.

Worth doing regardless of the download:

- Do not pre-warm when a signer already exists (`guard signer == nil` is there,
  but a failed earlier attempt leaves enough memory behind that the next
  `uc_open` fails).
- On failure, log the RSS at that moment, not just the error — the log above has
  no numbers to compare against.

## 5. Carried over, not part of the download

| Item | State | Note |
|---|---|---|
| P2-7 shared 64 MB heap, two bump allocators | open | Belongs to the store-runtime line, which is paused |
| P2-8 `bytes.Clone` cancels the mmap saving | blocked | Needs a real `vmmap` comparison on device |
| P3-14 `gofmt` on 35 files | not done | Whitespace-only diff, wants its own commit when nothing else is in flight |
| P3-12 dead code, P3-5 localisation, P3-9 Info.plist | not done | Decisions, not fixes |
| R2/R3/R5 on device | unverified | R2 needs a working download; R3 needs a cross-domain redirect that has not occurred; R5 needs a race |
| Diagnostic attempts in `classicDownload` | temporary | `[cookie only]` and `[ipatool headers]` cost two extra requests per download; delete them once the cause is known |

## 6. How each step is judged

Every entry needs a check that can fail before it counts as done.

- **§2.2 User-Agent**: one build, one run. Judged by `download attempt ...
  HTTP` staying at 1633 bytes of 2042 or becoming something else.
- **§2.3 authorizeMachine**: one build. Judged by whether the endpoint answers
  anything other than `2034`.
- **§3 ipatool reference**: zero builds. Judged by whether `ipatool download`
  produces an `.ipa` on the same account.
- **§2.1 transport**: only worth starting if §3 says the reference works.

Until §3 has an answer, the download is not blocked on our code, and the
remaining repairs should be treated as complete on their own terms.
