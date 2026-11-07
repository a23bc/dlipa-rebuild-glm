# Probe: which keychain shape this app can actually use

Branch `probe/keychain-shapes`, built from `main` (`56df4fb` and later). Local branch; the remote ref exists only while a build is being read, and is deleted when the reading is filed here.

## The question

The plan is to move four things out of `UserDefaults` and `Library/Caches` and into the keychain: the account's session tokens, the cookie jar, the device identity (the six-byte GUID), and the kbsync blob. That plan has one unmeasured assumption.

What is proven on device: the classic generic-password query works. The sign-in password has been written that way since 2026-11-06 and device captures carry `password kept for a session refresh`.

What is not proven, and is the shape the plan needs:

* the **data-protection keychain** (`kSecUseDataProtectionKeychain`) on a build that is sideloaded, signed with an ad-hoc identity, and has no keychain-access-groups entitlement of its own -- whether `SecItemAdd` answers 0 at all under those conditions;
* whether a **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** item survives, and what "survives" means here: the reason to prefer it is that a `ThisDeviceOnly` item does not travel in a backup, while the preferences file it would replace does. Whether it also survives an *uninstall* is a second, separate question -- and it is the one that decides whether the blob can be counted on at all.

Guessing either wrong costs a migration that breaks sign-in on the way back, so both get measured before anything moves.

## What the probe does

`KeychainProbe.run()` runs once at launch, after the diagnostic switches are read, and touches nothing else: one marker item per shape, under service `com.a23bc.dliparebuild.keychainProbe.<label>`, account `marker`, value `probe-<unix time of this launch>`. Per shape it logs four fields. The two lines below are the **shape** of the output with made-up values -- this branch has not been run yet, and that is the whole point of running it:

```
keychain probe classic: previous=probe-1762529814.512, delete=0, add=0, read-back=probe-1762533002.884
keychain probe data-protection: previous=absent, delete=-25300, add=0, read-back=probe-1762533002.884
```

* `previous` -- the value a **previous launch** left. Absent on the very first run, which is expected; what matters is the *second* launch.
* `delete` -- the status of the delete that precedes the write. `-25300` (`errSecItemNotFound`) on a first run is normal, not a failure.
* `add` -- the status of storing the item. **This is the answer to the first question.** Anything other than 0 for `data-protection` kills that shape on this signing setup.
* `read-back` -- what a fresh query returns. It must equal the value just written; the line is tagged `(DIFFERS FROM WHAT WAS WRITTEN)` when it does not, which would mean the write was answered from the call itself rather than stored.

## How to read the two lines

| outcome | what it rules |
| --- | --- |
| `data-protection add=0` and second launch shows `previous=<first launch's value>` | the whole plan is available: tokens, cookies, GUID and blob go to the data-protection keychain with `ThisDeviceOnly`, and the blob survives relaunch |
| `data-protection add=0`, but `previous=absent` on every launch | writes work, persistence does not -- migration must keep the blob somewhere else and the keychain is usable only for in-process state. This is the outcome to watch for, because `-34018` and silent non-persistence are the two classic failures under an ad-hoc signature |
| `data-protection add` non-zero, `classic add=0` | the data-protection class is out on this signing setup; fall back to the classic generic-password shape, which loses the "not in backup" property -- and then the honest description of the change is "out of the preferences file", not "out of backups" |
| both non-zero | keychain writes are broken on this build in a way the password path has not shown, and the first place to look is what changed since 2026-11-06, not the keychain |

After a reinstall: `previous` present means keychain items outlive the container, which is exactly the durability the blob wants. `previous=absent` after a reinstall and present before it means items die with the app, and the blob's durability argument moves to "not purged like `Library/Caches`", which the classic shape still gives.

## How to run it

1. Install the package, and turn **Record log** on first -- these lines go through `AppLog.info`, and with recording off the in-app window stays empty, so there is nothing to share.
2. Launch, wait for the two lines (they are near `map census:` in the same block), then launch once more.
3. For the reinstall half: delete the app, reinstall the same package, launch, and keep the second pair of lines too.
4. Send the log; the four fields per shape per launch are the whole deliverable.

The marker item is left in place on purpose -- the next launch's `previous` is the measurement. Nothing else reads this service, and the values are timestamps, not credentials.
