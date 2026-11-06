//
// Exposes the gomobile-generated C API to Swift.
//
// The symbols live in the app binary itself, not in an embedded framework.
// gomobile produced them as a c-archive that the link force-loads, so the
// bundle is a single executable like the original DLiPA, with no
// Frameworks/ directory. That matters: a nested framework is one more thing
// MobileInstallation has to accept during registration.
//

#import <Foundation/Foundation.h>
#include <sys/types.h>

// Everything SAP now goes through the Go bridge: handshake, signing, kbsync and
// the serial number. Sap/sap_guest.c is no longer compiled, so nothing here
// includes its header.
//
// The declarations below mirror Sapbridge.objc.h, which gomobile generates.
// They are copied by hand because the app links the c-archive rather than
// embedding the framework, so there is no header to import. A declaration
// missing here is invisible to Swift no matter what the archive exports, which is
// how generateKBSync first failed to build: the Go side and the archive were
// both correct. The workflow now checks the two lists against each other.

// ptrace is not in the public iOS SDK headers but exists in libSystem.
// PT_TRACE_ME = 0; used to set CS_DEBUGGED for JIT support.
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);

NS_ASSUME_NONNULL_BEGIN

@interface SapbridgeSigner : NSObject
- (nullable NSData *)sign:(NSData *)body error:(NSError **)error;
- (NSString *)signatureHeaderValue:(NSData *)body error:(NSError **)error;
- (nullable NSData *)generateKBSync:(NSString *)dsid error:(NSError **)error;
- (nullable NSString *)entDownload:(nullable NSString *)dsid token:(nullable NSString *)token storefront:(nullable NSString *)storefront endpoint:(nullable NSString *)endpoint cookieHeader:(nullable NSString *)cookieHeader appID:(long long)appID externalVersionID:(nullable NSString *)externalVersionID error:(NSError **)error;
- (nullable NSString *)storeSmoke:(nullable NSString *)dsid token:(nullable NSString *)token storefront:(nullable NSString *)storefront entEndpoint:(nullable NSString *)entEndpoint cookieHeader:(nullable NSString *)cookieHeader error:(NSError **)error;
- (nullable NSData *)hardware;
- (BOOL)close:(NSError **)error;
@end

FOUNDATION_EXPORT NSString * _Nonnull SapbridgeBundleDirValue(void);
FOUNDATION_EXPORT NSString * _Nonnull SapbridgeGuidFromHardware(NSData * _Nullable hardwareID);
FOUNDATION_EXPORT NSData * _Nullable SapbridgeKBSync(NSData * _Nullable hardwareID, NSString * _Nullable dsid, NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT SapbridgeSigner * _Nullable SapbridgeNew(NSString * _Nullable setupURL, NSString * _Nullable certURL, int32_t version, NSData * _Nullable hardwareID, NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT BOOL SapbridgeParseDSID(NSString * _Nullable value, int64_t * _Nullable ret0_, NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT NSString * _Nonnull SapbridgeSerialNumber(NSData * _Nullable hardwareID, NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT void SapbridgeSetBundleDir(NSString * _Nullable path);
// These take and return no pointers, so the nullability region they sit in
// makes no difference; they are here because the app needs them and the header
// check in build-ios.yml fails the build when a declaration present in
// gomobile's generated header is missing from this copy.
FOUNDATION_EXPORT BOOL SapbridgeAssetsCached(void);
FOUNDATION_EXPORT BOOL SapbridgeAssetFetchAllowed(void);
FOUNDATION_EXPORT void SapbridgeAllowAssetFetch(void);
// One-way on purpose: open() reads the choice once, so the row that flips it
// takes effect at the next launch, and there is nothing to undo mid-session.
// It takes no bool argument for the same reason the three above take none: the
// generated header proves how gomobile renders a bool return and says nothing
// about a bool argument.
FOUNDATION_EXPORT void SapbridgeEnableLazyCachePages(void);
// Also one-way, and for the same two reasons: nothing has to be undone inside a
// session, and a bool argument has no proven mapping. Read on every download, so
// unlike the cache switch it takes effect at the next account switch.
FOUNDATION_EXPORT void SapbridgeEnableAccountReopenProbe(void);

NS_ASSUME_NONNULL_END
FOUNDATION_EXPORT NSString * _Nullable SapbridgePatchIPA(NSString * _Nullable path, NSString * _Nullable email, NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT NSString * _Nullable SapbridgeStartInstallServer(NSString * _Nullable dataDir, NSString * _Nullable packagePath, NSString * _Nullable bundleID, NSString * _Nullable version, NSString * _Nullable title, NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT NSString * _Nullable SapbridgeInstallGuideURL(void);
FOUNDATION_EXPORT NSString * _Nullable SapbridgeBlankAudioPath(NSString * _Nullable dataDir, NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT NSString * _Nullable SapbridgeFetchSapAssets(NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT BOOL SapbridgeClearCachedKBSync(NSError * _Nullable * _Nullable error);