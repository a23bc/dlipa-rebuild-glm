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

// ptrace is not in the public iOS SDK headers but exists in libSystem.
// PT_TRACE_ME = 0; used to set CS_DEBUGGED for JIT support.
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);

NS_ASSUME_NONNULL_BEGIN

@interface SapbridgeSigner : NSObject
- (nullable NSData *)sign:(NSData *)body error:(NSError **)error;
- (NSString *)signatureHeaderValue:(NSData *)body error:(NSError **)error;
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

NS_ASSUME_NONNULL_END
