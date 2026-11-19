#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>

// The client half of anisette, as AuthKit declares it. These are private
// classes, so the interface is restated here rather than imported: the point of
// the probe is to find out whether the daemon behind them answers a
// third-party process at all.
@interface AKAnisetteData : NSObject
- (NSData *)machineID;
- (NSData *)oneTimePassword;
- (unsigned long long)routingInfo;
@end

@interface AKAnisetteProvisioningController : NSObject
- (void)anisetteDataWithCompletion:(void (^)(AKAnisetteData *data, NSError *error))completion;
@end

static void DLPAFinish(void (^callback)(NSString *), NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        callback(message);
    });
}

void DLPAProbeAnisetteDaemon(void (^callback)(NSString *)) {
    if (callback == nil) {
        return;
    }

    // AuthKit lives in the dyld shared cache and is not loaded until something
    // asks for it. NSClassFromString alone returns nil on a cold process.
    void *handle = dlopen("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit", RTLD_NOW);
    if (handle == NULL) {
        handle = dlopen("AuthKit", RTLD_NOW);
    }

    NSString *loadNote = handle == NULL ? @"dlopen=FAIL" : @"dlopen=OK";

    Class controllerClass = NSClassFromString(@"AKAnisetteProvisioningController");
    if (controllerClass == nil) {
        DLPAFinish(callback, [NSString stringWithFormat:@"%@ class=missing", loadNote]);
        return;
    }

    id controller = [[controllerClass alloc] init];
    SEL selector = NSSelectorFromString(@"anisetteDataWithCompletion:");

    if (controller == nil || ![controller respondsToSelector:selector]) {
        DLPAFinish(callback, [NSString stringWithFormat:@"%@ class=OK selector=missing", loadNote]);
        return;
    }

    __block BOOL finished = NO;
    void (^finish)(NSString *) = ^(NSString *message) {
        if (finished) {
            return;
        }

        finished = YES;
        DLPAFinish(callback, message);
    };

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        finish([NSString stringWithFormat:@"%@ callback=none within 5s", loadNote]);
    });

    [(AKAnisetteProvisioningController *)controller anisetteDataWithCompletion:^(AKAnisetteData *data, NSError *error) {
        if (error != nil) {
            finish([NSString stringWithFormat:@"%@ error=%@", loadNote, error.localizedDescription]);
            return;
        }

        if (data == nil) {
            finish([NSString stringWithFormat:@"%@ data=nil", loadNote]);
            return;
        }

        finish([NSString stringWithFormat:@"%@ mid=%lu otp=%lu routing=%llu",
                loadNote,
                (unsigned long)data.machineID.length,
                (unsigned long)data.oneTimePassword.length,
                data.routingInfo]);
    }];
}
