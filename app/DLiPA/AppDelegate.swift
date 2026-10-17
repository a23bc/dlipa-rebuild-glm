import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions:
                        [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        print("[DLiPA] AppDelegate.didFinishLaunchingWithOptions start")
        // The four Apple SAP binaries are about 119 MB. Copying them on the
        // main thread would stall launch, so staging runs in the background
        // and signing is blocked until it finishes.
        AssetStaging.stageIfNeeded { error in
            if let error {
                AppLog.error("staging failed: " + String(describing: error), .assets)
                print("[DLiPA] AppDelegate: staging failed: \(error)")
            } else {
                print("[DLiPA] AppDelegate: staging completed")
            }
        }
        print("[DLiPA] AppDelegate.didFinishLaunchingWithOptions returning true")
        return true
    }

    // MARK: UISceneSession Lifecycle

    func application(_ application: UIApplication,
                     configurationForConnecting connectingSceneSession: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
    }
}
