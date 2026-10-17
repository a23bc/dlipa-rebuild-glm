import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions:
                        [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // The four Apple SAP binaries are about 119 MB. Copying them on the
        // main thread would stall launch, so staging runs in the background
        // and signing is blocked until it finishes.
        AssetStaging.stageIfNeeded { error in
            if let error {
                AppLog.error("staging failed: " + String(describing: error), .assets)
            }
        }
        return true
    }

    // MARK: UISceneSession Lifecycle

    func application(_ application: UIApplication,
                     configurationForConnecting connectingSceneSession: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
    }
}
