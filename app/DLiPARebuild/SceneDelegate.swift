import SwiftUI
import UIKit

// The class must be exposed to the ObjC runtime under the bare name
// "SceneDelegate" (no module prefix) because Info.plist's
// UIApplicationSceneManifest references it by that name. Swift app-target
// classes are normally reachable under "<Module>.<Class>", and UIKit's
// NSClassFromString("SceneDelegate") fails without the @objc name below,
// which leaves the app with no scene delegate and therefore no UI.
@objc(SceneDelegate)
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {

    var window: UIWindow?

    func scene(_ scene: UIScene,
               willConnectTo session: UISceneSession,
               options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else {
            print("[DLiPA] SceneDelegate: scene is not UIWindowScene")
            return
        }

        print("[DLiPA] SceneDelegate: creating window")
        let window = UIWindow(windowScene: windowScene)
        // The app is a SwiftUI shell now. It is hosted in the existing
        // UIKit scene so the launch path, logging and icon plumbing stay
        // exactly as they were; only the view hierarchy changed.
        let vc = UIHostingController(rootView: RootTabView())
        window.rootViewController = vc
        window.backgroundColor = .systemBackground
        self.window = window
        window.makeKeyAndVisible()
        print("[DLiPA] SceneDelegate: window visible, rootViewController=\(type(of: vc))")
    }
}
