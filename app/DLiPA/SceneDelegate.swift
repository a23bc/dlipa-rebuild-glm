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
        let vc = MainViewController()
        window.rootViewController = UINavigationController(rootViewController: vc)
        window.backgroundColor = .systemBackground
        self.window = window
        window.makeKeyAndVisible()
        print("[DLiPA] SceneDelegate: window visible, rootViewController=\(type(of: vc))")
    }
}
