import UIKit

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
