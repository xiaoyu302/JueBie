import UIKit
import WebKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        
        let webConfig = WKWebViewConfiguration()
        webConfig.allowsInlineMediaPlayback = true
        webConfig.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        
        let webView = WKWebView(frame: UIScreen.main.bounds, configuration: webConfig)
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        webView.scrollView.bounces = false
        webView.isOpaque = false
        webView.backgroundColor = UIColor(red: 0.043, green: 0.055, blue: 0.078, alpha: 1.0)
        webView.scrollView.backgroundColor = UIColor(red: 0.043, green: 0.055, blue: 0.078, alpha: 1.0)
        
        // Load HTML from public folder in bundle
        if let publicPath = Bundle.main.path(forResource: "index", ofType: "html", inDirectory: "public") {
            let url = URL(fileURLWithPath: publicPath)
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        } else if let htmlPath = Bundle.main.path(forResource: "index", ofType: "html") {
            let url = URL(fileURLWithPath: htmlPath)
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        }
        
        let vc = UIViewController()
        vc.view = webView
        window?.rootViewController = vc
        window?.makeKeyAndVisible()
        
        return true
    }
}
