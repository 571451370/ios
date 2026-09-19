#import <Protect/sdk_ios.h>
#import <UIKit/UIKit.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // 必须在游戏创建任何 socket 之前
    char config[] = "{\"access_key\":\"这里换成后台 iOS 接入码\"}";
    int result = protect_start(config);
    if (result != 0) {
        NSLog(@"protect_start rc=%d %s", result, protect_error_message());
    }
    return YES;
}

- (void)applicationWillTerminate:(UIApplication *)application {
    protect_stop();
}

@end
