# 客户端 SDK 接入步骤（iOS）

玩家机上的 Frontend + Backend 用 Go 实现，打成 `Protect.framework`。
iOS **不用 VPN / Network Extension**，只改本 App 里的 `connect` / `sendto`，把游戏流量转到 `127.0.0.1`，再走和 PC/Android 相同的 smux + PROXY v2 + 续传。

接入码**区分平台**，后台创建时要选 **iOS**。

## 接入要求

- 需要有项目源码，开发环境正常可重新编译发布。
- 具备一定的开发能力，可根据 API 文档和程序样例加入 SDK 启动代码。
- **必须用 Mac + Xcode** 编译本 SDK（Windows 编不出 iOS framework）。

## 准备素材

1. 准备项目源码和开发环境，测试可正常编译。
2. 在 Mac 上生成 `Protect.framework`（见文末「生成 Framework」），放到游戏工程。

## 加载说明

准备好 Mac，安装好 Xcode，确保原有项目可以正常编译。  
Build Settings 里如果有 **Enable Bitcode**，需要关闭（Go 运行时不支持 Bitcode；Xcode 14 起该选项已移除可忽略）。

1. 将 `Protect.framework` 拖到 Xcode Project Navigator 的 Frameworks 下，勾选 **Copy items if needed**。  
   若已生成 `Protect.xcframework`，优先拖 xcframework（真机 + 模拟器）。
2. 打开当前 Target 的 **General** → **Frameworks, Libraries, and Embedded Content**，把 Protect 设为 **Embed & Sign**。
3. Info.plist 增加 ATS 例外（管理端 API 是 HTTP）。把 `sample/ATS.Info.plist.fragment.xml` 里的键合并进游戏 Info.plist。
4. **在游戏创建任何 socket 之前**启动：

```objc
// 引入
#import <Protect/sdk_ios.h>

// 配置（后台 iOS 平台接入码）
char config[] = "{\"access_key\":\"接入码\"}";

// 启动 (返回 0 表示成功, 其他表示错误)
int result = protect_start(config);
if (result != 0) {
    NSLog(@"protect_start %d %s", result, protect_error_message());
}
```

Swift：

```swift
import Protect

let config = "{\"access_key\":\"接入码\"}"
let result = config.withCString { protect_start($0) }
```

App 退出前：

```objc
protect_stop();
```

样例：`sample/AppDelegate.m`。

错误码：`0` 成功，`1` 已启动，`2` 配置，`3` 拉节点，`4` 本机监听，`5` hook 失败。

游戏 connect 的地址必须和后台 LocalList 一致（例如 `tcp://127.99.99.88:2222`）。不要改成直连源站公网 IP。

## 生成 Framework（Mac）

```bash
# Go 1.20、Xcode Command Line Tools
cd /path/to/iOSsdk
chmod +x build-framework.sh
./build-framework.sh
```

产出：

- `Protect.framework`（真机 arm64，可直接按上面步骤接入）
- `Protect.xcframework`（真机 + 模拟器，推荐）

本仓库在 Windows 上只能改源码；framework 必须在 Mac 或 GitHub Actions 上编。

推到 `main` 后会自动编译。打开 [Actions](https://github.com/571451370/ios/actions) → 最新一次 **Build Protect.framework** → 下载产物 **Protect-iOS-SDK**（`Protect.xcframework.zip`）。也可在 Actions 页点 **Run workflow** 手动再编一次。

## 原理

```
游戏 connect/sendto
    →（iOS）fishhook 改到 127.0.0.1:SDK端口
    → Go 监听
    → smux 隧道 → Server → Proxy → 游戏服
```

Go 自己的隧道拨号走 syscall，**不会**进 libc hook。切高防与 Android/PC 相同：会话 key `GUID|dst` + 续传。
