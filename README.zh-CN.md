# DLiPA — SAP 适配版重建

[English](README.md) · [简体中文](README.zh-CN.md)

DLiPA 失效，是因为 Apple 现在要求 App Store 私有 API 请求携带
`X-Apple-ActionSignature` 头，同时 `bag.xml` 里通告的下载端点搬到了 `ent/download`。
本仓库把这两处改动做进了应用，并在 GitHub Actions 上产出可安装的 IPA。

**当前状态**：登录、kbsync、签名、搜索、账号处理、版本历史与**下载**都已在真机跑通。
下载不再走经典的 `volumeStoreDownloadProduct` 请求——改由 Store 自己的代码在模拟 guest 里
组装 `ent/download` 请求。这既是 Apple 现在的要求，也是本项目绝大部分工作量所在。
它怎么工作、每一块为什么长成这样，见 [`docs/architecture.md`](docs/architecture.md)。

下载在后台运行：点一下立刻返回，进度在 Downloads 页，模拟的 Store runtime 干活期间应用照常
可用——现在是秒级，因为共享缓存改成先建索引、按需映射，不再每次 open 全量映射。

**不需要 Apple 开发者账号。** IPA 已封装但没有证书签名，用你自己的 Apple ID 通过 AltStore
或 Sideloadly 签一次即可——与原版 DLiPA 的 README 推荐的是同一套流程。

---

## 当初坏在哪，这里改了什么

| 问题 | 证据 | 这里的做法 |
|---|---|---|
| 请求没有签名 | 签名请求 → HTTP 200 + session cookie；不签名 → **HTTP 403** | `sapbridge` 给每个 body 签名 |
| authenticate URL 少了结尾的斜杠 | 没有它 Apple 返回 **HTTP 204** 空响应；加上即 HTTP 200 | `AppStoreClient.authenticate` 补 `/` |
| 经典下载请求被拒 | `volumeStoreDownloadProduct` 返回 **2042**（`AuthTokenResumeFreeBuy`），它的 `buyProduct` 兜底返回 `MZCommerce.SystemError` | 不再手工构造请求：由 Store 自己的编码器在模拟 guest 里组装 |
| 请求签了名仍被拒 | 空 body 的 500，逐字段试了五次 | `Content-Type: x-www-form-urlencoded`、`User-Agent: Configurator/2.18`、**session cookies**、`salableAdamId` 用*字符串*、`externalVersionId` 非空 |
| 没有 kbsync blob | `ent/download` 用 kbsync 把下载绑定到账号与设备 | `internal/sap/ent_fetch.go` 在 runtime 打开**之前**生成 |
| guid 是随机 UUID | `ent/download` 要求 6 字节 GUID | `HardwareIdentity.stable()` |
| dsid 是字符串 | `ent/download` 要求十进制 DSID | `SAPSigner.parseDSID` |

前两行背后的对照实验在 `../SIGNATURE_EXPERIMENT.md`。

---

## 目录结构

路径与文件名不译，保留原样：

    app/                        Xcode project (XcodeGen) + Swift sources
      project.yml               target DLiPARebuild, iOS 15, name auto-picked
      DLiPARebuild/
        DLiPA-Bridging-Header.h  hand-written declarations for the Go archive
        Networking/
          AppStoreClient.swift   signed transport, bag, login, download
          StoreBag.swift         bag.xml parsing (handles loc- prefix)
          SAPSigner.swift        wraps the Go bridge
          AssetStaging.swift     stages the SAP binaries: copied from the bundle
                                 when one ships them, fetched from Apple otherwise
        Model/
          AppSession.swift       session, account, the download primitive
          DownloadManager.swift  jobs that outlive the screen that started them
          StoreApp.swift         catalogue entry
        UI/
          SearchScreen.swift     search, download, version sheet
          VersionListView.swift  version ids, tap to download that build
          DownloadsScreen.swift  running and finished downloads, one list
          AccountsScreen.swift  SettingsScreen.swift  DiagnosticsScreen.swift
        Logging/
          StderrCapture.swift    previous launch's stderr, shareable from the app
    sapbridge/                  Go module
      sapbridge.go              Sign / KBSync / StoreSmoke / EntDownload (bridge)
      internal/sap/
        signer_local.go         the machine, the session, one store runtime
        ent_fetch.go            production ent/download through the encoder
        store_smoke.go          the diagnostic probe (E1-E4 live here first)
        machine/ machimage/     the arm64 guest and the Mach-O loader
      internal/store/
        emulator/               Store runtime: mapping, hooks, encoder, Execute
        profile/ cachepages/    recorded pages, and the dyld cache slice
    scripts/
      check-bridging-header.py  generated header vs the hand-written one
      build-unicorn-ios.sh      cross-compiles Unicorn TCI
      package-ipa.sh            sealed .app -> .ipa
    docs/architecture.md        how the pieces fit and why
    VendorAssets/               extraction output of the Fetch SAP assets
                                workflow; gitignored, and no build needs it
    .github/workflows/
      build-ios.yml             macOS runner: bridge -> app -> IPA -> artifact

---

## 文档

* **[docs/architecture.md](docs/architecture.md)** — 各部分怎么拼起来：两个租户（tenant）
  共用一个 guest、为什么 Store runtime 只打开一次并一直留着、下载流程的端到端、被具体
  失败逼出来的那些决定，以及在真机上打开一次要付多少代价。
* `DELIVERY_STATUS.md` — 现在什么能用、什么不能用，以及证据。
* `sapbridge/VERIFICATION.md` — Go 侧的构建与测试矩阵。
* **[docs/RELEASING.md](docs/RELEASING.md)** — 哪个版本字段是人为决定、哪个是运行计数，
  产物名字里带的是什么，以及 bundle 用什么封装的。

---

## 构建

### 走 GitHub Actions（推荐）

推送到 `main`，或开一个 pull request。工作流跑两个 job：

1. **go-bridge** — 跑单元测试、为 iOS arm64 交叉编译 Unicorn、用 gomobile 把 Go 模块
   绑成 `SapBridge.framework`。
2. **app** — 下载 framework 并构建应用。这一步不碰那四个 Apple 二进制：它们不在 bundle
   里，应用第一次需要签名时在设备上从 Apple 取。随后用生成的 CodeResources 封装、
   打包成 `DLiPARebuild-<digest>.ipa`、作为 artifact 上传。打 tag 的推送还会附到 release 上。

也可以在 Actions 页手动点 **Run workflow**。

### 本地（macOS + Xcode）

    brew install ldid cmake xcodegen

    # 1. Unicorn for iOS
    ./scripts/build-unicorn-ios.sh

    # 2. bind the Go bridge
    cd sapbridge
    CGO_ENABLED=1 GOOS=ios GOARCH=arm64 gomobile bind \
      -target=ios/arm64 -o ../app/DLiPARebuild/Frameworks/SapBridge.xcframework .
    cd ..

    # 3. generate the project and build
    cd app
    xcodegen generate
    xcodebuild -project DLiPARebuild.xcodeproj -scheme DLiPARebuild \
      -configuration Release -sdk iphoneos \
      -destination "generic/platform=iOS" \
      CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO

    # 4. package
    ./scripts/package-ipa.sh build/Build/Products/Release-iphoneos/DLiPARebuild.app DLiPARebuild.ipa

## 安装

从工作流运行里下载 `DLiPARebuild-<digest>.ipa`——文件名带一段二进制摘要，所以旧副本不会
被当成当前构建（或某个 release）。然后：

- **AltStore** — My Apps 页，点 +，选择 IPA，用你的 Apple ID 登录
- **Sideloadly** — 把 IPA 拖进去，登录

免费 Apple ID 的证书 7 天到期，每周重签一次；付费开发者账号是一年。

---

## 范围

这是**功能内核**，不是 DLiPA 1.4 的完整 UI 复刻。它实现了登录、搜索、版本历史和签名下载
链路——也就是需要修的那几块。

已知缺口，大致按会不会先撞上来排序：

* 经典的 `volumeStoreDownloadProduct` 仍作为兜底保留。它对已登录会话返回 `2042`，它的
  `buyProduct` 兜底返回 `SystemError`，所以实际不贡献任何东西；等编码器链路在真实使用中
  跑一段时间就删掉。
* 不支持购买，因此账号本来就不拥有的应用下载不了。这里只负责下载，不负责买。
* store runtime 打开一次就一直留着，因为 guest 里带着账号的会话状态——所以切换账号需要
  重启应用。现在一次 open 约 1.2 s，而共享缓存还是全量映射时要约 99 s（见架构文档）。
  原版应用的 100 个 Objective-C 类、12 种本地化、CocoaHTTPServer 安装流程和
  SSZipArchive 打包没有复刻；源码从未公开，只有编译好的 IPA。

## 许可

本项目自己的代码是 [AGPL-3.0](LICENSE)。从 DLiPA 和 ipatool 继承的代码仍按 MIT；
见 [NOTICE](NOTICE) 与 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。

所依赖的组件各自保留自己的条款，其中几条要紧：**Unicorn 是 GNU GPL v2 且被静态链接**，
它的条款随二进制一起传播。它不是上游 Unicorn：构建用的是
[1rhino2/unicorn-tci](https://github.com/1rhino2/unicorn-tci)，一个恢复了 QEMU TCI 解释器
的 fork，锁定在某个 commit 上。上游只发 JIT，而非越狱设备上 iOS 拒绝可执行的匿名内存，
转译缓存根本分配不出来。完整拆分——ipatool、Unicorn、Go 依赖、Apple 二进制，以及从原版
DLiPA 1.4 取用的资源——在 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) 里。

## 致谢

- [unicorn-tci](https://github.com/1rhino2/unicorn-tci)，作者 1rhino2 —— 本应用所针对的
  Unicorn TCI fork，GPL v2 加链接例外
- [Unicorn](https://github.com/unicorn-engine/unicorn)，作者 Nguyen Anh Quynh 及贡献者 ——
  那个 fork 所源自的 CPU 模拟器
- [ipatool](https://github.com/majd/ipatool)，作者 Majd Alfhaily —— 本项目 vendor 的 SAP
  签名栈，MIT
- [DLiPA](https://github.com/AhmedBafkir/DLiPA)，作者 Ahmed Bafkir —— 原版应用
