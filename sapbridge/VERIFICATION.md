# Go 桥（sapbridge）独立模块验证记录

本轮把 Go 桥从"ipatool 仓库里的补丁"改成**独立可编译模块**，
放在 `dlipa-rebuild/sapbridge/`，并裁掉了不需要的代码。

---

## 1. 为什么裁剪

原计划是"把 4 个 Apple 二进制打进 ipa"（BUILD_PLAN.md 方案 A），
所以**运行时下载整条链都不需要**：

    assets/aea.go       AEA1 解密（从 macOS IPSW 取资产才需要）
    assets/apfs.go      APFS 解析
    assets/dyld.go      dyld shared cache 解析
    assets/remote.go    远程 zip 读取
    assets/http_range.go HTTP Range

删掉后连带去掉了这些重依赖：go-apfs、lzfse、sevenzip、go-macos-pkg。
另外删掉 unicorn 的下载/缓存机制（iOS 是静态链接）和 Windows 专用代码。

裁剪结果：41 个 Go 文件 224 KB -> 23 个文件，依赖只剩 3 个直接依赖：

    github.com/blacktop/go-macho v1.1.282
    github.com/ebitengine/purego   v0.10.2
    howett.net/plist               v1.0.1

---

## 2. 验证结果

| 目标 | 命令 | 结果 |
|---|---|---|
| windows/amd64 | go build ./... | BUILD=0 |
| windows/amd64 | go vet ./... | VET=0 |
| windows/amd64 | go test . | 8/8 PASS |
| linux/arm64 | go build ./... | BUILD=0 |
| linux/arm64 | go vet ./... | VET=0 |
| ios/arm64 | go list -f "{{.GoFiles}}" | 选中 library_ios.go |
| ios/arm64 | go list -deps 含 apfs/lzfse/sevenzip | 0 个 |
| gofmt | gofmt -l . | 无输出 |

单测（8 个，全过）：

    TestSerialNumberByteLayout           钉住 base64(54 c8 b0 a9 88 ++ guid[2:])
    TestSerialNumberRejectsWrongLength    非 6 字节拒绝
    TestGuidFromHardware                  大写 hex
    TestParseDSID                         合法/非法 DSID
    TestKBSyncRejectsZeroDSID             零 DSID 拒绝
    TestNilSignerFailsClosed              nil signer 不静默出空签名
    TestNewRejectsBadHardware             握手前校验
    TestSignatureHeaderValueIsSingleLine  HTTP 头注入防护

还有 2 个 live 测试（TestLiveSAPHandshake / TestLiveKBSync），
本机 Windows 无 Unicorn 所以 SKIP；它们的设计是缺资产/网络时 skip 而不是 fail，
这样 CI 不会因为环境问题红。

---

## 3. iOS 上为什么需要 CGO

`GOOS=ios CGO_ENABLED=0` 会在 purego 编译时报：

    is_ios.go:13:9: undefined: _PUREGO_REQUIRES_CGO_ON_IOS

这是 purego 自己的保护（iOS 不允许运行时 dlopen）。
所以 iOS 构建必须 `CGO_ENABLED=1`，由 macOS runner 上的 clang 完成。
ipatool 的 build-ios.sh 已经设了 CGO_ENABLED=1，这点是对的。

本机（Windows）没有 clang + iPhoneOS SDK，所以 iOS 那一步只能在 runner 上做。

---

## 4. 改动清单

对上游拷贝做的修改（其余为逐字拷贝）：

| 文件 | 改动 |
|---|---|
| assets/assets.go | 删掉 resolveRemoteImage 回退，改成明确报错 |
| unicorn/library_unix.go | 重写：不再下载，改为搜索系统 libunicorn 或读 DLIPA_UNICORN_PATH |
| unicorn/library_windows.go | 改为 stub（本 trim 构建不支持 Windows） |
| unicorn/engine_config_windows.go | 新增 stub |
| 全部 | import 路径改成模块自己的路径 |
