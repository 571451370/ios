#!/bin/bash
# 在 Mac + Xcode + Go 1.20 上生成 Protect.framework / Protect.xcframework
# iOS 不支持 -buildmode=c-shared，用 c-archive 再链成动态库。
set -euo pipefail
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "请在 Mac 上运行: ./build-framework.sh" >&2
  exit 1
fi
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
MIN="${IOS_MIN:-12.0}"
BUILD="$ROOT/build"
rm -rf "$BUILD"
mkdir -p "$BUILD"

build_one() {
  local sdkname="$1"
  local arch="$2"
  local outdir="$3"
  local SDK
  SDK="$(xcrun --sdk "$sdkname" --show-sdk-path)"
  local CLANG
  CLANG="$(xcrun --sdk "$sdkname" -f clang)"
  local triple
  if [[ "$sdkname" == "iphonesimulator" ]]; then
    triple="${arch}-apple-ios${MIN}-simulator"
  else
    triple="${arch}-apple-ios${MIN}"
  fi
  echo "build $sdkname $arch -> $outdir"
  mkdir -p "$outdir"
  export CGO_ENABLED=1
  export GOOS=ios
  export GOARCH="$arch"
  export CC="$CLANG"
  export GOCACHE="$BUILD/gocache-$sdkname-$arch"
  export CGO_CFLAGS="-isysroot $SDK -target $triple -fPIC"
  export CGO_LDFLAGS="-isysroot $SDK -target $triple -fPIC"
  go build -trimpath -ldflags "-s -w" -buildmode=c-archive -o "$outdir/Protect.a" ./cmd/protectlib

  local fw="$outdir/Protect.framework"
  mkdir -p "$fw/Headers" "$fw/Modules"
  "$CLANG" -dynamiclib \
    -isysroot "$SDK" \
    -target "$triple" \
    -fPIC \
    -o "$fw/Protect" \
    -install_name "@rpath/Protect.framework/Protect" \
    -Wl,-force_load,"$outdir/Protect.a" \
    -framework Foundation \
    -framework CoreFoundation \
    -framework Security \
    -lresolv
  rm -f "$outdir/Protect.h" "$outdir/"*.h "$outdir/Protect.a"
  cp "$ROOT/include/sdk_ios.h" "$fw/Headers/sdk_ios.h"
  cp "$ROOT/framework/Info.plist" "$fw/Info.plist"
  cp "$ROOT/framework/module.modulemap" "$fw/Modules/module.modulemap"
  chmod +x "$fw/Protect"
  install_name_tool -id @rpath/Protect.framework/Protect "$fw/Protect" || true
}

build_one iphoneos arm64 "$BUILD/ios-arm64"
# Apple Silicon 模拟器（失败不阻断真机包）
build_one iphonesimulator arm64 "$BUILD/ios-arm64-sim" || true
# Intel 模拟器
if [[ "$(uname -m)" == "x86_64" ]]; then
  build_one iphonesimulator amd64 "$BUILD/ios-amd64-sim" || true
fi

rm -rf "$ROOT/Protect.framework" "$ROOT/Protect.xcframework"
cp -R "$BUILD/ios-arm64/Protect.framework" "$ROOT/Protect.framework"

XC=( -framework "$BUILD/ios-arm64/Protect.framework" )
if [[ -d "$BUILD/ios-arm64-sim/Protect.framework" ]]; then
  XC+=( -framework "$BUILD/ios-arm64-sim/Protect.framework" )
fi
if [[ -d "$BUILD/ios-amd64-sim/Protect.framework" ]]; then
  XC+=( -framework "$BUILD/ios-amd64-sim/Protect.framework" )
fi
xcodebuild -create-xcframework "${XC[@]}" -output "$ROOT/Protect.xcframework"
echo "ok: $ROOT/Protect.framework"
echo "ok: $ROOT/Protect.xcframework"
