#!/bin/bash
# 在 Mac + Xcode + Go 1.20 上生成 Protect.framework / Protect.xcframework
# Windows 无法交叉编译 iOS。
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
  export CGO_CFLAGS="-isysroot $SDK -target $triple -fPIC"
  export CGO_LDFLAGS="-isysroot $SDK -target $triple -fPIC -Wl,-install_name,@rpath/Protect.framework/Protect"
  go build -trimpath -ldflags "-s -w" -buildmode=c-shared -o "$outdir/Protect.dylib" ./cmd/protectlib
  mkdir -p "$outdir/Protect.framework/Headers" "$outdir/Protect.framework/Modules"
  mv "$outdir/Protect.dylib" "$outdir/Protect.framework/Protect"
  rm -f "$outdir/Protect.h" "$outdir/"*.h
  cp "$ROOT/include/sdk_ios.h" "$outdir/Protect.framework/Headers/sdk_ios.h"
  cp "$ROOT/framework/Info.plist" "$outdir/Protect.framework/Info.plist"
  cp "$ROOT/framework/module.modulemap" "$outdir/Protect.framework/Modules/module.modulemap"
  chmod +x "$outdir/Protect.framework/Protect"
  install_name_tool -id @rpath/Protect.framework/Protect "$outdir/Protect.framework/Protect" || true
}

build_one iphoneos arm64 "$BUILD/ios-arm64"
# Apple Silicon 模拟器
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
