#!/bin/sh
set -eu

printf '%s\n' "$VERSION" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || { echo "bad VERSION: $VERSION" >&2; exit 1; }
for sha in "$SHA_MACOS_AARCH64" "$SHA_MACOS_X86_64" "$SHA_LINUX_AARCH64" "$SHA_LINUX_X86_64"; do
  printf '%s\n' "$sha" | grep -Eqx '[0-9a-f]{64}' || { echo "bad sha256: $sha" >&2; exit 1; }
done

base="https://github.com/razvandimescu/natty/releases/download/v$VERSION"

cat <<EOF
class Natty < Formula
  desc "TCP services by name between two keys, through a natty relay"
  homepage "https://github.com/razvandimescu/natty"
  version "$VERSION"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    if Hardware::CPU.arm?
      url "$base/natty-macos-aarch64.tar.gz"
      sha256 "$SHA_MACOS_AARCH64"
    else
      url "$base/natty-macos-x86_64.tar.gz"
      sha256 "$SHA_MACOS_X86_64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$base/natty-linux-aarch64.tar.gz"
      sha256 "$SHA_LINUX_AARCH64"
    else
      url "$base/natty-linux-x86_64.tar.gz"
      sha256 "$SHA_LINUX_X86_64"
    end
  end

  def install
    bin.install "natty"
  end

  test do
    ENV["NATTY_KEY"] = testpath/"key"
    assert_match(/\A[a-z0-9]{52}\n\z/, shell_output("#{bin}/natty key"))
  end
end
EOF
