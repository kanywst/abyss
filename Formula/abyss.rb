class Abyss < Formula
  desc "Deep Insight OSINT Tool for passive reconnaissance"
  homepage "https://github.com/kanywst/abyss"
  url "https://github.com/kanywst/abyss/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256_OF_TARBALL"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    system "#{bin}/abyss", "--help"
  end
end
