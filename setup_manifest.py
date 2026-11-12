"""Committed, hash-pinned download manifest for external lint binaries and SDKs."""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse

# Sources (official release / checksum URLs read on Nov 6, 2026; Rust, .NET,
# csharpier and PSScriptAnalyzer re-read on Nov 10, 2026):
# - rust 1.97.1 standalone installer: https://static.rust-lang.org/dist/rust-1.97.1-<target>.tar.xz.sha256,
#   cross-checked against [pkg.rust] xz_hash in https://static.rust-lang.org/dist/channel-rust-1.97.1.toml
#   (whose own SHA-256 is RUST_CHANNEL_MANIFEST_SHA256 below)
# - go 1.27.3: https://go.dev/dl/?mode=json
# - dotnet SDK 10.0.404: https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json
# - csharpier 1.3.0 .nupkg: SHA-512 "packageHash" in the NuGet catalog entry
#   https://api.nuget.org/v3/catalog0/data/2026.06.07.17.51.05/csharpier.1.3.0.json
# - pwsh 7.6.9: https://github.com/PowerShell/PowerShell/releases/tag/v7.6.9
# - PSScriptAnalyzer 1.25.0 .nupkg: SHA-512 "PackageHash" in
#   https://www.powershellgallery.com/api/v2/Packages(Id='PSScriptAnalyzer',Version='1.25.0')
# - golangci-lint 2.15.0: https://github.com/golangci/golangci-lint/releases/tag/v2.15.0
# - biome 2.6.6: https://github.com/biomejs/biome/releases/tag/%40biomejs%2Fbiome%402.6.6
# - oxlint 1.92.0: https://github.com/oxc-project/oxc/releases/tag/oxlint_v1.92.0
# - stylua 2.6.0: https://github.com/JohnnyMorganz/StyLua/releases/tag/v2.6.0
# - selene 0.32.0: https://github.com/Kampfkarren/selene/releases/tag/0.32.0
# - glslang 16.6.0: https://github.com/KhronosGroup/glslang/releases/tag/16.6.0
# - dxc 1.9.2609: https://github.com/microsoft/DirectXShaderCompiler/releases/tag/v1.9.2609

OFFICIAL_HOSTS: frozenset[str] = frozenset(
    {
        "github.com",
        "static.rust-lang.org",
        "go.dev",
        "builds.dotnet.microsoft.com",
        # NuGet's official package content (flat container) for csharpier.
        "api.nuget.org",
        # The PowerShell Gallery's official package endpoint for PSScriptAnalyzer.
        "www.powershellgallery.com",
    }
)

# Download CDNs the official first hops redirect to. A redirect to any other
# host (or to a non-https URL) is refused; the pinned checksum still decides.
OFFICIAL_REDIRECT_HOSTS: frozenset[str] = frozenset(
    {
        "release-assets.githubusercontent.com",  # github.com release assets
        "objects.githubusercontent.com",  # github.com release assets (older CDN name)
        "dl.google.com",  # go.dev/dl/
        "cdn.powershellgallery.com",  # www.powershellgallery.com/api/v2/package/
    }
)

# SHA-256 of https://static.rust-lang.org/dist/channel-rust-1.97.1.toml, equal to
# the publisher's channel-rust-1.97.1.toml.sha256; the rust downloads below are
# the [pkg.rust] artifacts that manifest lists, with the same hashes.
RUST_VERSION = "1.97.1"
RUST_CHANNEL_MANIFEST_SHA256 = "03569b1886ceb5c05276b50c8431ab111de944cd6140fe1fa7d821dd8e0f29cf"
# Components merged from the standalone installer (the rest are not extracted).
RUST_COMPONENTS: tuple[str, ...] = ("rustc", "cargo", "rustfmt-preview", "clippy-preview")

_ALLOWED_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "install_dir",
        "bin_dir",
        "real_home",
        "pkg_dir",
    }
)

_HASH_LENGTHS: dict[str, int] = {
    "sha256": 64,
    "sha512": 128,
}

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_BRACE_RE = re.compile(r"\{([^{}]*)\}")


@dataclass(frozen=True)
class Binary:
    """Mapping from archive path to the exposed command name in bin_dir."""

    path: str
    name: str


@dataclass(frozen=True)
class Download:
    """Single platform-specific downloadable artifact and extraction metadata."""

    url: str
    hash: str
    hash_algo: str
    hash_source: str
    archive: str
    strip_components: int = 0
    binaries: tuple[Binary, ...] = ()
    chmod: bool = True
    # Only these top-level directories (after strip_components) are extracted.
    include: tuple[str, ...] = ()
    # "" (archive is the install tree) or "rust-components" (merge each
    # included rust-installer component per its manifest.in).
    layout: str = ""


@dataclass(frozen=True)
class Package:
    """Checksum-pinned follow-up package (.nupkg) installed from a verified local file.

    kind "dotnet-tool": placed in {pkg_dir} next to a NuGet.config that lists
    only {pkg_dir}, then `dotnet tool install --configfile` reads it from there.
    kind "pwsh-module": extracted by Defuzz into the PowerShell CurrentUser
    modules folder (no Install-Module, no Gallery access by PowerShell).
    """

    name: str
    version: str
    kind: str
    url: str
    hash: str
    hash_algo: str
    hash_source: str
    filename: str
    size_mb: int = 0


@dataclass(frozen=True)
class SetupItem:
    """Hash-pinned external lint binary or SDK specification."""

    name: str
    kind: str
    version: str
    homepage: str
    size_mb: int
    provides: tuple[str, ...]
    skip_if_on_path: tuple[str, ...]
    downloads: Mapping[tuple[str, str], Download]
    post_install: tuple[tuple[str, ...], ...] = ()
    packages: tuple[Package, ...] = ()


def exe_name(name: str, plat: tuple[str, str]) -> str:
    """Return the platform-appropriate executable filename for command `name`."""
    if isinstance(plat, tuple) and len(plat) >= 1 and plat[0] == "windows":
        return name if name.endswith(".exe") else f"{name}.exe"
    return name


def _bins(*specs: str | tuple[str, str]) -> tuple[Binary, ...]:
    """Build a tuple of Binary mappings from bare command names or (path, name) pairs."""
    return tuple(
        Binary(path=s, name=s) if isinstance(s, str) else Binary(path=s[0], name=s[1])
        for s in specs
    )


def _dl(
    url: str,
    hash_val: str,
    archive: str,
    *bins: str | tuple[str, str],
    strip: int = 0,
    algo: str = "sha256",
    source: str = "published",
    include: tuple[str, ...] = (),
    layout: str = "",
) -> Download:
    """Construct a Download entry with standard sha256/published defaults."""
    return Download(
        url=url,
        hash=hash_val,
        hash_algo=algo,
        hash_source=source,
        archive=archive,
        strip_components=strip,
        binaries=_bins(*bins),
        include=include,
        layout=layout,
    )


_RUST_BINS: tuple[tuple[str, str], ...] = (
    ("bin/cargo", "cargo"),
    ("bin/rustc", "rustc"),
    ("bin/rustdoc", "rustdoc"),
    ("bin/rustfmt", "rustfmt"),
    ("bin/cargo-fmt", "cargo-fmt"),
    ("bin/cargo-clippy", "cargo-clippy"),
    ("bin/clippy-driver", "clippy-driver"),
)


def _rust_dl(target: str, hash_val: str) -> Download:
    """Standalone rust installer for target: verified, then merged into one prefix."""
    return _dl(
        f"https://static.rust-lang.org/dist/rust-{RUST_VERSION}-{target}.tar.xz",
        hash_val,
        "tar.xz",
        *_RUST_BINS,
        strip=1,
        include=(*RUST_COMPONENTS, f"rust-std-{target}"),
        layout="rust-components",
    )


CSHARPIER = Package(
    name="csharpier",
    version="1.3.0",
    kind="dotnet-tool",
    url="https://api.nuget.org/v3-flatcontainer/csharpier/1.3.0/csharpier.1.3.0.nupkg",
    hash="d3badd5ec6757d094c4e9aeef2048977754cef68c59e3f5368e2f5f936a88d06a66dff2231367df12e21673af63017859431daa8cea24670fe1b497309d047fe",
    hash_algo="sha512",
    hash_source="published",
    filename="csharpier.1.3.0.nupkg",
    size_mb=23,
)

PSSCRIPTANALYZER = Package(
    name="PSScriptAnalyzer",
    version="1.25.0",
    kind="pwsh-module",
    url="https://www.powershellgallery.com/api/v2/package/PSScriptAnalyzer/1.25.0",
    hash="e7fb573262e604bab29914ae62921d24b97c2f88b519b41277b403ef6ce163f14b7d1b36dc73449a68e5ae5a8d9502891b10c264131fd1813adf29bf131c1663",
    hash_algo="sha512",
    hash_source="published",
    filename="psscriptanalyzer.1.25.0.nupkg",
    size_mb=15,
)


ITEMS: tuple[SetupItem, ...] = (
    SetupItem(
        name="rust",
        kind="sdk",
        version=RUST_VERSION,
        homepage="https://www.rust-lang.org/",
        size_mb=650,
        provides=tuple(name for _, name in _RUST_BINS),
        skip_if_on_path=("cargo", "rustfmt", "cargo-clippy"),
        # No rustup: the pinned standalone installer is the whole toolchain.
        # Native Windows is not supported by the plugin; it has no rust entry.
        downloads={
            ("linux", "x86_64"): _rust_dl(
                "x86_64-unknown-linux-gnu",
                "88f28fa9af20594179f85d6df67078dfd6fa93e2f6da5e1e9b0ac4997988ca4f",
            ),
            ("linux", "aarch64"): _rust_dl(
                "aarch64-unknown-linux-gnu",
                "9a7a2c336b4787f1b72f6bab7c35d5b7af2fd03cbd39b4fc721466a70d402a7d",
            ),
            ("darwin", "aarch64"): _rust_dl(
                "aarch64-apple-darwin",
                "c9748cc86107734a2a024069908a895de7caa2d37062fb641eef9f756938ace2",
            ),
            ("darwin", "x86_64"): _rust_dl(
                "x86_64-apple-darwin",
                "891c32ea77b750dccc7fb0ea98e3feb9db3d29fe0cfea5907d002f270c59cf58",
            ),
        },
        post_install=(),
    ),
    SetupItem(
        name="go",
        kind="sdk",
        version="1.27.3",
        homepage="https://go.dev/",
        size_mb=350,
        provides=("go", "gofmt"),
        skip_if_on_path=("go",),
        downloads={
            ("linux", "x86_64"): _dl(
                "https://go.dev/dl/go1.27.3.linux-amd64.tar.gz",
                "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40",
                "tar.gz",
                ("bin/go", "go"),
                ("bin/gofmt", "gofmt"),
                strip=1,
            ),
            ("linux", "aarch64"): _dl(
                "https://go.dev/dl/go1.27.3.linux-arm64.tar.gz",
                "a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49",
                "tar.gz",
                ("bin/go", "go"),
                ("bin/gofmt", "gofmt"),
                strip=1,
            ),
            ("darwin", "aarch64"): _dl(
                "https://go.dev/dl/go1.27.3.darwin-arm64.tar.gz",
                "dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2",
                "tar.gz",
                ("bin/go", "go"),
                ("bin/gofmt", "gofmt"),
                strip=1,
            ),
            ("darwin", "x86_64"): _dl(
                "https://go.dev/dl/go1.27.3.darwin-amd64.tar.gz",
                "b6f8e931e4ab497fcde6da8ae4499a58f9d258e55c8a80824a516eae5950a750",
                "tar.gz",
                ("bin/go", "go"),
                ("bin/gofmt", "gofmt"),
                strip=1,
            ),
            ("windows", "x86_64"): _dl(
                "https://go.dev/dl/go1.27.3.windows-amd64.zip",
                "f26081f438319757f8a1b46d7d0b2c5ec7583d4038e485e0aa725cfde7885fff",
                "zip",
                ("bin/go.exe", "go"),
                ("bin/gofmt.exe", "gofmt"),
                strip=1,
            ),
        },
        post_install=(),
    ),
    SetupItem(
        name="dotnet",
        kind="sdk",
        version="10.0.404",
        homepage="https://dotnet.microsoft.com/",
        size_mb=450,
        provides=("dotnet", "csharpier"),
        skip_if_on_path=("dotnet", "csharpier"),
        downloads={
            ("linux", "x86_64"): _dl(
                "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-linux-x64.tar.gz",
                "577d0eb17fec33d029104c5c63a1ab0accc3e28776274abef2218dbac5af18d2109b5406d26b31d76f5c245215e3ba0926a94c20246c672c41847c9e1eb1dc50",
                "tar.gz",
                "dotnet",
                algo="sha512",
            ),
            ("linux", "aarch64"): _dl(
                "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-linux-arm64.tar.gz",
                "3533a3869da219cac45c567aadac3d8e96cdf1c6a04fe1c1d5fdeefea5d45af8424488f0144730d11b4a751f7ad546fb11e4c2b2725cd8401efee726711f8f11",
                "tar.gz",
                "dotnet",
                algo="sha512",
            ),
            ("darwin", "aarch64"): _dl(
                "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-osx-arm64.tar.gz",
                "1c9a13f625d0c08f08ef5a53597bababe3d2473527e98db2199210940c69dd5fc599a39a4d7c30ebf297ca2334a81b2f64b9bf05ff99585de9af4a5d85215e96",
                "tar.gz",
                "dotnet",
                algo="sha512",
            ),
            ("darwin", "x86_64"): _dl(
                "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-osx-x64.tar.gz",
                "88ca5dac50562b619f852b1b9845f85243f00434be52d2149db18ab4dc05f527f3fca8e1dac82e87b9eeb46a98de1ba4a6d612714caf2222f37b95aeebb611b6",
                "tar.gz",
                "dotnet",
                algo="sha512",
            ),
            ("windows", "x86_64"): _dl(
                "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-win-x64.zip",
                "330ddd2665b43cd2e428216a0d8ea1ac7bb19b5434fdc530e62010dc3b52823a620bf95489d628e1ed6f5122401793ee4887cca4a019122361a1231497f632ee",
                "zip",
                ("dotnet.exe", "dotnet"),
                algo="sha512",
            ),
        },
        post_install=(
            (
                "{install_dir}/dotnet",
                "tool",
                "install",
                "csharpier",
                "--version",
                "1.3.0",
                "--tool-path",
                "{bin_dir}",
                "--configfile",
                "{pkg_dir}/NuGet.config",
            ),
        ),
        packages=(CSHARPIER,),
    ),
    SetupItem(
        name="pwsh",
        kind="sdk",
        version="7.6.9",
        homepage="https://github.com/PowerShell/PowerShell",
        size_mb=200,
        provides=("pwsh",),
        skip_if_on_path=("pwsh",),
        downloads={
            ("linux", "x86_64"): _dl(
                "https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/powershell-7.6.9-linux-x64.tar.gz",
                "1da6d6d6035d651f20e70ddee7c4c15ac6ab8b9fb40ee92240d91263f28a884b",
                "tar.gz",
                "pwsh",
            ),
            ("linux", "aarch64"): _dl(
                "https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/powershell-7.6.9-linux-arm64.tar.gz",
                "02eb9991af447c7e7fe881acde195961afd397c40b8eb1c2b3856b84ec2d85f2",
                "tar.gz",
                "pwsh",
            ),
            ("darwin", "aarch64"): _dl(
                "https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/powershell-7.6.9-osx-arm64.tar.gz",
                "a1c7e98ac403da4be5ba75c1c5855af272de7787a91d478c4267466fe58fc1af",
                "tar.gz",
                "pwsh",
            ),
            ("darwin", "x86_64"): _dl(
                "https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/powershell-7.6.9-osx-x64.tar.gz",
                "a5aa2308a7e9664510a5c93d5b337fd524ff7dc14b8a637fb6144a2bbaa298ae",
                "tar.gz",
                "pwsh",
            ),
            ("windows", "x86_64"): _dl(
                "https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/PowerShell-7.6.9-win-x64.zip",
                "ce7484804c0f0ad4dda10c958e71acdaf7eebfb22505c1b480f89e0e9f1da94d",
                "zip",
                ("pwsh.exe", "pwsh"),
            ),
        },
        post_install=(),
        packages=(PSSCRIPTANALYZER,),
    ),
    SetupItem(
        name="golangci-lint",
        kind="binary",
        version="2.15.0",
        homepage="https://golangci-lint.run/",
        size_mb=35,
        provides=("golangci-lint",),
        skip_if_on_path=("golangci-lint",),
        downloads={
            ("linux", "x86_64"): _dl(
                "https://github.com/golangci/golangci-lint/releases/download/v2.15.0/golangci-lint-2.15.0-linux-amd64.tar.gz",
                "9b7fe6a6bf6334b98decf8d86b11415ea7889afdabdd1959fdce23af2a9ebcea",
                "tar.gz",
                "golangci-lint",
                strip=1,
            ),
            ("linux", "aarch64"): _dl(
                "https://github.com/golangci/golangci-lint/releases/download/v2.15.0/golangci-lint-2.15.0-linux-arm64.tar.gz",
                "b4d8f17068b35ee6060cc2f69a16fb48740d706fbba81661c318649c114a6998",
                "tar.gz",
                "golangci-lint",
                strip=1,
            ),
            ("darwin", "aarch64"): _dl(
                "https://github.com/golangci/golangci-lint/releases/download/v2.15.0/golangci-lint-2.15.0-darwin-arm64.tar.gz",
                "d1e409481a8ca846c4bc97e781eb5cb1bd5c23353a0b3977a1cbda1b1b6447d5",
                "tar.gz",
                "golangci-lint",
                strip=1,
            ),
            ("darwin", "x86_64"): _dl(
                "https://github.com/golangci/golangci-lint/releases/download/v2.15.0/golangci-lint-2.15.0-darwin-amd64.tar.gz",
                "767b899a28285e88ded2823d5dcc4bc5ef681173eb2d80f029a7b17ee4ece3b8",
                "tar.gz",
                "golangci-lint",
                strip=1,
            ),
            ("windows", "x86_64"): _dl(
                "https://github.com/golangci/golangci-lint/releases/download/v2.15.0/golangci-lint-2.15.0-windows-amd64.zip",
                "cd7ea6063c95de245e17e5246e42bdc14bb221792c429dbd239ab3a6ade6ca6a",
                "zip",
                ("golangci-lint.exe", "golangci-lint"),
                strip=1,
            ),
        },
        post_install=(),
    ),
    SetupItem(
        name="biome",
        kind="binary",
        version="2.6.6",
        homepage="https://biomejs.dev/",
        size_mb=28,
        provides=("biome",),
        skip_if_on_path=("biome",),
        downloads={
            ("linux", "x86_64"): _dl(
                "https://github.com/biomejs/biome/releases/download/%40biomejs%2Fbiome%402.6.6/biome-linux-x64",
                "69ca8e9ff548091b2bfbd178d6f73142b483a5257b07854de702c68fb7f8c06b",
                "binary",
                "biome",
            ),
            ("linux", "aarch64"): _dl(
                "https://github.com/biomejs/biome/releases/download/%40biomejs%2Fbiome%402.6.6/biome-linux-arm64",
                "bd0c5860a6220b68ceb82d7a00b7a4ed97fbaf3904eb41bcb897f9ec74af4148",
                "binary",
                "biome",
            ),
            ("darwin", "aarch64"): _dl(
                "https://github.com/biomejs/biome/releases/download/%40biomejs%2Fbiome%402.6.6/biome-darwin-arm64",
                "dec6124a5e3ea475e8625a7a85b5a2ec939c1077624f95b78cfc1cb96199fab1",
                "binary",
                "biome",
            ),
            ("darwin", "x86_64"): _dl(
                "https://github.com/biomejs/biome/releases/download/%40biomejs%2Fbiome%402.6.6/biome-darwin-x64",
                "b92f74faad4521cff6bc45b54fc3806562d9aa136f8655222f1266e9819526e1",
                "binary",
                "biome",
            ),
            ("windows", "x86_64"): _dl(
                "https://github.com/biomejs/biome/releases/download/%40biomejs%2Fbiome%402.6.6/biome-win32-x64.exe",
                "d3aac0b55e1b52ce586892b7c64de6bd2fc3774fe5b71129426af92c8a3c0571",
                "binary",
                ("biome.exe", "biome"),
            ),
        },
        post_install=(),
    ),
    SetupItem(
        name="oxlint",
        kind="binary",
        version="1.92.0",
        homepage="https://oxc.rs/",
        size_mb=18,
        provides=("oxlint",),
        skip_if_on_path=("oxlint",),
        downloads={
            ("linux", "x86_64"): _dl(
                "https://github.com/oxc-project/oxc/releases/download/oxlint_v1.92.0/oxlint-x86_64-unknown-linux-gnu.tar.gz",
                "ba3a4d581ff73af83b2e11432fa4abeff1c6c3fc24c3ddca9990246cee8b9a92",
                "tar.gz",
                ("oxlint-x86_64-unknown-linux-gnu", "oxlint"),
            ),
            ("linux", "aarch64"): _dl(
                "https://github.com/oxc-project/oxc/releases/download/oxlint_v1.92.0/oxlint-aarch64-unknown-linux-gnu.tar.gz",
                "f646a6538b31d0a2735caa789b8be874d10b6a1328d80da50737da036bed400b",
                "tar.gz",
                ("oxlint-aarch64-unknown-linux-gnu", "oxlint"),
            ),
            ("darwin", "aarch64"): _dl(
                "https://github.com/oxc-project/oxc/releases/download/oxlint_v1.92.0/oxlint-aarch64-apple-darwin.tar.gz",
                "c71cd2dbfb4c5289634c9c3b0688adb8fd2d65413d1ce7e4ca7e7feac85a5a8b",
                "tar.gz",
                ("oxlint-aarch64-apple-darwin", "oxlint"),
            ),
            ("darwin", "x86_64"): _dl(
                "https://github.com/oxc-project/oxc/releases/download/oxlint_v1.92.0/oxlint-x86_64-apple-darwin.tar.gz",
                "343fc9f9785684f8f5d9d283fe28cbbf5514f3aa95e0d35eb051e9a70d5ccc2c",
                "tar.gz",
                ("oxlint-x86_64-apple-darwin", "oxlint"),
            ),
            ("windows", "x86_64"): _dl(
                "https://github.com/oxc-project/oxc/releases/download/oxlint_v1.92.0/oxlint-x86_64-pc-windows-msvc.zip",
                "eb821008cc1f593c27215088f926966ac5356ff621e612cdd0744cd19a410722",
                "zip",
                ("oxlint-x86_64-pc-windows-msvc.exe", "oxlint"),
            ),
        },
        post_install=(),
    ),
    SetupItem(
        name="stylua",
        kind="binary",
        version="2.6.0",
        homepage="https://github.com/JohnnyMorganz/StyLua",
        size_mb=6,
        provides=("stylua",),
        skip_if_on_path=("stylua",),
        downloads={
            ("linux", "x86_64"): _dl(
                "https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/stylua-linux-x86_64.zip",
                "a485f72bbfa22e4642e77a84b5edc2611a5cab7477b34e2e709dd8f78e919895",
                "zip",
                "stylua",
            ),
            ("linux", "aarch64"): _dl(
                "https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/stylua-linux-aarch64.zip",
                "8e67539e5fdf7a81cd03cf592b0df18d3bb96ee17a5ea5d9bf67b86387b903b0",
                "zip",
                "stylua",
            ),
            ("darwin", "aarch64"): _dl(
                "https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/stylua-macos-aarch64.zip",
                "dab9b66d340ca5ffc8225211f1dcf89b84783e09b8cbec8c518497eba81f3c42",
                "zip",
                "stylua",
            ),
            ("darwin", "x86_64"): _dl(
                "https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/stylua-macos-x86_64.zip",
                "90779aa873837b2dff8eb3361bd27950303914c24265a59cae0a0d0629d71585",
                "zip",
                "stylua",
            ),
            ("windows", "x86_64"): _dl(
                "https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/stylua-windows-x86_64.zip",
                "fd13b4014e3b779c244bbc03f2c282e357f15bc526de6a6fa5ecbc447538313c",
                "zip",
                ("stylua.exe", "stylua"),
            ),
        },
        post_install=(),
    ),
    SetupItem(
        name="selene",
        kind="binary",
        version="0.32.0",
        homepage="https://github.com/Kampfkarren/selene",
        size_mb=8,
        provides=("selene",),
        skip_if_on_path=("selene",),
        downloads={
            ("linux", "x86_64"): _dl(
                "https://github.com/Kampfkarren/selene/releases/download/0.32.0/selene-0.32.0-linux.zip",
                "d3773393578580074386e69337d35b7acddfbaa9fc38964c07fa3e28436ade9b",
                "zip",
                "selene",
            ),
            ("darwin", "aarch64"): _dl(
                "https://github.com/Kampfkarren/selene/releases/download/0.32.0/selene-0.32.0-macos.zip",
                "d8aa4701530a81334836f9c5e3bf38b91f633d9ad88f4d15cf29f63fe8589dc0",
                "zip",
                "selene",
            ),
            ("darwin", "x86_64"): _dl(
                "https://github.com/Kampfkarren/selene/releases/download/0.32.0/selene-0.32.0-macos.zip",
                "d8aa4701530a81334836f9c5e3bf38b91f633d9ad88f4d15cf29f63fe8589dc0",
                "zip",
                "selene",
            ),
            ("windows", "x86_64"): _dl(
                "https://github.com/Kampfkarren/selene/releases/download/0.32.0/selene-0.32.0-windows.zip",
                "c8b693de81d0ddc11490d8e1170dd98d775c2b21431144bd8286f738ef416109",
                "zip",
                ("selene.exe", "selene"),
            ),
        },
        post_install=(),
    ),
    SetupItem(
        name="glslang",
        kind="binary",
        version="16.6.0",
        homepage="https://github.com/KhronosGroup/glslang",
        size_mb=5,
        provides=("glslangValidator",),
        skip_if_on_path=("glslangValidator",),
        downloads={
            ("linux", "x86_64"): _dl(
                "https://github.com/KhronosGroup/glslang/releases/download/16.6.0/glslang-16.6.0-linux-x86_64-release.zip",
                "a3fc4f083b1793eb53e55fa3577ac9649ffbe0340715e30d116290fb5382393f",
                "zip",
                ("bin/glslangValidator", "glslangValidator"),
            ),
            ("darwin", "aarch64"): _dl(
                "https://github.com/KhronosGroup/glslang/releases/download/16.6.0/glslang-16.6.0-macos-universal-release.zip",
                "1086bc6c7ce8ff188e4e1d1a69078e9e38156a4c2c3f13e4f91b9289a1d90453",
                "zip",
                ("bin/glslangValidator", "glslangValidator"),
            ),
            ("darwin", "x86_64"): _dl(
                "https://github.com/KhronosGroup/glslang/releases/download/16.6.0/glslang-16.6.0-macos-universal-release.zip",
                "1086bc6c7ce8ff188e4e1d1a69078e9e38156a4c2c3f13e4f91b9289a1d90453",
                "zip",
                ("bin/glslangValidator", "glslangValidator"),
            ),
            ("windows", "x86_64"): _dl(
                "https://github.com/KhronosGroup/glslang/releases/download/16.6.0/glslang-16.6.0-windows-x86_64-release.zip",
                "82bf434e69b9bb4829de7e2b4bc2c5e7a7861e53d66cf75e5cc70f5f694a8d9b",
                "zip",
                ("bin/glslang.exe", "glslangValidator"),
            ),
        },
        post_install=(),
    ),
    SetupItem(
        name="dxc",
        kind="binary",
        version="1.9.2609",
        homepage="https://github.com/microsoft/DirectXShaderCompiler",
        size_mb=45,
        provides=("dxc",),
        skip_if_on_path=("dxc",),
        downloads={
            ("linux", "x86_64"): _dl(
                "https://github.com/microsoft/DirectXShaderCompiler/releases/download/v1.9.2609/linux_dxc_2026_09_28.x86_x64.tar.gz",
                "96faadc7f5c282d2ffda49804beb4c3ee38127bc252b723234e3c5cdf7aa39a1",
                "tar.gz",
                ("bin/dxc", "dxc"),
            ),
            ("windows", "x86_64"): _dl(
                "https://github.com/microsoft/DirectXShaderCompiler/releases/download/v1.9.2609/dxc_2026_09_29.zip",
                "ad31b1fc8443175d204f77a611fdb3ef2ec42759bdc2f1167368de24a4a7e7f1",
                "zip",
                ("bin/x64/dxc.exe", "dxc"),
            ),
        },
        post_install=(),
    ),
)


def current_platform() -> tuple[str, str]:
    """Return normalized (os, arch) tuple for the current host."""
    raw_os = platform.system().lower()
    if raw_os.startswith("linux"):
        os_name = "linux"
    elif raw_os == "darwin":
        os_name = "darwin"
    elif raw_os in ("windows", "win32", "cygwin") or raw_os.startswith("msys"):
        os_name = "windows"
    else:
        os_name = raw_os

    raw_arch = platform.machine().lower()
    if raw_arch in ("x86_64", "amd64", "x64"):
        arch = "x86_64"
    elif raw_arch in ("aarch64", "arm64"):
        arch = "aarch64"
    else:
        arch = raw_arch

    return (os_name, arch)


def downloads_for(plat: tuple[str, str]) -> list[tuple[SetupItem, Download]]:
    """Return ordered (SetupItem, Download) pairs available for plat."""
    return [
        (item, dl)
        for item in ITEMS
        if (dl := item.downloads.get(plat)) is not None
    ]


def total_size_mb(plat: tuple[str, str]) -> int:
    """Return approximate total size in MB for all items available on plat."""
    return sum(item.size_mb for item, _ in downloads_for(plat))


def _validate_item_fields(item: SetupItem) -> list[str]:
    """Check top-level SetupItem metadata fields."""
    problems: list[str] = []
    if not item.name or not item.name.strip():
        problems.append("item with empty name")
    if item.kind not in ("binary", "sdk"):
        problems.append(f"{item.name}: invalid kind {item.kind!r}")
    if not item.version or not item.version.strip():
        problems.append(f"{item.name}: empty version")
    if not item.provides:
        problems.append(f"{item.name}: empty provides")
    if not item.skip_if_on_path:
        problems.append(f"{item.name}: empty skip_if_on_path")
    if not item.downloads:
        problems.append(f"{item.name}: empty downloads")
    return problems


def _validate_platform_key(item_name: str, plat: object) -> tuple[str, list[str]]:
    """Validate a platform key tuple and return (diagnostic_label, problems)."""
    if (
        not isinstance(plat, tuple)
        or len(plat) != 2
        or not isinstance(plat[0], str)
        or not isinstance(plat[1], str)
    ):
        label = f"{item_name}[{plat!r}]"
        return label, [f"{label}: invalid platform tuple {plat!r}"]

    label = f"{item_name}[{plat[0]}/{plat[1]}]"
    if plat[0] not in ("linux", "darwin", "windows") or plat[1] not in ("x86_64", "aarch64"):
        return label, [f"{label}: invalid platform tuple {plat!r}"]
    return label, []


def _validate_download_binaries(
    label: str,
    item: SetupItem,
    binaries: tuple[Binary, ...],
    provides_set: set[str] | None = None,
) -> list[str]:
    """Validate Binary mappings on a Download against item.provides and item.kind."""
    if not binaries:
        return [f"{label}: empty binaries"]

    problems: list[str] = []
    if provides_set is None:
        provides_set = set(item.provides)
    exposed_names: set[str] = set()
    for b in binaries:
        if not isinstance(b, Binary) or not b.path or not b.name:
            problems.append(f"{label}: invalid binary entry {b!r}")
            continue
        exposed_names.add(b.name)
        if b.name not in provides_set:
            problems.append(
                f"{label}: binary name {b.name!r} not in provides {item.provides!r}"
            )

    if item.kind == "binary":
        missing = [p for p in item.provides if p not in exposed_names]
        if missing:
            problems.append(f"{label}: missing provides {missing!r} in binaries")
    elif item.kind == "sdk" and not exposed_names.issubset(provides_set):
        problems.append(
            f"{label}: sdk binary names {sorted(exposed_names)!r} not a subset of provides {item.provides!r}"
        )
    return problems


def _validate_download(
    item: SetupItem,
    plat: object,
    dl: Download,
    provides_set: set[str] | None = None,
) -> list[str]:
    """Validate a single platform Download entry on item."""
    label, problems = _validate_platform_key(item.name, plat)

    problems.extend(_check_artifact_url(label, dl.url))
    if "latest" in dl.url.lower():
        problems.append(f"{label}: unpinned 'latest' in url ({dl.url!r})")

    problems.extend(_check_artifact_hash(label, dl.hash, dl.hash_algo, dl.hash_source))
    if dl.archive not in ("tar.gz", "tar.xz", "zip", "binary"):
        problems.append(f"{label}: invalid archive {dl.archive!r}")
    if dl.strip_components < 0:
        problems.append(f"{label}: negative strip_components {dl.strip_components}")
    if not isinstance(dl.chmod, bool):
        problems.append(f"{label}: non-bool chmod {dl.chmod!r}")
    if dl.layout not in ("", "rust-components"):
        problems.append(f"{label}: invalid layout {dl.layout!r}")
    if dl.layout == "rust-components" and not dl.include:
        problems.append(f"{label}: rust-components layout needs include")
    for name in dl.include:
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            problems.append(f"{label}: invalid include entry {name!r}")

    problems.extend(_validate_download_binaries(label, item, dl.binaries, provides_set))
    return problems


_UNPINNED_RE = re.compile(r"(?<![A-Za-z])(stable|latest|nightly|beta)(?![A-Za-z])", re.IGNORECASE)


def _check_artifact_url(label: str, url: str) -> list[str]:
    """Check transport and host policy without imposing a pinning policy."""
    problems: list[str] = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        problems.append(f"{label}: url is not https ({url!r})")
    if parsed.hostname not in OFFICIAL_HOSTS:
        problems.append(f"{label}: host {parsed.hostname!r} not in OFFICIAL_HOSTS")
    return problems


def _check_artifact_hash(label: str, hash_val: str, hash_algo: str, hash_source: str) -> list[str]:
    """Check an artifact's checksum shape and provenance."""
    problems: list[str] = []
    exp_len = _HASH_LENGTHS.get(hash_algo)
    if exp_len is None:
        problems.append(f"{label}: unsupported hash_algo {hash_algo!r}")
    elif len(hash_val) != exp_len or not _HEX_RE.match(hash_val):
        problems.append(
            f"{label}: invalid {hash_algo} hash "
            f"(len={len(hash_val)}, expected {exp_len} lowercase hex)"
        )
    if hash_source not in ("published", "computed"):
        problems.append(f"{label}: invalid hash_source {hash_source!r}")
    return problems


def _check_pinned_hash(label: str, url: str, hash_val: str, hash_algo: str, hash_source: str) -> list[str]:
    """Shared https/official-host/hash-shape checks for a downloadable artifact."""
    problems = _check_artifact_url(label, url)
    if _UNPINNED_RE.search(url):
        problems.append(f"{label}: unpinned channel in url ({url!r})")
    problems.extend(_check_artifact_hash(label, hash_val, hash_algo, hash_source))
    return problems


def _validate_packages(item: SetupItem) -> list[str]:
    """Validate checksum-pinned follow-up packages on item."""
    problems: list[str] = []
    for pkg in item.packages:
        label = f"{item.name}/{pkg.name}"
        if not isinstance(pkg, Package):
            problems.append(f"{label}: invalid package entry {pkg!r}")
            continue
        if pkg.kind not in ("dotnet-tool", "pwsh-module"):
            problems.append(f"{label}: invalid package kind {pkg.kind!r}")
        if not re.fullmatch(r"\d+(\.\d+)+", pkg.version or ""):
            problems.append(f"{label}: version {pkg.version!r} is not an exact release")
        elif pkg.version not in pkg.url:
            problems.append(f"{label}: url does not name version {pkg.version}")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.nupkg", pkg.filename or ""):
            problems.append(f"{label}: invalid filename {pkg.filename!r}")
        problems.extend(_check_pinned_hash(label, pkg.url, pkg.hash, pkg.hash_algo, pkg.hash_source))
    return problems


def _validate_unpinned_args(item: SetupItem) -> list[str]:
    """Reject floating channels (stable/latest/...) in version or post_install argv."""
    problems: list[str] = []
    if _UNPINNED_RE.search(item.version) or not re.fullmatch(r"\d+(\.\d+)+", item.version):
        problems.append(f"{item.name}: version {item.version!r} is not an exact release")
    for cmd in item.post_install:
        for arg in cmd:
            if _UNPINNED_RE.search(arg):
                problems.append(f"{item.name}: unpinned channel in post_install arg {arg!r}")
    return problems


def _validate_post_install(
    item_name: str,
    post_install: tuple[tuple[str, ...], ...],
) -> list[str]:
    """Validate post_install command tuples and placeholder syntax."""
    problems: list[str] = []
    for cmd in post_install:
        if not cmd:
            problems.append(f"{item_name}: empty command in post_install")
        for arg in cmd:
            if "{" not in arg and "}" not in arg:
                continue
            matches = _BRACE_RE.findall(arg)
            cleaned = _BRACE_RE.sub("", arg)
            if "{" in cleaned or "}" in cleaned:
                problems.append(f"{item_name}: unmatched brace in post_install arg {arg!r}")
            for m in matches:
                if m not in _ALLOWED_PLACEHOLDERS:
                    problems.append(
                        f"{item_name}: disallowed placeholder {{{m}}} in post_install arg {arg!r}"
                    )
    return problems


def validate() -> list[str]:
    """Validate all ITEMS in the manifest and return a list of problem strings."""
    problems: list[str] = []
    for item in ITEMS:
        problems.extend(_validate_item_fields(item))
        provides_set = set(item.provides)
        for plat, dl in item.downloads.items():
            problems.extend(_validate_download(item, plat, dl, provides_set))
        problems.extend(_validate_post_install(item.name, item.post_install))
        problems.extend(_validate_packages(item))
        problems.extend(_validate_unpinned_args(item))
    return problems
