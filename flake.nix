{
  description = "APXM agents development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];

      forAllSystems = f:
        builtins.listToAttrs (map (system: {
          name = system;
          value = f system;
        }) systems);

      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      dekkFor = pkgs:
        pkgs.python312Packages.buildPythonApplication {
          pname = "dekk";
          version = "1.11.5";
          pyproject = true;

          src = pkgs.fetchFromGitHub {
            owner = "randreshg";
            repo = "dekk";
            rev = "1e263d76f26259d4a46f2c65ecd5cffc7aae5a4a";
            hash = "sha256-ZOjkAQf3E1Cl/r4/5cY2TeP70r6jj67NIQmzIR/0/lo=";
          };

          build-system = [ pkgs.python312Packages.hatchling ];
          dependencies = with pkgs.python312Packages; [
            platformdirs
            pyyaml
            questionary
            rich
            tomli-w
            typer
          ];
        };

      devShellFor = system:
        let
          pkgs = pkgsFor system;
          llvm = pkgs.llvmPackages;
          rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          python = pkgs.python312.withPackages (packages: [
            packages.pip
            packages.setuptools
            packages.pytest
            packages.pytest-asyncio
          ]);
          dekk = dekkFor pkgs;
        in pkgs.mkShell {
          packages = [
            dekk
            rust
            python
            pkgs.python312Packages.pip
            pkgs.uv
            pkgs.nodejs_22
            pkgs.git
            pkgs.curl
            pkgs.jq
            pkgs.cmake
            pkgs.ninja
            pkgs.pkg-config
            pkgs.openssl
            pkgs.docker
            pkgs.skopeo
            llvm.clang
            llvm.libclang
            llvm.mlir
            llvm.llvm
          ];

          env = {
            UV_PYTHON_DOWNLOADS = "never";
            MLIR_DIR = "${llvm.mlir}/lib/cmake/mlir";
            LLVM_DIR = "${llvm.llvm.dev}/lib/cmake/llvm";
            MLIR_PREFIX = "${llvm.mlir}";
            LLVM_PREFIX = "${llvm.llvm}";
            LIBCLANG_PATH = "${llvm.libclang.lib}/lib";
            CC = "${llvm.clang}/bin/clang";
            CXX = "${llvm.clang}/bin/clang++";
            LD_LIBRARY_PATH = "${llvm.llvm}/lib:${llvm.libclang.lib}/lib";
            PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
          } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "${llvm.clang}/bin/clang";
          };

          shellHook = ''
            export PATH="${python}/bin:$PWD/bin:$PWD/target/release:$PATH"
            # The runner data disk may be mounted noexec. Cargo must compile and
            # execute test binaries, so select persistent storage only when it
            # accepts execution; otherwise use the executable home filesystem.
            cargo_root="''${HOME}/.cache"
            if test -d /srv/clic && test -w /srv/clic; then
              cargo_root="/srv/clic"
            fi
            cargo_probe="''${cargo_root}/.apxm-exec-probe-''${USER:-unknown}"
            mkdir -p "$cargo_root"
            printf '#!/bin/sh\nexit 0\n' > "$cargo_probe"
            chmod 700 "$cargo_probe"
            if "$cargo_probe"; then
              rm -f "$cargo_probe"
              export CARGO_TARGET_DIR="''${cargo_root}/apxm-target-''${USER:-unknown}"
            else
              rm -f "$cargo_probe"
              export CARGO_TARGET_DIR="''${TMPDIR:-/tmp}/apxm-target-''${USER:-unknown}"
            fi
            export PYTHONPATH="$PWD/crates/compiler/frontend/python:$PWD/tools"
            export APXM_PYTHON_DRIVER="$(command -v python)"
            export APXM_TYPESCRIPT_DRIVER="$(command -v node)"
            mkdir -p "$PWD/.dekk/env/bin"
            ln -sfn "$APXM_PYTHON_DRIVER" "$PWD/.dekk/env/bin/python"
            ln -sfn "$APXM_TYPESCRIPT_DRIVER" "$PWD/.dekk/env/bin/node"
            export APXM_TYPESCRIPT_FRONTEND_PACKAGE="$PWD/crates/compiler/frontend/typescript"
            export APXM_TYPESCRIPT_AGENT_PACKAGING_PACKAGE="$PWD/crates/tools/cli/agent-packaging"
            export APXM_PYTHON_AGENT_PACKAGING_PACKAGE="$PWD/crates/tools/cli/agent-packaging-python"
            export NPM_CONFIG_CACHE="$PWD/.dekk/npm-cache"
            export PIP_CACHE_DIR="$PWD/.dekk/pip-cache"
            export UV_CACHE_DIR="$PWD/.dekk/uv-cache"
            echo ""
            echo "APXM Nix development shell"
            echo ""
            echo "  Run: dekk agents doctor|check|test"
            echo "  Release: dekk agents release-qualification"
            echo "  Nix: nix flake check"
            echo ""
            echo "MLIR: ${llvm.mlir.version}"
            echo "Rust: ${rust.version}"
          '';
        };
    in {
      packages = forAllSystems (system: {
        dekk = dekkFor (pkgsFor system);
        default = dekkFor (pkgsFor system);
      });

      devShells = forAllSystems (system: {
        default = devShellFor system;
      });
    };
}
