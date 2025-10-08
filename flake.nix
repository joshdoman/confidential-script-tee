{
  description = "An enclave that uses KMS to reproduce a secret only it can access";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    enclaver = {
      url = "github:joshdoman/enclaver/0b1a0209d43c2c9ae63ce180158396347efcf7e5";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, enclaver }:
    let
      perSystem = (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };

          makePackagesForTarget = targetArch:
            let
              arch = if targetArch == "aarch64" then "aarch64" else "x86_64";

              muslTarget = if targetArch == "aarch64"
                then "aarch64-unknown-linux-musl"
                else "x86_64-unknown-linux-musl";

              pkgsMusl = import nixpkgs {
                inherit system overlays;
                crossSystem = {
                  config = muslTarget;
                };
              };

              confidential-script = pkgsMusl.rustPlatform.buildRustPackage {
                pname = "confidential-script";
                version = "0.1.0";

                src = pkgs.lib.cleanSourceWith {
                  src = ./.;
                  filter = path: type:
                    let relativePath = pkgs.lib.removePrefix (toString ./. + "/") (toString path);
                    in !(pkgs.lib.hasPrefix "docs/" relativePath) &&
                       !(pkgs.lib.hasPrefix ".github/" relativePath) &&
                       !(relativePath == "README.md");
                };
  
                cargoLock.lockFile = ./Cargo.lock;
                doCheck = false;

                # Build dependencies for libbitcoinkernel-sys
                nativeBuildInputs = with pkgsMusl.pkgsBuildHost; [
                  cmake
                  pkg-config
                  git
                  clang
                  llvm
                ];

                buildInputs = with pkgsMusl; [
                  boost
                  libevent
                  openssl
                  sqlite
                ];

                # Environment variables
                RUSTFLAGS = "-C target-feature=+crt-static";
                RUST_LOG = "info";
                RUST_BACKTRACE = "1";

                # Bindgen environment variables
                LIBCLANG_PATH = "${pkgsMusl.pkgsBuildHost.libclang.lib}/lib";
                BINDGEN_EXTRA_CLANG_ARGS = pkgs.lib.concatStringsSep " " [
                  "-I${pkgsMusl.pkgsBuildHost.clang}/resource-root/include"
                  "-I${pkgsMusl.glibc.dev}/include"
                ];

                postInstall = ''
                  cp -L $out/bin/confidential-script $out/bin/entrypoint
                '';
              };

              makeAppEif = enclaver.lib.${system}.${arch}.makeAppEif or enclaver.lib.${system}.makeAppEif;

              eifBuild = makeAppEif {
                appPackage = confidential-script;
                configFile = ./enclaver.yaml;
              };

            in {
              inherit makeAppEif;
              eif = eifBuild.eif;
              rootfs = eifBuild.rootfs;
              app = confidential-script;
            };

          nativeArch = if pkgs.stdenv.isAarch64 then "aarch64" else "x86_64";
          nativePackages = makePackagesForTarget nativeArch;
          x86Packages = makePackagesForTarget "x86_64";
          aarch64Packages = makePackagesForTarget "aarch64";

        in
        {
          packages = {
            default = nativePackages.eif;
            app = nativePackages.app;
            rootfs = nativePackages.rootfs;
            eif = nativePackages.eif;
            x86_64-eif = x86Packages.eif;
            aarch64-eif = aarch64Packages.eif;
          };

          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              rust-bin.stable.latest.default
              pkg-config
              openssl
              cacert
              curl
              dnsutils
              cmake
              boost
              libevent
              zeromq
              sqlite
              git
              clang
              llvm
            ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.SystemConfiguration
            ];

            RUST_LOG = "debug";
            RUST_BACKTRACE = "1";
            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
            BINDGEN_EXTRA_CLANG_ARGS = pkgs.lib.concatStringsSep " " [
              "-I${pkgs.pkgsBuildHost.clang}/resource-root/include"
              "-I${pkgs.glibc.dev}/include"
            ];
          };

          apps = {
            default = flake-utils.lib.mkApp {
              drv = nativePackages.app;
              name = "confidential-script";
            };
          };
        });
    in
      flake-utils.lib.eachDefaultSystem perSystem;
}