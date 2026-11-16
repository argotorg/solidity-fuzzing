{
  # Build environment for both trees (build/, build_afl/), AFL++, afl-ts and the corpus tools: `nix develop`.
  description = "solidity-fuzzing build environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      llvm = pkgs.llvmPackages_21;
      # solidity links Boost statically (Boost_USE_STATIC_LIBS defaults to ON); nixpkgs ships it shared only
      boostStatic = pkgs.boost.override { enableShared = false; enableStatic = true; };
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          gnumake cmake ninja git pkg-config ccache which file
          python3 gdb
          protobuf abseil-cpp boostStatic zlib
          # AFL++ LLVM mode: llvm-config (llvm.dev), clang, lld for its LTO mode
          llvm.clang llvm.llvm llvm.llvm.dev llvm.lld
          # AFL++ gcc_plugin mode: gcc's plugin headers include gmp/mpfr/mpc
          gmp mpfr libmpc
          # tsgen (grammar-driven corpus generator)
          cargo rustc
        ];
        # _FORTIFY_SOURCE warns without optimisation, and solidity builds with -Werror
        hardeningDisable = [ "fortify" "fortify3" ];
        shellHook = ''
          export LLVM_CONFIG=${llvm.llvm.dev}/bin/llvm-config
        '';
      };
    };
}
