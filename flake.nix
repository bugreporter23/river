{
  description = "River: operator authority, native Nebula networking and Koi fleet projection";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.koi.url = "github:bugreporter23/koi/831d7c652ec821d9f3fea6ba8a3eb148ec310147";
  outputs =
    {
      self,
      nixpkgs,
      koi,
    }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      python = pkgs.python3.withPackages (p: [ p.cryptography ]);
      source = pkgs.lib.fileset.toSource {
        root = ./.;
        fileset = ./river;
      };
      package = pkgs.writeShellApplication {
        name = "river";
        derivationArgs.version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./river/VERSION);
        runtimeInputs = [
          python
          pkgs.nebula
          pkgs.openssh
          pkgs.systemd
          pkgs.iproute2
          pkgs.nftables
          pkgs.util-linux
          pkgs.sudo
          pkgs.coreutils
          koi.packages.${system}.control-plane
        ];
        text = ''
          export PYTHONPATH=${source}
          exec python3 -m river "$@"
        '';
      };
    in
    {
      packages.${system}.default = package;
      nixosModules.default = { ... }: {
        imports = [ ./module.nix ];
        services.river.package = package;
      };
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          package
          python
          pkgs.nebula
          pkgs.ruff
          pkgs.nixfmt
          pkgs.openssh
        ];
      };
      formatter.${system} = pkgs.nixfmt;
    };
}
