{ pkgs ? import <nixpkgs> {} }: with pkgs;

mkShell {
  buildInputs = [ bitcoind lnd nodejs nodePackages.npm ];
}
