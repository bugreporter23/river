{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.river;
in
{
  imports = [ ./koi-module.nix ];
  options.services.river = {
    enable = lib.mkEnableOption "operator-configured native Nebula networking";
    package = lib.mkOption { type = lib.types.package; };
    koi.enable = lib.mkEnableOption "Koi provider/manager projection";
    koi.resolver.enable = lib.mkEnableOption "guest-domain routing through host-owned systemd-resolved";
    allowedTCPPorts = lib.mkOption {
      type = lib.types.listOf lib.types.port;
      default = [ ];
      description = "Host TCP ports reachable on the river interface.";
    };
    allowedUDPPorts = lib.mkOption {
      type = lib.types.listOf lib.types.port;
      default = [ ];
      description = "Host UDP ports reachable on the river interface.";
    };
  };
  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
    networking.firewall.allowedUDPPorts = [ 4242 ];
    networking.firewall.interfaces.river = {
      inherit (cfg) allowedTCPPorts allowedUDPPorts;
    };
    systemd.tmpfiles.rules = [ "d /var/lib/river 0700 root root -" ];
    systemd.services.river-nebula = {
      description = "River native Nebula network";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      unitConfig.ConditionPathExists = "/var/lib/river/active.json";
      serviceConfig = {
        Type = "exec";
        ExecStart = "${pkgs.nebula}/bin/nebula -config /var/lib/river/active.json";
        Restart = "on-failure";
        RestartSec = 5;
        UMask = "0077";
        ProtectHome = true;
        ProtectSystem = "strict";
        PrivateTmp = true;
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
      };
    };
  };
}
