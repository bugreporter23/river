{
  config,
  lib,
  pkgs,
  ...
}:
let
  package = config.services.river.package;
  state = "/var/lib/river/koi";
  enrolled = {
    ConditionPathExists = [
      "${state}/network.json"
      "/var/lib/river/active.json"
    ];
  };
in
{
  config = lib.mkIf (config.services.river.enable && config.services.river.koi.enable) {
    assertions = [
      {
        assertion = config.networking.nftables.enable;
        message = "River Koi projection requires the host's nftables backend; select it explicitly.";
      }
      {
        assertion = !config.services.river.koi.resolver.enable || config.services.resolved.enable;
        message = "River resolver integration requires host-enabled systemd-resolved.";
      }
    ];
    networking.nftables.flushRuleset = false;
    networking.firewall.filterForward = true;
    networking.firewall.extraForwardRules = ''
      iifname "river" accept
      oifname "river" ct state established,related accept
    '';
    environment.etc."river/koi-enabled".text = "enabled\n";
    environment.etc."river/koi-resolver" = lib.mkIf config.services.river.koi.resolver.enable {
      text = "systemd-resolved\n";
    };
    services.river.allowedTCPPorts = [
      53
      2222
    ];
    services.river.allowedUDPPorts = [ 53 ];
    boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
    environment.etc."hosts".mode = "0644";
    security.sudo.extraConfig = ''
      @includedir ${state}/sudoers.d
    '';
    security.pam.services.sshd = { };
    users.groups.sshd = { };
    users.users.sshd = {
      isSystemUser = true;
      group = "sshd";
      home = "/var/empty";
    };
    users.groups.koi-client = { };
    users.users.koi-manager = {
      isSystemUser = true;
      group = "koi-client";
      shell = pkgs.bash;
      home = "/var/empty";
      hashedPassword = "*";
    };
    users.groups.river-dns = { };
    users.users.river-dns = {
      isSystemUser = true;
      group = "river-dns";
    };
    systemd.tmpfiles.rules = [
      "d ${state} 0700 root root -"
      "d ${state}/sudoers.d 0700 root root -"
      "d /run/river-koi-dns 0755 root root -"
    ];
    systemd.services.river-koi-network = {
      description = "River Koi projection lifecycle";
      wantedBy = [ "multi-user.target" ];
      wants = [ "river-nebula.service" ];
      after = [
        "river-nebula.service"
        "nftables.service"
      ];
      unitConfig.ConditionPathExists = "${state}/network.json";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.coreutils}/bin/true";
        ExecStop = "${package}/bin/river koi withdraw";
      };
    };
    systemd.services.river-reconcile = {
      wantedBy = [ "multi-user.target" ];
      wants = [ "river-koi-network.service" ];
      after = [
        "river-koi-network.service"
        "koi.service"
      ];
      partOf = [ "river-koi-network.service" ];
      unitConfig = enrolled;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${package}/bin/river reconcile";
      };
    };
    systemd.services.river-koi-ssh = {
      after = [ "river-koi-network.service" ];
      partOf = [ "river-koi-network.service" ];
      unitConfig = enrolled // {
        ConditionPathExists = enrolled.ConditionPathExists ++ [ "${state}/sshd.conf" ];
      };
      serviceConfig = {
        ExecStart = "${pkgs.openssh}/bin/sshd -D -e -f ${state}/sshd.conf";
        KillMode = "control-group";
        TimeoutStopSec = 5;
        SendSIGKILL = true;
      };
    };
    systemd.services.river-koi-dns = {
      after = [ "river-koi-network.service" ];
      partOf = [ "river-koi-network.service" ];
      unitConfig = enrolled;
      serviceConfig = {
        User = "river-dns";
        Group = "river-dns";
        ExecStart = "${pkgs.dnsmasq}/bin/dnsmasq --keep-in-foreground --pid-file= --conf-file=/run/river-koi-dns/dnsmasq.conf";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
      };
    };
    systemd.services.river-koi-export = {
      after = [
        "river-koi-network.service"
        "koi.service"
        "river-koi-dns.service"
      ];
      partOf = [ "river-koi-network.service" ];
      unitConfig = enrolled;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${package}/bin/river koi export-dns";
      };
    };
    systemd.timers.river-koi-export = {
      after = [ "river-koi-network.service" ];
      partOf = [ "river-koi-network.service" ];
      unitConfig = enrolled;
      timerConfig = {
        OnActiveSec = "1s";
        OnUnitActiveSec = "5s";
        AccuracySec = "1s";
      };
    };
    environment.systemPackages = [ pkgs.cdrkit ];
  };
}
