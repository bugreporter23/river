# River

River manages operator-owned Nebula authority, enrolled node software and Koi
fleet projection. It consumes [Koi's public CLI](https://github.com/bugreporter23/koi)
for compute facts and access. Applications own their bundles and guest processes.

The flake supplies `packages.x86_64-linux.default` and `nixosModules.default`.
Requires Linux, maintenance SSH with independently verified host keys, an
operator-owned signing store and native Nebula. Managed provider/manager nodes
currently require Koi projection; standalone lighthouses run native Nebula.

```nix
{
  imports = [ river.nixosModules.default koi.nixosModules.default ];
  services.river = { enable = true; koi.enable = true; };
  services.koi.enable = true;
  virtualisation.incus.enable = true;
  networking.nftables.enable = true;
}
```

Enable node software, then create a protected operator store:

```sh
river init --store /media/operator/river
```

Edit its `map.json` with a network and independently verified node destinations:

```json
{
  "schema": 2,
  "network": "10.77.0.0/24",
  "peers": {
    "lighthouse": {
      "role": "lighthouse", "address": "10.77.0.1",
      "endpoint": "192.0.2.1:4242", "target": "root@192.0.2.1"
    },
    "compute-a": {
      "role": "provider-manager", "address": "10.77.0.2",
      "routed_prefix": "10.90.7.0/24", "target": "root@compute-a"
    }
  }
}
```

Select prefixes that are disjoint from overlay, guest networks and deployment
LANs/VPNs. Maintenance SSH credentials belong to the administrator's existing
configuration. Review and apply the map:

```sh
river plan --store /media/operator/river
river apply --store /media/operator/river
river status --check --store /media/operator/river
```

Planning computes local intent. Application requests node key generation over
maintenance SSH, signs locally and delivers serially. First issuance creates
encrypted signing authorities and prompts for a passphrase. Required unreachable
nodes remain pending; repeat application when they become reachable. Report
containment only after all required revocations have been applied.

`renew --due`, `compromise NAME` and `replace NAME --target SSH_DESTINATION` prepare
lifecycle changes for review/application. Compromise blocks local issuance;
containment also requires fleet delivery. Renewal preserves keys. Replacement
creates fresh keys. Issuer rollover requires a separate future design.

Node state lives under `/var/lib/river`. `river reconcile` restores its accepted
configuration. Disabling River's Koi projection withdraws owned listeners,
packet rules, routes, DNS and manager targets. Keys and accepted authority remain
for reactivation. Host and guest software replacement follows each owner's
activation procedure; selecting a new image applies to future Koi guests.

[Interfaces](INTERFACES.md) describes composition and access. Original River code
is [MIT licensed](LICENSE).
