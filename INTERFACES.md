# River interfaces

`river --help` and command help describe the operator and node commands.
`directory` reads generated operator facts; `peers` reads a node's delivered
copy. `node-status` reports local application. `authorization` reports accepted
access policy. The operator controls issuer authority and approved fleet scope.

Koi retains local compute allocation, immutable guest identity, disks, snapshots
and pinned SSH trust. River queries public `koi network`, `list`, `bind` and
`guest-access` facts and installs an owner-scoped `koi-host admin-targets`
projection. River owns address translation, remote DNS and the manager SSH
entrance. Koi image bundle connection declarations require explicit fleet policy
before an application endpoint becomes reachable.

`services.river.enable` selects node service activation;
`services.river.package` selects software. `services.river.koi.enable` selects
compute projection. Projection requires host-enabled nftables.
`services.river.koi.resolver.enable` selects guest-domain routing through a
host-enabled systemd-resolved. Host application ports are explicitly selected
with `services.river.allowedTCPPorts` and `allowedUDPPorts`; delivered Nebula
policy must also permit the connection. Routing and authentication have separate
owners.

Security updates with unchanged provider mappings use retained pins, including
when a provider is unavailable. Mapping changes require fresh Koi facts before
activation. Software updates retain node keys, accepted authority, revocations,
provider pins and compute identities. Withdrawal removes River's owned live
projection while retaining its persistent state.
