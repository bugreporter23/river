# River agent guidance

Use [README.md](README.md) for prerequisites and operator commands and
[INTERFACES.md](INTERFACES.md) for composition and access contracts.
`river --version` reports the application SemVer from `river/VERSION`.
The Nix package uses the same file. Releases use independent `vX.Y.Z` snapshot
branches; pin dependencies to a resolved commit and content hash.

Root `PUBLICATE.json` describes River's private ticket queue and its Git endpoint.
Authorized contributors can submit reproductions using Publicate's ticket
contract. With a Nix-packaged Publicate command installed, run from this checkout:

```sh
publicate ticket --title 'Describe the observed failure' \
  --body-file /path/to/report.txt --code-version vX.Y.Z --push
```

Include the reproducer, expected behavior, observed behavior, application version
and relevant diagnostics. Keep credentials in the caller's Git environment.
Queue access follows the endpoint's Git permissions. Ticket review evaluates the
report against current source and records a concrete resolution.

Source changes are prepared in the owning development repository and exported
through its publication policy. Activation, hardware acceptance and operations
that change authority or deployed nodes require the operator's selected targets
and approval.
