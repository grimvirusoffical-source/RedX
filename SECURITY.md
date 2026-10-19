# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (private vulnerability reporting).

Include the version (`redxd version`), the platform, and steps to reproduce. You will receive an acknowledgement, and fixes are published in a new release with a note in the [changelog](CHANGELOG.md).

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: the `redxd` host, the `redx` CLI, the storage engines, the SDKs, and the install scripts in this repository.

The security model of the host (keys, TLS, policy, encryption) is described in [docs/security.md](docs/security.md). Known limitations are listed in the [README](README.md#known-limitations).
