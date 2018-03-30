# Playground VPN-In-A-Box

This project is everything you need to turn a new Fedora server into an OpenVPN server, including
administrative and integration tools.

# Overview

This project consists of 3 key components.

## OpenVPN Runtime

OpenVPN is, of course, doing all the heavy lifting. This project is essentially a constellation of
tools to help deploy an OpenVPN security with a decently secure arrangement with decent usability.

The key moving pieces are:

* a SQLite3 database with a simple schema tracking certificate validity, and audit logs
* `ovpn-tls-verify.py` - a script for OpenVPN's `tls-verify` hook that handles certificate validity
  and revocations via the database
* `ovpn-auth-user-pass-verify.py` - a script for the `auth-user-pass-verify` hook that implements
  TOTP authentication (not passwords) suitable for use with Google Authenticator or Authy
* `ovpn-client-logger.py` - a script for the `client-(dis)?connect` hook that logs usage by IP

### Security Posture

The model is multi-factor authentication with a minimum of integration or overhead, in particular
avoiding dependencies on other systems, especially password databases.

Essentially this is three-factor authentication. To access the VPN you must have:
1. The client certificate on the device itself (ideally stored in a hardware TPM)
2. The device where the TOTP app is installed
3. The native passwords/lock codes to those devices

That is, if an attacker wants to get onto the VPN, he must steal *two* devices, *and* be able to
unlock those devices.

Naturally the actual security of this model depends on the OS and user behavior, so sensibly
policies must also be used. Specifically, the device used for TOTP must not itself have a VPN client
certificate. And of course suitable device-native locks should be used.

## Heimdall API Server

Heimdall is an API server to front the SQLite3 database. The client authentication runtime scripts
use the database to read certificate status (i.e. for validity and revocations), and write logs to
it. The API server provides REST endpoints to manage certificates -- create users, reset TOTP seeds,
issue and revoke certificates, etc.

The web UI is simply a front-end to Heimdall. A command-line front-end is also provided, but
generally it's expected that most operations will be done via the web UI.

Heimdall authenticates its client via certificate pinning. The intention is that the Heimdall
process itself runs on the OpenVPN server, where the SQLite3 database is located. The web UI can be
run anywhere, using Heimdall as its back-end.

## Bifröst Web UI

The Bifröst web UI is where policy enforcement happens. This project is intended for use by a relatively
small number of total users, perhaps up to a couple hundred. The UI is intended to be generally
self-service.

Users can create and revoke certificates, up to a limit on number of extant certificates set by the
administrator. For instance, the admin can set the limit to 1, allowing for only one machine at a
time, intended to be a laptop. Or, the admin can set the limit to 3, perhaps allowing for a laptop,
desktop, and tablet. If a user is at the limit, they must revoke a certificate to create a new one.

The administrator can opt to either have a manual whitelist of users, or allow unrestricted access
to a particular domain via Google's OAuth2/OpenID Connect. In both cases, the certificate limits are
enforced.

# Contents

## `./ansible/`

The `./ansible/` directory contains config files and an Ansible playbook to configure a fresh Fedora
27 server as an OpenVPN server.

## `./src/`

The `./src/` directory contains the Go source code for the management REST API server.
