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

# Installation

## Build binaries

    GOPATH=`pwd` go build src/playground/bifrost/bifrost.go 
    GOPATH=`pwd` go build src/playground/heimdall/heimdall.go 
    GOPATH=`pwd` go build src/vendor/playground/ca/main/pgcert.go 

    mv pgcert bifrost heimdall ansible/tmp

## Generate keymatter
    ./pgcert \
        -bits 4096 -days 3650 -pass something \
        -cn "Temp Authority" -org "Sententious Heavy Industries" \
        -locality "Mountain View" -province "CA" -country "US" \
        rootca ansible/tmp/ca.key ansible/tmp/ca.crt

    ./pgcert \
        -bits 4096 -days 365 -rootpass something -cn "ovpn.playground.global" \
        server ansible/tmp/ca.key ansible/tmp/ca.crt
    mv ovpn.playground.global.key ansible/tmp/server.key
    mv ovpn.playground.global.crt ansible/tmp/server.crt

    ./pgcert \
        -bits 4096 -days 365 -rootpass something -pass something -cn "Heimdall API Client" \
        client ansible/tmp/ca.key ansible/tmp/ca.crt
    mv "Heimdall API Client".key ansible/tmp/client.key
    mv "Heimdall API Client".crt ansible/tmp/client.crt

    openvpn --genkey --secret ansible/tmp/tls-auth.pem

    openssl dhparam -out ansible/tmp/dh-4096.pem -outform PEM 4096

## Create configuration
### Create `hosts.ini`

    cp etc/ansible-hosts-example.ini ansible/tmp
    vim ansible/tmp/hosts.ini

* `vpn_public_ip` - the public IP address of your VPN server
* `vpn_public_port` - the public port of your VPN server
* `vpn_bind_ip` - the machine-local IP address the OpenVPN process should listen on (possibly the
  same as `vpn_public_ip` but different if you're behind a firewall)
* `vpn_bind_port` - the machine-local port the OpenVPN process should bind
* `vpn_uplink_interface` - the interface name of your machine's primary uplink (e.g. `eth0`)
* `vpn_api_port` - the port number where the API server (`heimdall`) should listen
* `vpn_client_domain` - the domain name to push to clients (i.e. via DHCP)
* `vpn_client_dns_servers` - the list of DNS servers to push to clients (i.e. via DHCP)
* `vpn_client_routes` - the list of routes to push to clients (i.e. via DHCP)
* `oauth_client_id` - the Google Cloud OAuth client ID from developer console
* `oauth_client_secret` - the Google Cloud OAuth client secret from developer console
* `oauth_redirect_prefix` - the prefix (i.e. scheme+host+port) of the redirect target, configured in Google Cloud console

    cp etc/config-bifrost-example.json ansible/tmp/bifrost.json
    cp etc/config-heimdall-example.json ansible/tmp/heimdall.json
    vim ansible/tmp/*json

### 

## Copy configuration to server
    cd ansible
    ansible-playbook -i tmp/hosts.ini bifrost.yml