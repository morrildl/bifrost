# Playground VPN-In-A-Box

This project is everything you need to turn a new Fedora server into an OpenVPN server, including
administrative and integration tools. If you're using other than Fedora, the software will work
fine but you may need to tweak the Ansible playbook for installation.

Special thanks to Playground Global, LLC for open-sourcing this software. See `LICENSE` for details.

# Cloning

    git clone --recursive https://github.com/morrild/bifrost

Note that this software relies on git submodules, so don't overlook the `--recursive` flag. (If you
did overlook it, try `git submodule update --init --recursive`.)

Though this is Go software, I use git submodules to manually mount libraries at specific places in
my tree, as the standard `go get` behavior of conflating hosting site with source package name is
poor software engineering practice. Specifically, the `playground/*` libraries are mirrored (or
have been mirrored in the course of their development) on multiple sites, so I use git submodules
to manage them.

# Overview

This project consists of 3 key components.

## OpenVPN Runtime

OpenVPN is, of course, doing all the heavy lifting. This project is essentially a constellation of
tools to help deploy an OpenVPN with a decently secure configuration, with decent usability.

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
1. The client certificate on the device (i.e. laptop) wanting to use VPN (ideally stored in a hardware TPM, but beyond the scope of this project)
2. The device (i.e. phone) where the TOTP app is installed
3. The OS passwords/lock codes to those devices

That is, if an attacker wants to get onto the VPN, he must steal your phone, *and* your laptop, *and* know your screensaver password and your phone unlock code.

Naturally the actual security of this model depends on the OS and user behavior, so sensible policies must also be used. Specifically, the device used for TOTP must not itself have a VPN client certificate (because then you lose a factor). And of course suitable OS-level screen locks must be used.

Note that this implementation (currently) does _not_ use the OpenVPN administrative runtime hooks to disconnect a device with an extant connection, if that device's cert is revoked. Since the expectation is that the web UI runs behind the VPN, and not necessarily on the public internet, VPN access is required to refresh device certificates. Thus we cannot revoke clients immediately via OpenVPN admin hooks: it would kick users off instantly as soon as they click the disconnect button but before they can generate a new certificate for their device. Certainly a dedicated "re-up this device" UI flow for this case is possible, but it would be more complicated, and the current UI is specifically intended to be dirt simple. All of which is to say, this is a conscious usability vs. security tradeoff.

## Heimdall API Server

Heimdall is an API server to front the SQLite3 database. The client authentication runtime scripts use the database to read certificate status (i.e. for validity and revocations), and write logs to it. The API server provides REST endpoints to manage certificates -- create users, reset TOTP seeds, issue and revoke certificates, etc.

The web UI is simply a front-end to Heimdall. A command-line front-end is also provided, but generally it's expected that most operations will be done via the web UI.

Heimdall authenticates its client via certificate pinning. The intention is that the Heimdall process itself runs on the OpenVPN server, where the SQLite3 database is located. The web UI can be run anywhere, using Heimdall as its back-end.

The specific configuration encoded in the Ansible playbook has Heimdall and Bifröst running on the same machine. This is also fine, though with a reduced security posture; but the two were built separately to make it straightforward to split the two if desired.

## Bifröst Web UI

The Bifröst web UI is where policy enforcement happens. This project is intended for use by a relatively small number of total users, perhaps up to a couple hundred. The UI is intended to be generally self-service.

Users can create and revoke certificates, up to a limit on number of extant certificates set by the administrator. For instance, the admin can set the limit to 1, allowing for only one machine at a time, intended to be a laptop. Or, the admin can set the limit to 3, perhaps allowing for a laptop, desktop, and tablet. If a user is at the limit, they must revoke a certificate to create a new one.

The administrator can opt to either have a manual whitelist of users, or allow unrestricted access to a particular domain via Google's OAuth2/OpenID Connect. In both cases, the certificate limits are enforced.

## Gjallahorn

Gjallarhorn is a binary intended to be run as a cron job that scans the extant certificates in the database, and sends notification emails about impending expirations. That is, it notifies users when their certificates are set to expire in 30/7/1 days, so that they can log in to the web UI and re-issue new certificates before they lose VPN access.


# Contents

## `./ansible/`

The `./ansible/` directory contains config files and an Ansible playbook to configure a fresh Fedora
27 server as an OpenVPN server.

## `./src/`

The `./src/` directory contains the Go source code for all three programs.

# Installation

## Build binaries

    GOPATH=`pwd` go build src/bifrost/cmd/bifrost.go 
    GOPATH=`pwd` go build src/heimdall/cmd/heimdall.go 
    GOPATH=`pwd` go build src/gjallarhorn/cmd/gjallarhorn.go 
    GOPATH=`pwd` go build src/vendor/playground/ca/cmd/pgcert.go 

    mv pgcert bifrost heimdall gjallarhorn ansible/tmp

## Generate keymatter

### Create a Certificate Authority root signing certificate
    cd ansible/tmp

    ./pgcert \
        -bits 4096 -days 3650 -pass something \
        -cn "Temp Authority" -org "Sententious Heavy Industries" \
        -locality "Mountain View" -province "CA" -country "US" \
        rootca ca.key ca.crt

### Create an OpenVPN server certificate

    ./pgcert \
        -bits 4096 -days 365 -rootpass something -pass something \
        -cn "vpn.domain.tld" \
        server ca.key ca.crt
    mv vpn.domain.tld.crt openvpn-server.crt
    mv vpn.domain.tld.key openvpn-server-tmp.key
    openssl rsa -in openvpn-server-tmp.key -out openvpn-server.key
    rm openvpn-server-tmp.key

Note that the `-cn` value must be the hostname of the server, or it will fail validation by the
clients.

### Create a certificate for the Heimdall API server

    ./pgcert \
        -bits 4096 -days 365 -rootpass something -pass something \
        -cn "localhost" \
        server ca.key ca.crt
    mv localhost.crt heimdall-server.crt
    mv localhost.key heimdall-server-tmp.key
    openssl rsa -in heimdall-server-tmp.key -out heimdall-server.key
    rm heimdall-server-tmp.key

The Bifröst UI web server calls into Heimdall for most operations; that is, Bifröst is the
primary (usually only) client of Heimdall. The purpose is to allow the API server, which handles
the root CA keymatter, to be separated onto a different machine, if desired. This would improve
an organization's security posture.

Note that, again, the `-cn` value must be the hostname of the server, or it will fail validation
by the client.

### Create a client certificate for Bifröst to use to talk to Heimdall

    ./pgcert \
        -bits 4096 -days 365 -rootpass something -pass something \
        -cn "Heimdall API Client" \
        client ca.key ca.crt
    mv "Heimdall API Client".crt heimdall-client.crt
    mv "Heimdall API Client".key heimdall-client-tmp.key
    openssl rsa -in heimdall-client-tmp.key -out heimdall-client.key
    rm heimdall-client-tmp.key

This certificate identifies the front-end UI server (Bifröst) to the API server which manages
the database and keys (Heimdall.) Heimdall will refuse to talk to any client except one which
presents this certificate and private key.

### Generate additional keymatter required by OpenVPN

Create an OpenVPN `tls-auth` file, used to improve security during client connections:

    openvpn --genkey --secret tls-auth.pem

Create Diffie-Hellman parameters for the TLS server:

    openssl dhparam -out dh-4096.pem -outform PEM 4096

Place the password for the OpenVPN server private key into the relevant file:
    
    echo something > openvpn-server-pw.txt

Note that this must match the value of the `-pass` argument used above.

## Copy in your web UI HTTPS certificates

The certificates created above are signed by your custom root CA, created in the first step. As this
root CA will not be recognized by browsers, it can't be used to sign certificates that browsers
will accept by default.

So, you'll need to copy in standard TLS certificates, sourced from a commercial CA in the usual
way. Note that certificates from <a href="https://letsencrypt.org">Let's Encrypt</a> are perfectly acceptable.

Copy these files into the tree as PEM-encoded X509 certificate and PKCS11 RSA private key files
as `ansible/tmp/bifrost-server.crt` and `ansible/tmp/bifrost-server.key` respectively.

## Create configuration
### Create `hosts.ini`

    cp etc/hosts-example.ini ansible/tmp/hosts.ini
    vim ansible/tmp/hosts.ini

* `vpn_public_ip` - the public IP address of your VPN server
* `vpn_public_port` - the public port of your VPN server
* `vpn_bind_ip` - the machine-local IP address the OpenVPN process should listen on (possibly the
  same as `vpn_public_ip` but different if you're behind a firewall)
* `vpn_bind_port` - the machine-local port the OpenVPN process should bind
* `vpn_uplink_interface` - the interface name of your machine's primary uplink (e.g. `eth0`)
* `vpn_client_domain` - the domain name to push to clients (i.e. via DHCP)
* `vpn_client_dns_servers` - the list of DNS servers to push to clients (i.e. via DHCP)
* `vpn_client_routes` - the list of routes to push to clients (i.e. via DHCP)
* `oauth_client_id` - the Google Cloud OAuth client ID from developer console
* `oauth_client_secret` - the Google Cloud OAuth client secret from developer console
* `oauth_redirect_prefix` - the prefix (i.e. scheme+host+port) of the redirect target, configured in Google Cloud console
* `ca_key_password` - the password of the CA signing key (`ca.key`)
* `bifrost_admin_list` - the list of email addresses who shall have admin rights in the web UI
* `bifrost_bind_address` - the IP address for the web UI to listen on (possibly but not necessarily the same as `vpn_bind_ip`)

## Copy configuration to server

    cd .. # i.e. up to $TREE/ansible
    ansible-playbook -i tmp/hosts.ini bifrost.yml

# Usage and management

You should now be able to visit the web UI at the port and address you configured above. If you
log in (using Google OAuth2) as an administrator, you'll see the admin UI to manage users, change
settings and policies, and view events. Admins are also users of the service, and can set TOTP
password seeds and configure device certificates.

If you're not an admin, you'll only be able to use the self-service features.

Read on to get some tips on common tasks.

## Restart web UI & API server

    systemctl restart bifrost
    systemctl restart heimdall

## Restart OpenVPN service

    systemctl restart openvpn-server@main

## Access database directly

    sqlite3 /opt/bifrost/heimdall.sqlite3

## Update firewall configuration

    vim /etc/sysconfig/iptables
    systemctl restart iptables

## Edit configuration files

* Firewall rules: `/etc/sysconfig/iptables`
* OpenVPN server: `/etc/openvpn/server/main.conf`
* Change the `.ovpn` config files generated by Heimdall: `/opt/bifrost/etc/template.ovpn`
* Change Bifröst web UI settings (e.g. to add/remove admins): `/opt/bifrost/etc/bifrost.json`
* Change Heimdall API server settings: `/opt/bifrost/etc/heimdall.json`
