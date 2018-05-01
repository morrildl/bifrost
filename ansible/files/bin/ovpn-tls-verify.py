#!/usr/bin/env python2

import sys, os, sqlite3, ldap

try:
  PEER_FINGERPRINT = os.environ.get("tls_digest_sha256_0", "").replace(":", "")
  SQLITE_FILE = sys.argv[1]
  CERT_DEPTH = int(sys.argv[2])
  COMMON_NAME = sys.argv[3]

  if CERT_DEPTH > 0:
    raise SystemExit(0)

  CN=""
  for i in ldap.dn.str2dn(COMMON_NAME):
    if i and i[0] and i[0][0] == "CN" and i[0][1]:
      CN = i[0][1]
  if not CN:
    print "bad CN"
    raise SystemExit(1)

  if not PEER_FINGERPRINT or not SQLITE_FILE or not CN:
    print "missing required env var"
    raise SystemExit(1)

  cxn = sqlite3.connect(SQLITE_FILE)
  query = cxn.execute(
    'select email, revoked from certs where fingerprint=?',
    [PEER_FINGERPRINT])
  result = query.fetchone()
  if not result or len(result) != 2:
    print "unknown cert"
    raise SystemExit(1)
  if result[1]:
    print "revoked cert", result[1]
    raise SystemExit(1)
  if result[0] != CN:
    print "username mismatch", result[0], CN
    raise SystemExit(1)

  try:
    query.close()
    cxn.close()
  except:
    pass
  raise SystemExit(0)
except SystemExit, x:
  raise x
except Exception, e:
  print e
  raise SystemExit(1)
