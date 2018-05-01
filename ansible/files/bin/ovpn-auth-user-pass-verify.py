#!/usr/bin/env python2

import sys, os, sqlite3, pyotp, ldap

try:
  PASSWORD = os.environ.get("password", '')
  USERNAME = os.environ.get("username", '')
  SQLITE_FILE = sys.argv[1]

  if not PASSWORD or not SQLITE_FILE or not USERNAME:
    print "missing required env var"
    raise SystemExit(1)

  cxn = sqlite3.connect(SQLITE_FILE)
  query = cxn.execute('select seed from totp where email=?', [USERNAME])
  result = query.fetchone()
  if not result or len(result) != 1:
    print "no seed for", USERNAME
    raise SystemExit(1)

  seed = result[0]

  try:
    query.close()
    cxn.close()
  except:
    pass

  totp = pyotp.TOTP(seed)
  expected = totp.now()

  if PASSWORD != expected:
    print "bad TOTP/password"
    raise SystemExit(1)

  raise SystemExit(0)
except SystemExit, x:
  raise x
except Exception, e:
  print e
  raise SystemExit(1)
