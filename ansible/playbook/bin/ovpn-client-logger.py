#!/usr/bin/env python2

import sys, os, sqlite3

try:
  print sys.argv
  SQLITE_FILE = sys.argv[1]
  COMMON_NAME = os.environ.get("common_name")
  IP_ADDR = os.environ.get("ifconfig_pool_remote_ip")
  SCRIPT_TYPE = os.environ.get('script_type', 'unknown')

  print os.environ

  if not COMMON_NAME or not SQLITE_FILE or not IP_ADDR:
    print "missing required env var", COMMON_NAME, SQLITE_FILE, IP_ADDR
    raise SystemExit(1)

  cxn = sqlite3.connect(SQLITE_FILE)
  query = cxn.execute(
    "insert into events (email, ip, event) values (?, ?, ?)",
    [COMMON_NAME, IP_ADDR, SCRIPT_TYPE])
  cxn.commit()
  try:
    query.close()
    cxn.close()
  except:
    pass
  raise SystemExit(0)
except SystemExit, x:
  raise x
except Exception, e:
  print "error"
  print e
  raise SystemExit(1)
