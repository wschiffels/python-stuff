#!/usr/bin/env python
import logging
import os

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(message)s',
    handlers=[logging.StreamHandler()]
)

try:
    import ldap
except ImportError:
    logging.error('To use this script, you need to install `python-ldap`')
    exit(0)


SSH_KEY_ATTR = 'altSecurityIdentities'
LDAP_SERVER = 'ldap.tld:636'
try:
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
    ldap.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
    ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
    ldap_client = ldap.initialize(LDAP_SERVER)
    username = "@option.Username@"
    password = "@option.Password@"
    ldap_client.start_tls_s()
    ldap_client.simple_bind_s(username, password)
except ldap.LDAPError as e:
    logging.error(e)
    exit(0)

ldap_filter = 'sAMAccountName=%s' % username.split('@')[0]
user = ldap_client.search_s(
    'DC=tld,DC=com', ldap.SCOPE_SUBTREE,
    ldap_filter, [SSH_KEY_ATTR]
)

user_dn = user[0][0]
keys = user[0][1].get(SSH_KEY_ATTR, [])
key = "@option.SSHPublicKey@"

keys.append('%s' % (key))

try:
    ldap_client.modify_s(user_dn, [(ldap.MOD_REPLACE, SSH_KEY_ATTR, keys)])
except ldap.LDAPError as e:
    logging.error(e)
    exit(0)
