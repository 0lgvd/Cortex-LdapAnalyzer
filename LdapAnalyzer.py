#!/usr/bin/env python3

import json
import ldap3
import argparse
import os
import sys
import datetime
import traceback

# GitHub Repository URL
GITHUB_REPO = "https://github.com/0lgvd/Cortex-LdapAnalyzer"

# Parse arguments passed by Cortex
parser = argparse.ArgumentParser()
parser.add_argument('--LDAP_address', required=True, help='LDAP server address (e.g., ldap://10.0.2.15:389)')
parser.add_argument('--LDAP_bind_dn', required=True, help='LDAP admin DN (e.g., cn=admin,dc=echelon,dc=local)')
parser.add_argument('--LDAP_password_file', required=True, help='Path to the file containing the LDAP password')
parser.add_argument('--LDAP_base_dn', required=True, help='LDAP base DN (e.g., dc=echelon,dc=local)')
parser.add_argument('--LDAP_search_filter', required=False, default='(objectClass=inetOrgPerson)', help='LDAP search filter')
parser.add_argument('--LDAP_attributes', required=False, default='cn,uid,description,lastLogin,logonTime', help='Comma-separated list of LDAP attributes to retrieve')
args = parser.parse_args()

# Read LDAP password from the specified file
try:
    with open(args.LDAP_password_file, 'r') as pw_file:
        BIND_PASSWORD = pw_file.read().strip()
except Exception as e:
    print(json.dumps({"success": False, "error": f"Failed to read password file: {str(e)}", "repository": GITHUB_REPO}))
    exit(1)

def query_ldap():
    try:
        server = ldap3.Server(args.LDAP_address, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, args.LDAP_bind_dn, BIND_PASSWORD, auto_bind=True)

        search_attributes = args.LDAP_attributes.split(',')
        conn.search(args.LDAP_base_dn, args.LDAP_search_filter, attributes=search_attributes)

        results = []
        for entry in conn.entries:
            entry_data = {}
            for attr in search_attributes:
                if hasattr(entry, attr):
                    value = getattr(entry, attr).value
                    # Vérifier si la valeur est un datetime et la convertir en string
                    if isinstance(value, (datetime.datetime, datetime.date)):
                        entry_data[attr] = value.isoformat()  # Convertit en format compatible JSON
                    else:
                        entry_data[attr] = value
                else:
                    entry_data[attr] = None
            results.append(entry_data)

        print(json.dumps({"success": True, "data": results, "repository": GITHUB_REPO}, indent=4))
    except Exception as e:
        print(json.dumps({
            "success": False,
            "error": str(e),
            "trace": traceback.format_exc(),
            "repository": GITHUB_REPO
        }, indent=4))
        exit(1)

if __name__ == "__main__":
    query_ldap()

