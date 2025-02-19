#!/usr/bin/env python3

import json
from cortexutils.analyzer import Analyzer
import ldap3
from ldap3 import Server, Connection, SIMPLE, SYNC, SUBTREE, ALL

class LdapUserMachineQuery(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        ldap_address = self.get_param("config.LDAP_address", None, "LDAP address is missing")
        ldap_port = self.get_param("config.LDAP_port", None, "LDAP port is missing")
        ldap_port = int(ldap_port)

        username = self.get_param("config.LDAP_username", None, "Username is missing")
        password = self.get_param("config.LDAP_password", None, "Password is missing")
        self.base_dn = self.get_param("config.base_DN", None, "Base DN is missing")
        self.search_filter = self.get_param("config.search_filter", "(objectClass=*)", "Search filter is missing")
        self.attributes = self.get_param("config.attributes", None, "Attributes list is missing")

        try:
            server = Server(ldap_address, port=ldap_port, get_info=ALL, use_ssl=True if ldap_port == 636 else False)
            self.connection = Connection(
                server,
                auto_bind=True,
                client_strategy=SYNC,
                user=username,
                password=password,
                authentication=SIMPLE,
                check_names=True,
            )
        except Exception as e:
            self.error(f"Error during LDAP connection: {str(e)}")

    def run(self):
        try:
            data = self.get_param("data", None, "Data is missing")
            query = f"(&({self.search_filter})(uid={data}))"

            self.connection.search(self.base_dn, query, SUBTREE, attributes=self.attributes.split(','))
            responses = self.connection.response

            users = []
            if responses:
                for response in responses:
                    user_data = response.get("attributes", {})
                    user = {attr: user_data.get(attr, [])[0] for attr in self.attributes.split(',') if attr in user_data}
                    users.append(user)

            self.connection.unbind()
            self.report({"results": users})
        except Exception as e:
            self.error(str(e))

if __name__ == "__main__":
    LdapUserMachineQuery().run()

