import json
import ldap3
import sys

# Configuration de l'analyzer (peut être personnalisée via Cortex)
LDAP_SERVER = "ldap://10.0.2.15:389"
BIND_DN = "cn=admin,dc=echelon,dc=local"
BIND_PASSWORD = "LDAP_password"
BASE_DN = "ou=computers,dc=echelon,dc=local"

def query_ldap():
    try:
        # Connexion au serveur LDAP
        server = ldap3.Server(LDAP_SERVER, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, BIND_DN, BIND_PASSWORD, auto_bind=True)
        
        # Filtrer les machines récemment modifiées
        search_filter = "(objectClass=inetOrgPerson)"
        search_attributes = ["cn", "uid", "description", "modifyTimestamp", "entryUUID"]
        
        conn.search(BASE_DN, search_filter, attributes=search_attributes)
        
        # Extraction des résultats
        results = []
        for entry in conn.entries:
            results.append({
                "cn": entry.cn.value,
                "uid": entry.uid.value if "uid" in entry else None,
                "description": entry.description.value if "description" in entry else None,
                "modifyTimestamp": entry.modifyTimestamp.value if "modifyTimestamp" in entry else None,
                "entryUUID": entry.entryUUID.value if "entryUUID" in entry else None
            })

        # Affichage du JSON pour Cortex
        print(json.dumps(results, indent=4))
    
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    query_ldap()

