# Vérificateur DNS

Ce projet contient un script Python pour vérifier l'état opérationnel de domaines DNS, ainsi qu'un script bash NRPE pour l'intégration avec des systèmes de surveillance.

## Script Python (dns_check.py)

### But

Le script Python vérifie l'état opérationnel de domaines DNS spécifiés. Il effectue les vérifications suivantes :

- Existence du domaine
- Opérabilité des serveurs DNS
- Cohérence des enregistrements SOA
- Vérifications en IPv4 et IPv6 (si disponible)

### Prérequis

- Python 3.x
- Bibliothèques Python : dnspython

### Utilisation

```bash
pipenv run python dns_check.py <fichier_domaines> [--tcp] [--json] [--summary]
# ou bien
pipenv run dns_check <fichier_domaines> [--tcp] [--json] [--summary]

<fichier_domaines> : Chemin vers un fichier contenant la liste des domaines à vérifier (un par ligne)
--tcp : Force l'utilisation de requêtes TCP
--json : Sortie au format JSON
--summary : Affiche un résumé des problèmes
```

## Script NRPE (check_dns_domains.sh)

Ce script bash sert d'interface entre le script Python et un système de surveillance compatible NRPE (comme Nagios ou Icinga).

### Prérequis

- Bash
- jq
- Python 3.x
- pipenv

### Installation

1. Placez le script `check_dns_domains.sh` dans le répertoire des plugins NRPE.
1. Rendez le script exécutable : `chmod +x check_dns_domains.sh`
1. Configurez NRPE pour utiliser ce script.

### Configuration NRPE

Ajoutez la ligne suivante à votre configuration NRPE :

```text
command[check_dns_domains]=/chemin/vers/check_dns_domains.sh
```

### Fonctionnement

Le script NRPE :

- Vérifie les dépendances nécessaires
- Exécute le script Python dans l'environnement pipenv
- Analyse la sortie JSON du script Python
- Retourne un statut NRPE approprié (**OK**, **WARNING**, **CRITICAL**) basé sur les résultats

### Codes de sortie

- 0 (**OK**) : Tous les domaines sont opérationnels
- 1 (**WARNING**) : Certains domaines ont des problèmes mineurs
- 2 (**CRITICAL**) : Un ou plusieurs domaines n'ont aucun serveur DNS opérationnel
- 3 (**UNKNOWN**) : Erreur d'exécution ou dépendances manquantes

## Maintenance

Pour mettre à jour les dépendances :

```bash
pipenv update
```

Pour plus d'informations sur la configuration ou le dépannage, consultez la documentation de NRPE et de votre système de surveillance.
