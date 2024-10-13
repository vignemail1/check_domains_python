#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import dns.exception
import json
from datetime import datetime
import sys
import socket
import ipaddress
import argparse

def has_ipv6():
    try:
        socket.create_connection(("2001:4860:4860::8888", 53), timeout=1)
        return True
    except:
        return False

def check_domain(domain, use_tcp):
    result = {
        "domain": domain,
        "exists": True,
        "all_ns_operational": True,
        "consistent_soa": True,
        "soa_records": {"ipv4": [], "ipv6": []},
        "errors": []
    }

    try:
        # Obtenir les serveurs de noms pour le domaine
        ns_answers = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(rdata) for rdata in ns_answers]
    except dns.resolver.NXDOMAIN:
        result["exists"] = False
        return result
    except dns.exception.DNSException as e:
        result["errors"].append(f"Erreur lors de la résolution NS: {str(e)}")
        return result

    ipv6_enabled = has_ipv6()

    for ns in nameservers:
        try:
            # Résolution IPv4
            ipv4_address = socket.gethostbyname(ns)
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ipv4_address]
            resolver.use_edns = 0
            soa_answer_ipv4 = resolver.resolve(domain, 'SOA', tcp=use_tcp)
            result["soa_records"]["ipv4"].append(str(soa_answer_ipv4[0]))

            # Résolution IPv6 si disponible
            if ipv6_enabled:
                try:
                    ipv6_addresses = [addr[4][0] for addr in socket.getaddrinfo(ns, None, socket.AF_INET6) if addr[4][0] != '::1']
                    if ipv6_addresses:
                        resolver.nameservers = [ipv6_addresses[0]]
                        soa_answer_ipv6 = resolver.resolve(domain, 'SOA', tcp=use_tcp)
                        result["soa_records"]["ipv6"].append(str(soa_answer_ipv6[0]))
                except socket.gaierror:
                    result["errors"].append(f"Pas d'adresse IPv6 pour le serveur {ns}")

        except (dns.exception.DNSException, socket.error) as e:
            result["all_ns_operational"] = False
            result["errors"].append(f"Erreur avec le serveur {ns}: {str(e)}")

    # Vérifier la cohérence des enregistrements SOA
    all_soa_records = result["soa_records"]["ipv4"] + result["soa_records"]["ipv6"]
    if len(set(all_soa_records)) > 1:
        result["consistent_soa"] = False
        result["errors"].append("Incohérence entre les enregistrements SOA IPv4 et IPv6")

    return result


def summarize_results(results):
    total_domains = len(results)
    problem_domains = {
        "non_existent": [],
        "ns_not_operational": [],
        "no_operational_ns": [],
        "inconsistent_soa": [],
        "other_errors": []
    }
    
    for result in results:
        if not result["exists"]:
            problem_domains["non_existent"].append(result["domain"])
        elif not result["all_ns_operational"]:
            if "Aucun serveur DNS opérationnel trouvé" in result["errors"]:
                problem_domains["no_operational_ns"].append(result["domain"])
            else:
                problem_domains["ns_not_operational"].append(result["domain"])
        elif not result["consistent_soa"]:
            problem_domains["inconsistent_soa"].append(result["domain"])
        elif result["errors"]:
            problem_domains["other_errors"].append(result["domain"])
    
    problem_count = sum(len(domains) for domains in problem_domains.values())
    no_problem_count = total_domains - problem_count
    
    summary = {
        "total_domains": total_domains,
        "domains_without_problems": no_problem_count,
        "problem_domains": problem_domains
    }
    
    return summary

def main():
    parser = argparse.ArgumentParser(description="Vérification de l'état opérationnel des domaines DNS")
    parser.add_argument("domains_file", help="Fichier contenant la liste des domaines à vérifier")
    parser.add_argument("--tcp", action="store_true", help="Forcer l'utilisation de requêtes TCP")
    parser.add_argument("--json", action="store_true", help="Sortie au format JSON")
    parser.add_argument("--summary", action="store_true", help="Afficher un résumé des problèmes")
    args = parser.parse_args()

    check_time = datetime.now().isoformat()
    results = []

    with open(args.domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    for domain in domains:
        results.append(check_domain(domain, args.tcp))

    if args.summary:
        summary = summarize_results(results)
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(f"Total des domaines vérifiés: {summary['total_domains']}")
            print(f"Domaines sans problème: {summary['domains_without_problems']}")
            print("\nDomaines avec problèmes:")
            for problem, domains in summary['problem_domains'].items():
                if domains:
                    print(f"  {problem}: {len(domains)}")
                    for domain in domains:
                        print(f"    - {domain}")
    elif args.json:
        json_output = {
            "check_time": check_time,
            "tcp_used": args.tcp,
            "results": results
        }
        print(json.dumps(json_output, indent=2))
    else:
        print(f"Vérification effectuée le : {check_time}")
        print(f"Utilisation de TCP : {'Oui' if args.tcp else 'Non'}")
        for result in results:
            print(f"\nDomaine: {result['domain']}")
            print(f"Existe: {'Oui' if result['exists'] else 'Non'}")
            print(f"Tous les serveurs DNS opérationnels: {'Oui' if result['all_ns_operational'] else 'Non'}")
            print(f"SOA cohérent: {'Oui' if result['consistent_soa'] else 'Non'}")
            if result['errors']:
                print("Erreurs:")
                for error in result['errors']:
                    print(f"  - {error}")

if __name__ == "__main__":
    main()
