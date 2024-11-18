# -*- coding: utf-8 -*-
"""
-------------------------------------------------------------------------
NOME..: yaml_to_iptables.py
LANG..: Python3
TITULO: Programa para converter um arquivo yaml em regras iptables
DATA..: 04/11/2024
VERSÃO: 0.1.00
HOST..: diversos
LOCAL.: diversos
OBS...: colocar nas linhas abaixo informações importantes sobre o programa

DEPEND: (informar nas linhas abaixo os recursos necessários para utilização)

-------------------------------------------------------------------------
Copyright (c) 2022 - Vya.Digital
This script is licensed under GNU GPL version 2.0 or above
-------------------------------------------------------------------------
Modifications.....:
 Date          Rev    Author           Description
 04/11/2024     0     Yves Marinho     Elaboração
-------------------------------------------------------------------------
PARÂMETROS (informar os parâmetros necessários no exemplo de utilização)
-
SET STATUS: (status em que se encontra o código DEV/PROD)
DEV
"""
import yaml
import sys
from glob import glob


class YamlToIptables:
    def __init__(self, yaml_path):
        self.yaml_path = yaml_path
        self.config = self.load_yaml()

    def load_yaml(self):
        with open(self.yaml_path, 'r') as file:
            return yaml.safe_load(file)

    def generate_ipset_commands(self):
        commands = []
        ipsets = self.config.get('ipsets', {})
        for ipset_name, ipset_data in ipsets.items():
            commands.append(f"create {ipset_name} {ipset_data['type']}")
            for entry in ipset_data.get('entries', []):
                commands.append(f"add {ipset_name} {entry}")
        return "\n".join(commands)

    def generate_iptables_rules(self):
        rules = []

        # Process variables
        variables = self.config.get('variables', {})
        for var, value in variables.items():
            rules.append(f"# Variable: {var} = {value}")

        # Process global policies and helper chains
        global_config = self.config.get('global', {})
        policies = global_config.get('policy', {})
        for table, chains in policies.items():
            rules.append(f"*{table}")
            for chain, policy in chains.items():
                rules.append(f":{chain} {policy} [0:0]")

        helper_chains = global_config.get('helper_chains', {})
        for table, chains in helper_chains.items():
            rules.append(f"*{table}")
            for chain, chain_rules in chains.items():
                rules.append(f":{chain} - [0:0]")
                for rule in chain_rules:
                    rules.append(f"-A {chain} {rule}")

        # Process zones and their rules
        zones = self.config.get('zones', {})
        for zone, zone_data in zones.items():
            for table, chains in zone_data.get('rules', {}).items():
                rules.append(f"*{table}")
                for chain, chain_rules in chains.items():
                    rules.append(f":{chain} ACCEPT [0:0]")  # Default policy
                    for rule in chain_rules:
                        rules.append(f"-A {chain} {rule}")
                rules.append("COMMIT")

        return "\n".join(rules)

    def save_ipset_commands(self, output_path):
        commands = self.generate_ipset_commands()
        with open(output_path, 'w') as file:
            file.write(commands)

    def save_iptables_rules(self, output_path):
        rules = self.generate_iptables_rules()
        with open(output_path, 'w') as file:
            file.write(rules)


if __name__ == '__main__':
    list_files = glob("/etc/*.yml")
    if not "/etc/config.yml" in list_files:
        sys.exit("Arquivo de configuração não encontrado")
    yaml_to_iptables = YamlToIptables('/etc/config.yml')
    yaml_to_iptables.save_ipset_commands('ipset_commands.sh')