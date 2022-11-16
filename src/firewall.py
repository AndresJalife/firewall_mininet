from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as pkt
from collections import namedtuple
import os
import csv

log = core.getLogger()

class Firewall(object):
    POLICY_FILE = "./policy.csv"

    def __init__(self):
        core.openflow.addListeners(self)
        self.rules = []
        for rule in Firewall.read_rules():
            self.add_rule(*rule)
        log.debug("Iniciando modulo de Firewall")

    def _handle_PacketIn(self, event):
        self.process_packet(event)

    @staticmethod
    def matches_rule(packet, rule):
        ip_packet = packet.find('ipv4')
        log.debug(ip_packet)
        log.debug(packet)
        is_protocol = (packet.find(rule['protocol']) is not None) if rule['protocol'] != '*' else True
        return (ip_packet.srcip == rule['src'] or '*' == rule['src']) and \
               (ip_packet.dstip == rule['dst'] or '*' == rule['dst']) and \
               (ip_packet.srcport == rule['srcport'] or '*' == rule['srcport']) and \
               (ip_packet.dstport == rule['dstport'] or '*' == rule['dstport']) and is_protocol

    def check_rules(self, packet):
        return any(Firewall.matches_rule(packet, rule) for rule in self.rules)

    def process_packet(self, event):
        pass
        #if self.check_rules(event.parsed):
        #    msg = self.drop_packet(event)
        #else:
        #    msg = self.send_packet(event)
        #event.connection.send(msg)
    def add_rule(self, src, dst, srcport, dstport, protocol):
        self.rules.append({
            'src': src,
            'dst': dst,
            'srcport': srcport,
            'dstport': dstport,
            'protocol': protocol,
        })

    @staticmethod
    def read_rules():
        rules = []
        with open(Firewall.POLICY_FILE, 'r') as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if i == 0:
                    continue
                rules.append(row)
        log.debug(f"Se leyeron {len(rules)} reglas para el firewall")
        return rules

    def _handle_ConnectionUp(self, event):
        log.debug("El Firewall se instalo en %s", dpid_to_str(event.dpid))

def launch():
    core.registerNew(Firewall)
