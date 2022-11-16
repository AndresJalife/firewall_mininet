from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as pkt
from collections import namedtuple
import os
import csv

log = core.getLogger()

class Firewall(EventMixin):
    POLICY_FILE = "./policy.csv"

    def __init__(self):
        self.listenTo(core.openflow)
        self.rules = []
        for rule in Firewall.read_rules():
            self.add_rule(*rule)
        log.debug("Iniciando modulo de Firewall")

    def _handle_PacketIn(self, event):
        self.process_packet(event)

    @staticmethod
    def matches_rules(packet, rule):
        ip_packet = packet.find('ipv4')
        log.debug(ip_packet)
        log.debug(packet)
        is_protocol = (packet.find(rule['protocol']) is not None) if rule['protocol'] != '*' else True
        return (ip_packet.srcip == rule['src'] or '*' == rule['src']) and \
               (ip_packet.dstip == rule['dst'] or '*' == rule['dst']) and \
               (ip_packet.srcport == rule['srcport'] or '*' == rule['srcport']) and \
               (ip_packet.dstport == rule['dstport'] or '*' == rule['dstport']) and is_protocol

    def check_rules(self, packet):
        return any(self.matches_rule(packet, rule) for rule in self.rules)

    def process_packet(self, event):
        if self.check_rules(event.parsed):
            #self.dropPacket(event)
            return
        #self.sendFlowMod(msg, event)
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
        event.connection.addListeners(self)
        log.debug("El Firewall se instalo en %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)