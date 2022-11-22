from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as pkt
import csv

"""
Firewall implemented for pox controller.
Reads rules from a policy file and sets them in the first switch that connects.
"""

log = core.getLogger()


class Firewall(object):
    POLICY_FILE = "./policy.csv"
    SWITCH_FIREWALL_ID = 1

    def __init__(self):
        """Connects to openflow and creates the rule messages."""
        core.openflow.addListeners(self)
        self.rule_msgs = []
        for rule in Firewall.read_rules():
            self.add_rule_message(*rule)
        log.debug("Iniciando modulo de Firewall")

    def add_rule_message(self, src, dst, srcport, dstport, protocol):
        """Creates a rule message and saves it"""
        self.rule_msgs.append(self._create_rule_msg(src, dst, srcport, dstport, protocol))

    @staticmethod
    def read_rules():
        """Returns all the rules from the POLICY_FILE"""
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
        """Sets the rules to the first connection"""
        if event.connection.dpid == self.SWITCH_FIREWALL_ID:
            self._set_rules_to_connection(event.connection)
        log.debug("El Firewall se instalo en %s", dpid_to_str(event.dpid))

    def _set_rules_to_connection(self, connection):
        """Sets all the rules to one conecction"""
        for rule_msg in self.rule_msgs:
            connection.send(rule_msg)

    def _create_rule_msg(self, src, dst, srcport, dstport, protocol):
        """Creates a rule message"""
        msg = of.ofp_flow_mod()
        match = of.ofp_match(dl_type=pkt.ethernet.IP_TYPE)
        if protocol != '*':
            match.nw_proto = self._get_rule_protocol(protocol)
        if src != '*':
            match.nw_src = IPAddr(src)
        if dst != '*':
            match.nw_dst = IPAddr(dst)
        if srcport != '*':
            match.tp_src = int(srcport)
        if dstport != '*':
            match.tp_dst = int(dstport)
        msg.match = match
        return msg

    def _get_rule_protocol(self, proto):
        """Parses a protocol to openflow format"""
        if proto == 'TCP':
            return pkt.ipv4.TCP_PROTOCOL
        elif proto == 'UDP':
            return pkt.ipv4.UDP_PROTOCOL
        else:
            return pkt.ipv4.ICMP_PROTOCOL

def launch():
    core.registerNew(Firewall)
