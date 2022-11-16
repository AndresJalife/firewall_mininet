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
        self.rules = {}
        log.debug("Enabling Firewall Module")

    def add_rule(self, src, dst):
        pass

    def read_rules(self):
        rules = []
        with open(Firewall.POLICY_FILE, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                rules.append((row[0], row[1]))
        print(f"Se leyeron {len(rules)} reglas para el firewall")
        return rules

    def _handle_ConnectionUp(self, event):
        for rule in self.read_rules():
            self.add_rule(*rule)
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)