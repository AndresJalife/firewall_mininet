from mininet.topo import Topo


class Topologia(Topo):

    def __init__(self, switch_count):
        assert switch_count > 0
        self.switch_count = switch_count
        Topo.__init__(self)

    def build(self):
        h1_1 = self.addHost('h1_1')
        h1_2 = self.addHost('h1_2')
        h2_1 = self.addHost('h2_1')
        h2_2 = self.addHost('h2_2')

        switches = []
        for i in range(self.switch_count):
            switches.append(self.addSwitch(f'switch_{i}'))

        self.addLink(h1_1, switches[0])
        self.addLink(h1_2, switches[0])
        self.addLink(switches[-1], h2_1)
        self.addLink(switches[-1], h2_2)

        for i in range(1, self.switch_count):
            self.addLink(switches[i-1], switches[i])

topos = {'customTopo' : lambda: Topologia(2) }
