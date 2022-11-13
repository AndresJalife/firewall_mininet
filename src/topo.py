from mininet.topo import Topo


class Topologia(Topo):

    def __init__(self, switch_count):
        assert switch_count > 0
        Topo.__init__(self)

        h1 = self.addHost('host_1')
        h2 = self.addHost('host_2')

        switches = []
        for i in range(switch_count):
            switches.append(self.addSwitch(f'switch_{i}'))

        self.addLink(h1, switches[0])
        self.addLink(switches[-1], h2)

        for i in range(1, switch_count-1):
            self.addLink(switches[i-1], switches[i])

