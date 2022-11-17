# firewall_mininet

## como correr

#### correr pox
- Hacer softlink de firewall.py en /pox/pox
- Hacer softlink de policy.csv en /pox/pox

`python3 ./pox.py forwarding.l2_learning firewall`

#### correr mininet

`sudo mn --custom src/topo.py --topo customTopo --mac --arp --controller remote`