# firewall_mininet

## como correr

#### correr pox
- Hacer softlink de firewall.py en /pox/pox
- Hacer softlink de policy.csv en /pox/pox

`$ python3 ./pox.py forwarding.l2_learning firewall`

#### correr mininet

`$ sudo mn --custom src/topo.py --topo customTopo --mac --arp --controller remote`

## Descargar lo necesario

#### Xterm
`$ sudo apt install xterm`

#### Mininet
`$ sudo apt install mininet`

#### Pox
`$ git clone http://github.com/noxrepo/pox`

`$ cd pox`

`~/pox$ git checkout dart`
