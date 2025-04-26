from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.packet_base import packet_base
from pox.lib.packet.packet_utils import *
import pox.lib.packet as pkt
import time
import os
from pox.lib.recoco import Timer
import struct
from pox.openflow.of_json import *

log = core.getLogger()

# Inicjalizacja zmiennych globalnych

# Identyfikatory polaczen switchy
s1_dpid=0
s2_dpid=0
s3_dpid=0
s4_dpid=0
s5_dpid=0

# Statystyki portow (liczba wyslanych "s1" lub odebranych "s2", "s3", "s4" pakietow) otrzymane ze switchy w biezacym kroku
s1_p1=0
s1_p4=0
s1_p5=0
s1_p6=0
s2_p1=0
s3_p1=0
s4_p1=0

# Statystyki portow (liczba wyslanych "s1" lub odebranych "s2", "s3", "s4" pakietow) otrzymane ze switchy w poprzednim kroku
pre_s1_p1=0
pre_s1_p4=0
pre_s1_p5=0
pre_s1_p6=0
pre_s2_p1=0
pre_s3_p1=0
pre_s4_p1=0

# Zmienne do obliczania opoznien i zmiany trasy
start_time = 0.0
send_time1=0.0
send_time2=0.0
src_dpid=0
dst_dpid=0
mytimer = 0
OWD1=0.0
OWD2=0.0
current_link_index = 0
isFirstTime = True
connections = []
available_links = {}
previous_link = None
MAX_DELAY = 60				# Akceptowalne opoznienie
load_balance_counter = 0
info={
  "s1": {
    "connection": {
      "s2": {
      	"port-number": 4,
        "port": "eth4",
        "port-mac": "0:0:0:0:1:4"
      },
      "s3": {
        "port-number": 5,
        "port": "eth5",
        "port-mac": "0:0:0:0:1:5"
      },
      "s4": {
        "port-number": 6,
        "port": "eth6",
        "port-mac": "0:0:0:0:1:6"
      }
    },
    "delays": {
      "s2": 0,
      "s3": 0,
      "s4": 0
    }
  },
  "s2": {
    "connection": {
      "s1": {
        "port-number": 1,
        "port": "eth1",
        "port-mac": "0:0:0:0:2:1"
      },
      "s5": {
        "port-number": 2,
        "port": "eth2",
        "port-mac": "0:0:0:0:2:2"
      }
    }
  },
  "s3": {
    "connection": {
      "s1": {
        "port-number": 1,
        "port": "eth1",
        "port-mac": "0:0:0:0:3:1"
      },
      "s5": {
        "port-number": 2,
        "port": "eth2",
        "port-mac": "0:0:0:0:3:2"
      }
    }
  },
  "s4": {
    "connection": {
      "s1": {
        "port-number": 1,
        "port": "eth1",
        "port-mac": "0:0:0:0:4:1"
      },
      "s5": {
        "port-number": 2,
        "port": "eth2",
        "port-mac": "0:0:0:0:4:2"
      }
    }
  },
  "s5": {
    "connection": {
      "s2": {
        "port-number": 1,
        "port": "eth1",
        "port-mac": "0:0:0:0:5:1"
      },
      "s3": {
        "port-number": 2,
        "port": "eth2",
        "port-mac": "0:0:0:0:5:2"
      },
      "s4": {
        "port-number": 3,
        "port": "eth3",
        "port-mac": "0:0:0:0:5:3"
      }
    }
  }
}

# Klasa definiujaca specjalny typ pakietu
class myproto(packet_base):

  # Konstruktor klasy inicjalizujacy pakiet
  def __init__(self):
     packet_base.__init__(self)
     self.timestamp=0					# Dodaje pole do pakietu przechowujace znacznik czasu (moment, kiedy pakiet zostal utworzony)

  # Funkcja zwracajaca naglowek pakietu 
  def hdr(self, payload):
     return struct.pack('!I', self.timestamp)		# Zamiana wartosci czasu na bajty

# Obsluga zdarzenia rozlaczenia kontrolera ze switchem
def _handle_ConnectionDown (event):
  global mytimer
  
  print("ConnectionDown: ", dpidToStr(event.connection.dpid))		# event.connection.dpid identyfikuje switch, z ktorego otrzymano wiadomosc
  mytimer.cancel()							# Zatrzymanie dzialania licznika

# Funkcja wypisujaca obecna date i godzine
def getTheTime():
  flock = time.localtime()
  then = "[%s-%s-%s" %(str(flock.tm_year),str(flock.tm_mon),str(flock.tm_mday))

  if int(flock.tm_hour)<10:
    hrs = "0%s" % (str(flock.tm_hour))
  else:
    hrs = str(flock.tm_hour)
  if int(flock.tm_min)<10:
    mins = "0%s" % (str(flock.tm_min))
  else:
    mins = str(flock.tm_min)

  if int(flock.tm_sec)<10:
    secs = "0%s" % (str(flock.tm_sec))
  else:
    secs = str(flock.tm_sec)

  then +="] %s.%s.%s" % (hrs,mins,secs)
  return then

# Funkcja zbierajaca i analizujaca liczbe wyslanych i odebranych pakietow przez konkretne porty przelacznikow
def _handle_portstats_received (event):
  global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid
  global s1_p1, s1_p4, s1_p5, s1_p6, s2_p1, s3_p1, s4_p1
  global pre_s1_p1, pre_s1_p4, pre_s1_p5, pre_s1_p6, pre_s2_p1, pre_s3_p1, pre_s4_p1
  global start_time, send_time1, send_time2, src_dpid, dst_dpid, OWD1, OWD2

  #print("===>Event.stats:")
  #print(event.stats)
  #print("<===")

  if event.connection.dpid==s1_dpid:
    for f in event.stats:
      if int(f.port_no)<65534:
        if f.port_no==1:
          pre_s1_p1=s1_p1
          s1_p1=f.rx_packets
          #print( "s1_p1->", s1_p1, "TxDrop:", f.tx_dropped,"RxDrop:",f.rx_dropped,"TxErr:",f.tx_errors,"CRC:",f.rx_crc_err,"Coll:",f.collisions,"Tx:",f.tx_packets,"Rx:",f.rx_packets)
        if f.port_no==4:
          pre_s1_p4=s1_p4
          s1_p4=f.tx_packets
          #s1_p4=f.tx_bytes
          #print( "s1_p4->", s1_p4, "TxDrop:", f.tx_dropped,"RxDrop:",f.rx_dropped,"TxErr:",f.tx_errors,"CRC:",f.rx_crc_err,"Coll:",f.collisions,"Tx:",f.tx_packets,"Rx:",f.rx_packets)
        if f.port_no==5:
          pre_s1_p5=s1_p5
          s1_p5=f.tx_packets
        if f.port_no==6:
          pre_s1_p6=s1_p6
          s1_p6=f.tx_packets

  if event.connection.dpid==s2_dpid:
     for f in event.stats:
       if int(f.port_no)<65534:
         if f.port_no==1:
           pre_s2_p1=s2_p1
           s2_p1=f.rx_packets
           #s2_p1=f.rx_bytes
     #print( getTheTime(), "s1_p4(Sent):", (s1_p4-pre_s1_p4), "s2_p1(Received):", (s2_p1-pre_s2_p1))

  if event.connection.dpid==s3_dpid:
     for f in event.stats:
       if int(f.port_no)<65534:
         if f.port_no==1:
           pre_s3_p1=s3_p1
           s3_p1=f.rx_packets
     #print( getTheTime(), "s1_p5(Sent):", (s1_p5-pre_s1_p5), "s3_p1(Received):", (s3_p1-pre_s3_p1))

  if event.connection.dpid==s4_dpid:
     for f in event.stats:
       if int(f.port_no)<65534:
         if f.port_no==1:
           pre_s4_p1=s4_p1
           s4_p1=f.rx_packets
     #print( getTheTime(), "s1_p6(Sent):", (s1_p6-pre_s1_p6), "s4_p1(Received):", (s4_p1-pre_s4_p1))

  received_time = time.time() * 1000*10 - start_time		# Obliczony czas, ktory uplynal od momentu wyslania do chwili otrzymania pakietu

  if event.connection.dpid == src_dpid:
    OWD1=0.5*(received_time - send_time1)			# Obliczony czas T1

  elif event.connection.dpid == dst_dpid:
    OWD2=0.5*(received_time - send_time2) 			# Obliczony czas T2

# Funkcja wywolujaca sie, gdy nastapi polaczenie kontrolera ze switchem
def _handle_ConnectionUp (event):
  global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid, src_dpid, dst_dpid, mytimer, connections
  print( "ConnectionUp: ",dpidToStr(event.connection.dpid))

  for m in event.connection.features.ports:
    if m.name == "s1-eth1":
      s1_dpid = event.connection.dpid
      print( "s1_dpid=", s1_dpid)
    elif m.name == "s2-eth1":
      s2_dpid = event.connection.dpid
      print( "s2_dpid=", s2_dpid)
    elif m.name == "s3-eth1":
      s3_dpid = event.connection.dpid
      print( "s3_dpid=", s3_dpid)
    elif m.name == "s4-eth1":
      s4_dpid = event.connection.dpid
      print( "s4_dpid=", s4_dpid)
    elif m.name == "s5-eth1":
      s5_dpid = event.connection.dpid
      print( "s5_dpid=", s5_dpid)
      
  connections.append(event.connection)

  # Gdy wszystkie switche sa podlaczone, startujemy timer
  if all([s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid]):
    print( getTheTime(), "=================================")
    print( getTheTime(), "Wszystkie przelaczniki polaczone")
    print( getTheTime(), "=================================")
    
    mytimer=Timer(1, _timer_func, recurring=True)

# Funkcja wywoujaca sie, gdy switch otrzyma pakiet, ale nie ma dla niego reguly w swojej tablicy (przesyla go do kontrolera)
def _handle_PacketIn(event):
  global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid, start_time, OWD1, OWD2, first

  received_time = time.time() * 1000*10 - start_time 		# Obliczony czas, ktory uplynal od momentu wyslania do chwili otrzymania pakietu
  packet=event.parsed
  a=packet.find('arp')
  
  if packet.type==0x5577 and event.connection.dpid==dst_dpid: 	# Sprawdzenie, czy typ pakietu to 0x5577 (niestandardowy typ Ethernet przypisany do pakietow sondy)
    c=packet.find('ethernet').payload				# Pobranie danych z pakietu Ethernet
    d,=struct.unpack('!I', c) 					# Rozpakowanie danych jako liczba calkowita (big-endian)
    
    delay = int(received_time - d - OWD1 - OWD2)/10
    name = "s" + str(dst_dpid)
    info["s1"]["delays"][name] = delay

    print( getTheTime(), "=====> s1 <-> s" + str(dst_dpid), "delay:", delay, "[ms] <=====")
  
  if event.connection.dpid==s1_dpid:
    if a and a.protodst=="10.0.0.1":
      msg = of.ofp_packet_out(data=event.ofp)				# Utworz wiadomosc packet_out, uzyj przychodzacego pakietu jako danych dla wiadomosci packet_out
      msg.actions.append(of.ofp_action_output(port=1))			# Dodaj akcje, aby wyslac na okreslony port
      event.connection.send(msg)					# Wyslij wiadomosc do switcha
       
    msg = of.ofp_flow_mod()	     					# tworzy obiekt o typie ofp_flow_mod		
    msg.priority =100		     					# ustala priorytet przeplywu
    msg.idle_timeout = 0	      					# przez jaki czas regula pozostaje aktywna, jezeli nie ma zadnych nowych pakietow pasujacych do tej reguly
    msg.hard_timeout = 0	      					# czas po ktorym regula pozostaje aktywna niezaleznie od tego, czy sa odbierane pakiety pasujace do tej reguly czy nie
    msg.match.dl_type = 0x0800	      					# regula dla pakietow IP (x0800)
    msg.match.nw_dst = "10.0.0.1"    					# regula dla pakietow o takim docelowym adresie IP
    msg.actions.append(of.ofp_action_output(port = 1)) 			# dodaje akcje do reguly przeplywu (przekazanie na port 1)
    event.connection.send(msg)	      					# Wyslij wiadomosc do switcha
       
    if a and a.protodst=="10.0.0.2":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=2))
      event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =100
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.dl_type = 0x0800
    msg.match.nw_dst = "10.0.0.2"
    msg.actions.append(of.ofp_action_output(port = 2))
    event.connection.send(msg)

    if a and a.protodst=="10.0.0.3":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=3))
      event.connection.send(msg)
       
    msg = of.ofp_flow_mod()
    msg.priority =100
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.dl_type = 0x0800
    msg.match.nw_dst = "10.0.0.3"
    msg.actions.append(of.ofp_action_output(port = 3))
    event.connection.send(msg)
     
    if a and a.protodst=="10.0.0.4":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=4))
      event.connection.send(msg)
       
    if a and a.protodst=="10.0.0.5":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=5))
      event.connection.send(msg)
       
    if a and a.protodst=="10.0.0.6":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=6))
      event.connection.send(msg)

  elif event.connection.dpid==s2_dpid:
    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 1
    msg.match.dl_type=0x0806					# regula dla pakietow ARP (x0806)
    msg.actions.append(of.ofp_action_output(port = 2))
    event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 1
    msg.match.dl_type=0x0800
    msg.actions.append(of.ofp_action_output(port = 2))
    event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 2
    msg.match.dl_type=0x0806
    msg.actions.append(of.ofp_action_output(port = 1))
    event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 2
    msg.match.dl_type=0x0800
    msg.actions.append(of.ofp_action_output(port = 1))
    event.connection.send(msg)

  elif event.connection.dpid==s3_dpid:
    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 1
    msg.match.dl_type=0x0806
    msg.actions.append(of.ofp_action_output(port = 2))
    event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 1
    msg.match.dl_type=0x0800
    msg.actions.append(of.ofp_action_output(port = 2))
    event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 2
    msg.match.dl_type=0x0806
    msg.actions.append(of.ofp_action_output(port = 1))
    event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 2
    msg.match.dl_type=0x0800
    msg.actions.append(of.ofp_action_output(port = 1))
    event.connection.send(msg)

  elif event.connection.dpid==s4_dpid:
    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 1
    msg.match.dl_type=0x0806
    msg.actions.append(of.ofp_action_output(port = 2))
    event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 1
    msg.match.dl_type=0x0800
    msg.actions.append(of.ofp_action_output(port = 2))
    event.connection.send(msg)
      
    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 2
    msg.match.dl_type=0x0806
    msg.actions.append(of.ofp_action_output(port = 1))
    event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =10
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.in_port = 2
    msg.match.dl_type=0x0800
    msg.actions.append(of.ofp_action_output(port = 1))
    event.connection.send(msg)

  elif event.connection.dpid==s5_dpid:
    if a and a.protodst=="10.0.0.4":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=4))
      event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =100
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.dl_type = 0x0800
    msg.match.nw_dst = "10.0.0.4"
    msg.actions.append(of.ofp_action_output(port = 4))
    event.connection.send(msg)

    if a and a.protodst=="10.0.0.5":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=5))
      event.connection.send(msg)
       
    msg = of.ofp_flow_mod()
    msg.priority =100
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.dl_type = 0x0800
    msg.match.nw_dst = "10.0.0.5"
    msg.actions.append(of.ofp_action_output(port = 5))
    event.connection.send(msg)

    if a and a.protodst=="10.0.0.6":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=6))
      event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.priority =100
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.dl_type = 0x0800
    msg.match.nw_dst = "10.0.0.6"
    msg.actions.append(of.ofp_action_output(port = 6))
    event.connection.send(msg)
     
    if a and a.protodst=="10.0.0.1":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=1))
      event.connection.send(msg)
       
    if a and a.protodst=="10.0.0.2":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=2))
      event.connection.send(msg)
       
    if a and a.protodst=="10.0.0.3":
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port=3))
      event.connection.send(msg)
  
  if packet.type == packet.IP_TYPE:
    ip_packet = packet.payload
    src_ip = str(ip_packet.srcip)
    dst_ip = str(ip_packet.dstip)
    port_s1, port_s5 = choose_port()

    msg = of.ofp_flow_mod()
    msg.command=of.OFPFC_MODIFY_STRICT
    msg.priority = 100
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.dl_type = 0x0800
    msg.match.nw_src = IPAddr(src_ip)
    msg.match.nw_dst = IPAddr(dst_ip)
    msg.actions.append(of.ofp_action_output(port = port_s1))
    core.openflow.getConnection(s1_dpid).send(msg)
    
    msg = of.ofp_flow_mod()
    msg.command=of.OFPFC_MODIFY_STRICT
    msg.priority = 100
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.match.dl_type = 0x0800
    msg.match.nw_src = IPAddr(dst_ip)
    msg.match.nw_dst = IPAddr(src_ip)
    msg.actions.append(of.ofp_action_output(port = port_s5))
    core.openflow.getConnection(s5_dpid).send(msg)

# Funkcja wybierajaca trase
def choose_port():
  global load_balance_counter
    
  valid_keys = list(available_links.keys())
    
  if not valid_keys:
    print("Brak dostepnych portow z akceptowalnym opoznieniem!")
    return None
        
  selected_key = valid_keys[load_balance_counter % len(valid_keys)]
  port_s1 = info["s1"]["connection"][selected_key]["port-number"]
  port_s5 = info["s5"]["connection"][selected_key]["port-number"]
  load_balance_counter += 1
  return port_s1, port_s5

# Funkcja zmieniajaca trase
def reroute():
  global s1_dpid, s5_dpid, previous_link
  
  displayed = False
  if available_links:
    selected_link = min(available_links, key=available_links.get)
  else:
    return
      
  if selected_link != previous_link:
    for ip in ["10.0.0.4", "10.0.0.5", "10.0.0.6"]:     
      msg = of.ofp_flow_mod()
      msg.command=of.OFPFC_MODIFY_STRICT
      msg.priority = 100
      msg.idle_timeout = 0
      msg.hard_timeout = 0
      msg.match.dl_type = 0x0800
      msg.match.nw_dst = ip
      msg.actions.append(of.ofp_action_output(port = info["s1"]["connection"][selected_link]["port-number"]))
      core.openflow.getConnection(s1_dpid).send(msg)
      
    for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
      msg = of.ofp_flow_mod()
      msg.command=of.OFPFC_MODIFY_STRICT
      msg.priority = 100
      msg.idle_timeout = 0
      msg.hard_timeout = 0
      msg.match.dl_type = 0x0800
      msg.match.nw_dst = ip
      msg.actions.append(of.ofp_action_output(port = info["s5"]["connection"][selected_link]["port-number"]))
      core.openflow.getConnection(s5_dpid).send(msg)
  
    if not displayed:
      print( getTheTime(), "=================================")
      print( getTheTime())
      print( getTheTime(), "Zmiana na trase: s1 <->", selected_link, "<-> s5")
      print( getTheTime())
      print( getTheTime(), "=================================")
      displayed = True
    previous_link = selected_link

# Funkcja wysylajaca wiadomosci pomiarowe do switchy
def _timer_func():
  global start_time, send_time1, send_time2, src_dpid, dst_dpid, current_link_index, isFirstTime, available_links

  keys = list(info["s1"]["connection"].keys())
  key = keys[current_link_index % len(keys)]
  
  src_name = "s1-" + str(info["s1"]["connection"][key]["port"])
  dst_name = str(key) + "-" + str(info[key]["connection"]["s1"]["port"])
  
  src_dpid = None
  dst_dpid = None
  
  for connection in core.openflow._connections.values():
      for m in connection.features.ports:
        if m.name == src_name:
          src_dpid = connection.dpid
        elif m.name == dst_name:
          dst_dpid = connection.dpid

  # Sprawdzenie, czy istnieje polaczenie ze switchem zrodlowym (Pomiar T1)
  if src_dpid is not None and core.openflow.getConnection(src_dpid) is not None:  
    core.openflow.getConnection(src_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))  # Wyslanie zadanie statystyk portu switcha zrodlowego (w celu pomiaru T1)
    send_time1=time.time() * 1000*10 - start_time 							# Wyliczenie czasu, ktory uplynal od momentu przeslania przez kontroler powyzszego zapytania
      
    # Pomiar czasu T3
    f = myproto() 											# Stworzenie pakietu pomiarowego
    e = pkt.ethernet() 											# Stworzenie pakietu Ethernet
    e.src = EthAddr(info["s1"]["connection"][key]["port-mac"])						# Ustawienie adresu zrodlowego
    e.dst = EthAddr(info[key]["connection"]["s1"]["port-mac"])						# Ustawienie adresu docelowego
    e.type=0x5577 											# Ustawienie niestandardowego typu pakietu (pozwoli odroznic pakiety testowe)
    msg = of.ofp_packet_out() 										# Stworzenie wiadomosci PACKET_OUT
    msg.actions.append(of.ofp_action_output(port=info["s1"]["connection"][key]["port-number"])) 	# Ustawienie portu wyjsciowego na switchu zrodlowym
    f.timestamp = int(time.time()*1000*10 - start_time) 						# Ustawienie znacznika czasowego w pakiecie pomiarowym
    e.payload = f											# Dolaczenie pakietu pomiarowego do pakietu Ethernet
    msg.data = e.pack()
    core.openflow.getConnection(src_dpid).send(msg)
      
  # Sprawdzenie, czy istnieje polaczenie ze switchem docelowym (pomiar T2)
  if dst_dpid is not None and core.openflow.getConnection(dst_dpid) is not None:
    core.openflow.getConnection(dst_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))  # Wyslanie zadanie statystyk portu switcha docelowego (w celu pomiaru T2)
    send_time2=time.time() * 1000*10 - start_time							# Wyliczenie czasu, ktory uplynal od momentu przeslania przez kontroler powyzszego zapytania 
      
  if current_link_index % 3 == 0 and not isFirstTime:
    print( getTheTime(), "=================================================================================")
    print( getTheTime())
    print( getTheTime(), "=====> Delay to s2:", info["s1"]["delays"]["s2"], "ms | Delay to s3:", info["s1"]["delays"]["s3"], "ms | Delay to s4:", info["s1"]["delays"]["s4"], "ms <=====")
    print( getTheTime())
    print( getTheTime(), "=================================================================================")
    for key, delay in info["s1"]["delays"].items():
      if delay < MAX_DELAY:
        available_links[key] = delay
      else:
        if key in available_links:
          del available_links[key]
    #reroute()
    
  isFirstTime = False
  current_link_index += 1
    
# Glowna funkcja inicjujaca komponenty 
def launch ():
  global start_time

  start_time = time.time() * 1000*10
  
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("ConnectionDown", _handle_ConnectionDown)
  core.openflow.addListenerByName("PortStatsReceived",_handle_portstats_received)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)
