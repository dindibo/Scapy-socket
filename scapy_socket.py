# Notes:

# TODO: Implement auto fin replier
# TODO: Fix bug - can't send twice

from scapy.all import *
import binascii as ascii
from time import gmtime, strftime
import time, random

class socket(object):
	def __init__(self, src_ip, dst_ip, port):
		self.src_ip = src_ip
		self.dst_ip = dst_ip
		self.port = port
		
		self._seq = random.randint(1, 4294967295)
		self._ack = 0
		self.dport = None
		
	def handshake(self):
		syn = sniff(count=1, lfilter = lambda x: x.haslayer(IP) and x.haslayer(TCP) and x[IP].dst == self.src_ip and x[IP].src == self.dst_ip and x[TCP].dport == self.port)[0]
		self.dport = syn[TCP].sport
		syn_ack = IP(src = self.src_ip, dst = self.dst_ip) / TCP(flags = 'SA', seq = 20000, ack = syn[TCP].seq + 1, sport = self.port, dport = syn[TCP].sport)
		send(syn_ack)
		self._ack = syn_ack[TCP].ack


	def recv(self):
		push = sniff(count=1, lfilter = lambda x: x.haslayer(IP) and x.haslayer(TCP) and x[IP].dst == self.src_ip and x[IP].src == self.dst_ip and x[TCP].dport == self.port and
		x[TCP].flags == 24)[0]

		# saves last packet's seq, ack and length of data
		a, b, c = push[TCP].seq, push[TCP].ack, len(push[Raw].load)

		self._seq = b
		self._ack = a + c

		pack = IP(src = self.src_ip, dst = self.dst_ip) / TCP(flags = 'A', seq = self._seq, ack = self._ack, sport = self.port, dport = push[TCP].sport)
		send(pack)


		return push[Raw].load


	def send(self, data):
		pack = IP(src = self.src_ip, dst = self.dst_ip) / TCP(flags = 24, seq = self._seq, ack = self._ack, sport = self.port, dport = self.dport) / data
		send(pack)


	def fin(self):
		fin_ack = sniff(count=1, lfilter = lambda x: x.haslayer(IP) and x.haslayer(TCP) and x[IP].dst == self.src_ip and x[IP].src == self.dst_ip and x[TCP].dport == self.port and
		x[TCP].flags == 17)[0]
		
		a, b = fin_ack[TCP].seq, fin_ack[TCP].ack
		pack = IP(src = self.src_ip, dst = self.dst_ip) / TCP(flags = 17, seq = b, ack = a + 1, sport = self.port, dport = self.dport)
