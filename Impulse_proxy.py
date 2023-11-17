from mitmproxy import http
from mitmproxy import ctx
from mitmproxy import options
from mitmproxy.proxy import config
from mitmproxy.proxy.server import ProxyServer
from mitmproxy.tools.dump import DumpMaster

import requests
import socket

from proxy_config import c2_lsit_ip_url

import time
from nostril import nonsense

#Block by C2 server IP
def get_list_c2_servers():
	response = requests.get(c2_lsit_ip_url)
	data = response.json()
	ips = [ e['ip_address'] for e in data ] 
	return ips


def get_ip_from_host(host):
	return socket.gethostbyname(host)

def block_by_hostname(host):
	ips = get_list_c2_servers()
	if get_ip_from_host(host) in ips:
		return True
	else:
		return False


#Block for noncence domain

def is_noncence_domain(host):
	domains = host.split(".")
	print(domains)
	for u in domains:
		if len(u) > 6:
			if nonsense(u):
				print(nonsense(u), u)
				return True
	return False




class AddHeader:
	def __init__(self):
		self.num = 0
		self.max_requests = 200
		self.time_frame = 60
		self.request_times = {}

	def template_blocked(self):
		template = http.HTTPResponse.make(
			200,
			b"Impulse PeaceData Firewall",
			{"Content-Type": "text/plain"}
			)
		return template

	def template_temporary_blocked(self):
		template = http.HTTPResponse.make(
			200,
			b"Impulse PeaceData Firewall\n Temporary blocked: too many requests",
			{"Content-Type": "text/plain"}
			)
		return template


	def request(self, flow):
		client_ip = flow.client_conn.ip_address[0]
		current_time = time.time()

		if client_ip not in self.request_times:
			self.request_times[client_ip] = []

		requests = self.request_times[client_ip]

		self.request_times[client_ip] = [t for t in requests if current_time - t < self.time_frame]

		if len(self.request_times[client_ip]) >= self.max_requests:
			flow.response = self.template_temporary_blocked()
		else:
			self.request_times[client_ip].append(current_time)



		if block_by_hostname(flow.request.host):
			flow.response = self.template_blocked()

		if is_noncence_domain(flow.request.host):
			flow.response = self.template_blocked()

		# Check if the request domain is a YouTube domain
		if "youtube.com" in flow.request.host or "ytimg.com" in flow.request.host:
			#flow.kill()  # Drop the request
			flow.response = self.template_blocked()

	def response(self, flow):
		self.num += 1
		flow.response.headers["count"] = str(self.num)



# Set mitmproxy options
opts = options.Options(listen_host='0.0.0.0', listen_port=8080)
opts.add_option("body_size_limit", int, 0, "Maximum size of a single HTTP message body.")
opts.add_option("flow_detail", int, 1, "Flow detail.")

# Create a ProxyConfig
proxy_config = config.ProxyConfig(opts)

# Initialize and configure DumpMaster
m = DumpMaster(opts)
m.server = ProxyServer(proxy_config)
m.addons.add(AddHeader())

try:
	print("Impulse Proxy running on port 8080...")
	m.run()
except KeyboardInterrupt:
	m.shutdown()

