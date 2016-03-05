import  os, time, socket, datetime, platform, urllib2, ssl

from OpenSSL import crypto, SSL

from twisted.internet import  defer, reactor, task, ssl as tssl
from twisted.web.http import HTTPChannel
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.web.static import File
from twisted.web.server import NOT_DONE_YET
from twisted.web.resource import NoResource

early_failures = 0
firmware_send_count = 0

def getTimestamp():
	return '{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())

def printStatus(str):
	print getTimestamp()+" "+str
	
def getHost():
	# From:
	# http://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
	return ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])

def validateCertHost(key_fname, cert_fname, tprint_fname, host):
	cert_host = ""
	try:
		cert_f = open(cert_fname)
		cert_data = cert_f.read()
		cert_f.close()
	
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
		cert_host = cert.get_subject().CN
	except IOError:
		pass
		
	if(cert_host == host):
		print "Previous key is valid for "+host
	else:
		cert = generateCert(key_fname, cert_fname, host)
		print "New key generated for: "+host
		
	
	thumbprint = cert.digest('sha1').replace(":"," ")
	print "Key thumbprint: "+thumbprint
	tp_file = open(tprint_fname, "w")
	tp_file.write(thumbprint)
	tp_file.close()
	
def generateCert(key_fname, cert_fname, host):
	# Inspired by:
	# https://skippylovesmalorie.wordpress.com/2010/02/12/how-to-generate-a-self-signed-certificate-using-pyopenssl/
	# create a key pair
	k = crypto.PKey()
	k.generate_key(crypto.TYPE_RSA, 2048)

	# create a self-signed cert
	cert = crypto.X509()
	cert.get_subject().CN = host
	cert.set_serial_number(1000)
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(365*24*60*60)
	cert.set_issuer(cert.get_subject())
	cert.set_pubkey(k)
	cert.sign(k, 'sha256')

	
	f = open(cert_fname, "wt")
	f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
	f.close()
	f = open(key_fname, "wt")
	f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
	f.close()
	
	return cert
	
def fetchFile(url, fname):
	ssl_ctx = None
	try:
		ssl_ctx = ssl.create_default_context()
		ssl_ctx.check_hostname = False
		ssl_ctx.verify_mode = ssl.CERT_REQUIRED
	except Exception:
		pass
	print "Fetching "+url
	with open(fname, "wb") as f:
		if(ssl_ctx == None):
			u =  urllib2.urlopen(url)
		else:
			u =  urllib2.urlopen(url, context=ssl_ctx)
		
		f.write(u.read())
	
	
class FirmwareSender:
	def __init__(self, request, firmware_data):
		self.request = request
		self.client_ip = "UNKNOWN"
		self.request_finished = False
		self.firmware_data = firmware_data
		request_finished_defer = request.notifyFinish()
		request_finished_defer.addBoth(lambda x: self.onRequestFinished(x))
	def run(self):
		global early_failures
		global firmware_send_count
		firmware_data = self.firmware_data
		firmware_size = len(firmware_data)
		request = self.request
		self.request_finished = False
		self.client_ip = request.getClientIP()
		chunk_size = 1024
		chunk_delay = .100
		
		printStatus("Starting firmware transfer to: "+request.getClientIP())
		#size = os.path.getsize(fname)
		request.setHeader('content-length', firmware_size)
		for i in xrange(0, firmware_size, chunk_size):
			request.write(firmware_data[i:i+chunk_size])
			time.sleep(chunk_delay)
			if(self.request_finished == True):
				early_failures = early_failures + 1
				printStatus("Early termination to: "+request.getClientIP()+" ("+str(i+chunk_size)+" bytes written, fail count = "+str(early_failures)+")")
				break
		firmware_send_count = firmware_send_count + 1		
		printStatus("Finishing firmware transfer to: "+request.getClientIP()+" ("+str(firmware_send_count)+" transfers done)")
		try:
			if(self.request_finished == False):
				if(platform.system() == "Windows"):
					time.sleep(1.0)
				self.request.finish()
		except Exception:
			pass

	def onRequestFinished(self, reason):
		printStatus("Firmware request finished for "+self.client_ip+" (Reason: "+str(reason)+")")
		self.request_finished = True

class FirmwareHandler(Resource):
	isLeaf = True
	def __init__(self, firmware_dir):
		self.firmware_files = ["firmware_v1.bin"]
		self.firmware_dict = dict()
		for fname in self.firmware_files:
			try:
				with open(firmware_dir+fname, "rb") as f:
					self.firmware_dict[fname] = f.read()
			except IOError as e:
				fetchFile("https://oakota.digistump.com/firmware/"+fname, firmware_dir+fname)
				# Hopefully this worked, and we got the file.  Otherwise, abort!
				with open(firmware_dir+fname, "rb") as f:
					self.firmware_dict[fname] = f.read()				
				
		Resource.__init__(self)
	
	def render_GET(self, request):
		for fname in self.firmware_dict.keys():
			if(fname in request.path):
				sender = FirmwareSender(request, self.firmware_dict[fname])
				reactor.callInThread(sender.run)
				return NOT_DONE_YET
		request.setResponseCode(404)
		return "<html><head><title>404</title></head><body><h1>404</h1></body></html>"

	def render_POST(self, request):
		return self.render_GET(request)

class MyHttpChannel(HTTPChannel):
	def __init__(self):

		self.ssl_context = tssl.DefaultOpenSSLContextFactory('data/cert/key.pem', 'data/cert/cert.pem')
		HTTPChannel.__init__(self)
	def connectionMade(self):
	
		printStatus("New connection from: "+self.transport.getPeer().host)
		sock = self.transport.getHandle()
		self.setTimeout(10)
		# Don't let data accumulate, send ASAP
		sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		if(platform.system() == "Linux"):
			# Don't let closed sockets hang out for long
			sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_LINGER2, 2)
			# TCP_USER_TIMEOUT closes connections if packets aren't ACK'ed
			# 18 = TCP_USER_TIMEOUT, open bug in python to expose this from "socket"
			sock.setsockopt(socket.IPPROTO_TCP, 18, 10*1000)
			sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
			sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)

			sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 600)
		elif(platform.system() == "Windows"):
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 0)
		
		# After KEEPINTVL seconds, KEEPCNT packets will be sent
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
		#print sock
		self.transport.startTLS(self.ssl_context)
	def connectionLost(self, reason):
		printStatus("Connection lost to: "+self.transport.getPeer().host)
		HTTPChannel.connectionLost(self, reason)
		

def startup():
	if not os.path.exists('data/firmware'):
		os.makedirs('data/firmware')
	if not os.path.exists('data/static'):
		os.makedirs('data/static')
	if not os.path.exists('data/cert'):
		os.makedirs('data/cert')
	# Check the certificate file
	host = getHost()
	validateCertHost('data/cert/key.pem', 'data/cert/cert.pem', 'data/static/thumb.txt', host)
	
	# Start up the HTTPS server
	web_port = 443
	root_handler = File('./data/static/')	
	firmware_handler = FirmwareHandler('data/firmware/')
	root_handler.putChild('firmware', firmware_handler)
	site = Site(root_handler)
	site.protocol = MyHttpChannel
	reactor.listenTCP(web_port, site)
	
	# Start up the HTTP server
	root_handler_http = File("./data/static/")
	config_handler = File("./config.html")
	root_handler_http.putChild('config.html', config_handler)
	site_http = Site(root_handler_http)
	reactor.listenTCP(8080, site_http)

	reactor.suggestThreadPoolSize(50)

	printStatus("Startup complete, running main loop...")

	# Run the main loop, this never returns:
	reactor.run()

	
if __name__ == '__main__':
	startup()