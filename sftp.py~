
#!/usr/bin/env python

import os, random, sys, hashlib, struct, thread, socket
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP		

ANONYMOUS_FILEPATH = "/home/ubuntu/anonymous/"		# This is the location where anonymously uploaded files are saved
PRIV_KEY_LOC = "/home/ubuntu/Desktop/id_rsa"
PUB_KEY_LOC = "/home/ubuntu/Desktop/id_rsa.pub"
CLIENT_HOST = "127.0.0.1"
USER_HOME = os.path.expanduser("~")					# get the user's home directory
TCP_CON_PORT = 9988									# TCP port for reverse connection - return Integrity validation results

def send_validation_result(result):					# this function uses a seperate socket connection to the client to send integrity validation results
	csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	# create a TCP (STREAM) socket
	csock.connect((CLIENT_HOST, TCP_CON_PORT))				# connect to the client
	csock.send(result)								# send the integrity validation result to the client
	csock.close()									# close the socket connection

def validation_server(port):						# this method listens for integrity validation results sent by the server
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	# create a TCP socket
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)	# set socket options to allow address reuse. This is important because when testing my client and the server is on the same machine
	sock.bind(("0.0.0.0",port))						# bind the server to all interfaces
	sock.listen(2)									# listen for incoming connections
	(client, (ip, clientport)) = sock.accept()		# accept a socket connection
	data = client.recv(2048)						# accept any data sent by the server
	if(data == "1"):
		print "[*] Integrity validation Passed!"	# if the server sent "1", integrity validation passed
	else:
		print "[-] Integrity validation Failed!!! File has been modified"	# else, integrity validation failed
	#thread.interrupt_main()
	os._exit(0)										# once integrity validation results are received, forcible quit the program. This is needed since we are in an infinite while loop at line 167

class MyHandler(FTPHandler):				#FTP server handler
	def on_file_received(self, filepath):	# Once the file is received by the server, trigger this event
		decrypt(filepath)					# decrypt the encrypted file at 'filepath'
		os.system("rm "+filepath)			# remove encrypted file after decrypting and saving

def validateIntegrity(orighash, destfilepath):			# Validate the integrity of the received file
	desthash = hashlib.md5(open(destfilepath, "rb").read()).hexdigest()		# calculate the received and decrypted file's MD5 checksum
	if(orighash==desthash):
		send_validation_result("1")
		return True 						# If the original hash matches the decrypted file's hash, return true		
	else:
		os.system("rm "+destfilepath)		# If two hashed do not match, file is either corrupted or modified in the middle. So delete the file..
		send_validation_result("0")
		return False						# ..and return false

def decrypt(filepath):						# function to decrypt files
	print "[!] Starting decryption...."
	dec_filename = ANONYMOUS_FILEPATH + os.path.basename(filepath).strip(".enc")
	inFile = open(filepath,"r")				# open the file to be decrypted as read-only
	chunksize=64*1024						# set the chunk size which is used as the block for block decryption
	hash = inFile.read(32)					# read the first 32 bytes from the file which contains the original file's hash		
	encAESKey = inFile.read(512)			# read second 512 bytes which is the RSA enrypted AES symmetric key
	
	#####decrypt AES symmetric key using RSA decryption with private key####
	private_key_loc = PRIV_KEY_LOC			
	privkey = open(private_key_loc, "r").read()			# open the SSH private key used for decryption
	rsakey = RSA.importKey(privkey)
	rsakey = PKCS1_OAEP.new(rsakey)						# use OAEP to create cipher for decryption
	aes_key = rsakey.decrypt(encAESKey) 				# decrypt the AES symmetric key using RSA decryption
	########################################################################

	origsize = struct.unpack('<Q', inFile.read(struct.calcsize('Q')))[0]	# calculate the original file size
	iv = inFile.read(16)								# extract next 16 bytes as the 16 bytes initialization vector 
	decryptor = AES.new(aes_key, AES.MODE_CBC, iv)		# create new AES Decryptor object

	with open(dec_filename, 'wb') as outfile:
		while True:
			chunk = inFile.read(chunksize)
			if len(chunk) == 0:
				break
			outfile.write(decryptor.decrypt(chunk))		# decrypt the file chunk by chunk using the created decryptor 
		
		outfile.truncate(origsize)						# truncate the decrypted file to the original size 
	
	print "[+] File was decrypted and saved at \""+dec_filename+"\""
	
	print "[!] Validating integrity..."
	if (validateIntegrity(hash, dec_filename)):			# call the integrity validator, pass the extracted original file's hash and the decrypted file's location to the function
		print "[+] Integrity validation Passed!"
	else:
		print "[-] Integrity validation Failed!"
	
	return dec_filename
	
def encrypt(filepath):
	print "[!] Starting Encryption...."
	aes_key = os.urandom(32)			# generate a 32 bit secret key using the random number generator
	out_filename = filepath + ".enc"
	filehash = hashlib.md5(open(filepath).read()).hexdigest()		# calculate the MD5 hash of the file to be sent
	
	public_key_loc = PUB_KEY_LOC
	#public key encryption of the symmetric key
	pubkey = open(public_key_loc, "r").read()			# open the SSH public key of the destination server
	rsakey = RSA.importKey(pubkey)						# import the public key
	rsakey = PKCS1_OAEP.new(rsakey)						# create the cipher using OAEP with RSA
	encKey = rsakey.encrypt(aes_key)					# encrypt the generated 21 bit AES key to be shared with the server
	outFile = open(out_filename,"w+")					# Open a new file which will be our encrypted file
	
	outFile.write(filehash)							# write the calculated MD5 hash of the original file at the begining of the file
	
	outFile.write(encKey)							# then, write the encrypted AES key, to the file
	
	iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))	# generate a 16 byte IV - Initialization vector which is used by AES algorithm with CBC to encrypt the first block of the file
	encryptor = AES.new(aes_key, AES.MODE_CBC, iv)	# create a new encryptor object
	filesize = os.path.getsize(filepath)			# calculate the size of the original file which we are going to encrypt
	chunksize=64*1024								# initialize chunk size for block encryption
	
	with open(filepath, 'rb') as infile:
		outFile.write(struct.pack('<Q', filesize)) 	# interpret the data string of the file as a packed binary data. This is needed at the destination to truncate the file to its original size.
		outFile.write(iv)							# write the generated IV to the file. IV is needed by the destination to decrypt only the first block of encrypted data
		
		while True:
			chunk = infile.read(chunksize)			# read a chunk of data from the file
			if len(chunk) == 0:						
				break								# if the chunk is empty, obviously file has been completed reading. So break the reading operation
			elif len(chunk) % 16 != 0:
				chunk += ' ' * (16 - len(chunk) % 16)	# if the chunk's size is not a multiple of 16 bytes, it needs to be padded so that it can be block encrypted. So add spaces as paddinig
			outFile.write(encryptor.encrypt(chunk))		# encrypt the chunk and write the encrypted chunk to the file
	
	outFile.close()
	print "[+] Encryption successful!"
	return out_filename				# return the encrypted file's path to the caller (client)

def startServer():
	authorizer = DummyAuthorizer()		# create a new FTP authorizer
	
	authorizer.add_anonymous(USER_HOME + "/anonymous", perm='elradfmwM') # add anonymous user, set the directory for anonymous file uploads and give enough permissions to the anonymous user
	# permissions are denoted by the charactors 'elradfmwM'. To see what they means please visit, https://code.google.com/p/pyftpdlib/wiki/Tutorial
	
	handler = MyHandler   				# select the created custom FTP hander 
	handler.authorizer = authorizer 	# assign the authorizer to the handler
	handler.banner = "Server Ready.."	# server banner is returned when the client calls a getWelcomeMessage() call
	hostname = ""						# hostname is empty, which implies all interfaces (0.0.0.0)
	address = (hostname,21)				
	server = FTPServer(address, handler)	# start listening on port 21 on all interfaces
	
	server.max_cons = 10 				# maximum number of simultanious connections per time
	server.serve_forever()				# start the server
	
	
	
def startClient():
	from ftplib import FTP		# import ftplib for FTP client operation
	thread.start_new_thread(validation_server, (TCP_CON_PORT,))	# start the validation server in a seperate thread so that it runs seperately from the client
	hostname = sys.argv[2]				# read the second command line argumand to the python script as the destination FTP server hostname
	ftp = FTP(hostname)					# create a new FTP object associated with the desired host
	ftp.login()							# anonymously login to the FTP server
	filepath = sys.argv[3]				# read the 3rd command line argument as the path of the file to be transfered to the server
	encFilepath = encrypt(filepath)		# call the encryption function to encrypt the file
	
	localfile = open(encFilepath,"rb")	# open the encrypted file
	try:
		print "[!] File Transfer in Progress...."
		result = ftp.storbinary("STOR "+str(os.path.basename(encFilepath)),localfile)	# transfer the encrypted file to the FTP server using raw FTP STOR command. Result of the data transfer will be returned
	except Exception as e:
		print e 	# print any exception occured
	else:
		print str(result)	# if no exception occured, show the result
		
	os.system("rm "+encFilepath)	# once the file transfer is successfully completed, remove the encrypted version of the file
	print "[!] Waiting for integrity validation..."
	while True:
		pass
	
	
def main():
	method = sys.argv[1]	# read the first command line argument to this python script
	if(method == "server"):
		startServer()			# if the argument is equal to "server" start FTP server
	elif(method == "client"):
		startClient()			# if the argument is "client" continue as a client
	else:
		print "[-] Unknown method! Exiting.."	# if the argument is unknown, exit program
		exit()

if __name__=="__main__":
	main()			# run the main function
 @harora
 Styling with Markdown is supported
Write Preview

Leave a comment
Attach files by dragging & dropping,  Choose Files selecting them, or pasting from the clipboard.
Comment
Status API Training Shop Blog About Pricing
© 2015 GitHub, Inc. Terms Privacy Security Contact Help