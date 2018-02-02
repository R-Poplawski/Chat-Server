from SimpleWebSocketServer import WebSocket
import dataset
import json
import hashlib
import os
import base64
import re

db = dataset.connect('mysql://root:root@127.0.0.1/chatdb')
clients = []


class ChatInstance(WebSocket):
	def handleMessage(self):
		print (self.address, 'Received message: ' + self.data)
		try:
			jsonObject = json.loads(self.data)
			handler = jsonObject.keys()[0]
			obj = jsonObject[handler]
			self.on_message(handler, obj)
		except:
			response = {'error': {}}
			self.sendMessage(response)
			print (self.address, 'Sending response: ' + response)


	def handleConnected(self):
		print (self.address, 'connected')
		clients.append(self)
		self.uid = -1
	  

	def handleClose(self):
		clients.remove(self)
		print (self.address, 'closed')
		
	
	def send_packet(self, handler, obj):
		msg = {handler: obj}
		jsonStr = unicode(json.dumps(msg))
		self.sendMessage(jsonStr)
		print (self.address, 'Sending response: ' + jsonStr)
		
	
	def on_message(self, handler, data):
		if handler == 'send_message':
			self.send_message(data)
		elif handler == 'get_messages':
			self.get_messages(data)
		elif handler == 'request_contact':
			self.request_contact(data)
		elif handler == 'accept_request':
			self.accept_request(data)
		elif handler == 'remove_contact':
			self.remove_contact(data)
		elif handler == 'login':
			self.login(data)
		elif handler == 'register':
			self.register(data)
	

	def login(self, data):
		username = data['username']
		password = data['password']
		user = self.check_credentials(username, password)
		if user:
			print (self.address, 'Authenticated as %s' % user['username'])
			self.uid = user['id']
			self.username = user['username']
			contacts = self.get_user_contacts()
			requests = self.get_requests()
			self.send_packet('login', {'success': True, 'id': self.uid, 'username': user['username'], 'contacts': contacts, 'requests': requests})
		else:
			print (self.address, 'Failed to authenticate user: \"' + username + '\"')
			self.uid = -1
			self.username = ''
			self.send_packet('login', {'success': False})
		
		
	def register(self, data):
		username = data['username'].strip()
		password = data['password']
		
		if len(username) < 4:
			self.send_packet('register', {'success': False, 'error': 'username too short'})
			return
		if len(password) < 4:
			self.send_packet('register', {'success': False, 'error': 'password too short'})
			return
		if not re.match("^[a-zA-Z0-9_ ]*$", username):
			self.send_packet('register', {'success': False, 'error': 'username contains invalid characters'})
			return
		
		user = self.get_user(username)
		if user:
			print (self.address, 'Registration failed')
			self.send_packet('register', {'success': False, 'error': 'username taken'})
		else:
			salt = self.generate_salt()
			hash = self.get_hash_with_salt(password, salt)
			users = db['users']
			self.uid = users.insert(dict(username=username, pass_hash=hash, pass_salt=salt))
			self.send_packet('register', {'success': True, 'id': self.uid, 'username': username})
		
		
	def request_contact(self, data):
		if not self.uid or self.uid < 0:
			self.send_packet('request_contact', {'success': False, 'error': 'you are not logged in'})
			return
		username = data['username']
		user = self.get_user(username)
		if not user:
			self.send_packet('request_contact', {'success': False, 'error': 'user not found'})
			return
		if user['id'] == self.uid:
			self.send_packet('request_contact', {'success': False, 'error': 'you can\'t add yourself'})
			return
		contacts = db['contacts']
		if contacts.find_one(list_owner=self.uid, contact=user['id']):
			self.send_packet('request_contact', {'success': False, 'error': 'user is in your contacts already'})
			return
		contact_requests = db['contact_requests']
		response = contact_requests.find_one(requesting_user=self.uid, recipient=user['id'])
		if response:
			self.send_packet('request_contact', {'success': False, 'error': 'request already exists'})
			return
		request2 = contact_requests.find_one(requesting_user=user['id'], recipient=self.uid)
		if request2:
			data = {'id': user['id']}
			self.accept_request(data)
			return
		contact_requests.insert(dict(requesting_user=self.uid, recipient=user['id']))
		self.send_packet('request_contact', {'success': True, 'id': user['id'], 'username': user['username']})
		receiving_client = self.get_client(user['id'])
		if receiving_client:
			receiving_client.send_packet('incoming_request', {'id': self.uid, 'username': self.username})


	def accept_request(self, data):
		if not self.uid or self.uid < 0:
			self.send_packet('accept_request', {'success': False, 'error': 'you are not logged in'})
			return
		user_id = data['id']
		users = db['users']
		user = users.find_one(id=user_id)
		if not user:
			self.send_packet('accept_request', {'success': False, 'error': 'user doesn\'t exist'})
			return
		contact_requests = db['contact_requests']
		request = contact_requests.find_one(requesting_user=user_id, recipient=self.uid)
		if not request:
			self.send_packet('accept_request', {'success': False, 'error': 'request doesn\'t exist'})
			return
		contacts = db['contacts']
		if not contacts.find_one(list_owner=self.uid, contact=user_id):
			contacts.insert(dict(list_owner=self.uid, contact=user_id))
		if not contacts.find_one(list_owner=user_id, contact=self.uid):
			contacts.insert(dict(list_owner=user_id, contact=self.uid))
		contact_requests.delete(requesting_user=user_id, recipient=self.uid)
		self.send_packet('accept_request', {'success': True, 'id': user_id, 'username': user['username']})
		requesting_client = self.get_client(user_id)
		if requesting_client:
			requesting_client.send_packet('accept_request', {'success': True, 'id': self.uid, 'username': self.username})
			
			
	def remove_contact(self, data):
		if not self.uid or self.uid < 0:
			self.send_packet('remove_contact', {'success': False, 'error': 'you are not logged in'})
			return
		user_id = data['id']
		users = db['users']
		user = users.find_one(id=user_id)
		if not user:
			self.send_packet('remove_contact', {'success': False, 'error': 'user doesn\'t exist'})
			return
		contacts = db['contacts']
		if not contacts.find_one(list_owner=self.uid, contact=user_id):
			self.send_packet('remove_contact', {'success': False, 'error': 'contact doesn\'t exist'})
			return
		else:
			contacts.delete(list_owner=self.uid, contact=user_id)
		if contacts.find_one(list_owner=user_id, contact=self.uid):
			contacts.delete(list_owner=user_id, contact=self.uid)
		self.send_packet('remove_contact', {'success': True, 'id': user_id})
		removed_client = self.get_client(user_id)
		if removed_client:
			removed_client.send_packet('incoming_remove', {'id': self.uid})
	
	def send_message(self, data):
		if not self.uid or self.uid < 0:
			self.send_packet('send_message', {'success': False, 'error': 'you are not logged in'})
			return
		user_id = data['id']
		users = db['users']
		user = users.find_one(id=user_id)
		if not user:
			self.send_packet('send_message', {'success': False, 'error': 'user doesn\'t exist'})
			return
		contacts = db['contacts']
		if not contacts.find_one(list_owner=self.uid, contact=user_id):
			self.send_packet('send_message', {'success': False, 'error': 'user is not in your contacts'})
			return
		content = data['content']
		if not content or len(content) == 0:
			self.send_packet('send_message', {'success': False, 'error': 'empty message'})
			return
		messages = db['messages']
		m_id = messages.insert(dict(sender=self.uid, recipient=user_id, content=content))
		msg = messages.find_one(id=m_id)
		self.send_packet('send_message', {'success': True, 'id': m_id, 'recipient': user_id, 'content': content, 'date_sent': msg['date_sent'].__str__()})
		recipient_client = self.get_client(user_id)
		if recipient_client:
			recipient_client.send_packet('incoming_message', {'id': m_id, 'sender': self.uid, 'content': content, 'date_sent': msg['date_sent'].__str__()})
			
	
	def get_messages(self, data):
		if not self.uid or self.uid < 0:
			self.send_packet('get_messages', {'success': False, 'error': 'you are not logged in'})
			return
		user_id = data['user_id']
		oldest_message_id = data['oldest_message_id']
		users = db['users']
		user = users.find_one(id=user_id)
		if not user:
			self.send_packet('get_messages', {'success': False, 'error': 'user doesn\'t exist'})
			return
		limit = 25
		s1 = ""
		if oldest_message_id > 0:
			s1 = "id < %s AND " % oldest_message_id
		statement = """SELECT * FROM messages 
					WHERE %s((sender = %s AND recipient = %s) OR (sender = %s AND recipient = %s)) 
					ORDER BY id DESC LIMIT %s""" % (s1, self.uid, user_id, user_id, self.uid, (limit + 1))
		result = db.query(statement)
		more = False
		messages = []
		for row in result:
			if len(messages) < limit:
				date_sent = (row['date_sent']).__str__()
				m = {'id': row['id'], 'sender': row['sender'], 'recipient': row['recipient'], 'content': row['content'], 'date_sent': date_sent}
				messages.insert(0, m)
			else:
				more = True
		self.send_packet('get_messages', {'success': True, 'user_id': user_id, 'messages': messages, 'more_messages': more})
		
	def get_user(self, username):
		username = self.escape_sql(username.strip())
		statement = 'SELECT * FROM users WHERE lower(username) LIKE \'' + username.lower() + '\''
		result = db.query(statement)
		try:
			user = next(result)
			return user
		except:
			return None
			
			
	def get_client(self, id):
		for client in clients:
			if client.uid == id:
				return client
		return None
	
	
	def get_user_contacts(self):
		user_contacts = []
		if self.uid and self.uid >= 0:
			contacts = db['contacts']
			users = db['users']
			contact_obj = contacts.find(list_owner=self.uid)
			for o in contact_obj:
				contact = users.find_one(id=o['contact'])
				c = {'id': contact['id'], 'username': contact['username']}
				user_contacts.append(c)
		return user_contacts
		
		
	def get_requests(self):
		requesting_users = []
		if self.uid and self.uid >= 0:
			contact_requests = db['contact_requests']
			users = db['users']
			request_obj = contact_requests.find(recipient=self.uid)
			for o in request_obj:
				user = users.find_one(id=o['requesting_user'])
				u = {'id': user['id'], 'username': user['username']}
				requesting_users.append(u)
		return requesting_users
	
		
	def get_hash(self, input):
		hash_object = hashlib.sha512(input)
		hex_dig = hash_object.hexdigest()
		return hex_dig
		
	
	def get_hash_with_salt(self, input, salt):
		return self.get_hash(input + salt)
		
	
	def generate_salt(self):
		salt = os.urandom(16)
		return str(base64.b64encode(salt))
		
	
	def escape_sql(self, str):
		str = str.replace("\\", "\\\\")
		str = str.replace("\'", "\'\'")
		str = str.replace("\"", "\"\"")
		
		return str
	
	
	def check_credentials(self, username, password):
		username = self.escape_sql(username)
		statement = 'SELECT * FROM users WHERE lower(username) LIKE \'' + username.lower() + '\''
		result = db.query(statement)
		try:
			user = next(result)
			salt = user['pass_salt']
			hash = self.get_hash_with_salt(password, salt)
			if hash == user['pass_hash']:
				return user
		except Exception:
			return None
	
