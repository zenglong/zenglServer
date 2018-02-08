# -*- coding: utf-8 -*-
# 请使用python3运行本脚本
import sys
if sys.version_info[0] < 3:
	sys.exit("Must be using Python 3")
import socketserver
import json
try:
	import readline
except ImportError:
	# 如果没有安装readline模块，则显示警告信息，readline模块主要用于linux系统中，在接受用户输入时可以使用上下左右键等
	# 如果需要安装readline模块，可以通过：https://pypi.python.org/pypi/pyreadline 下载pyreadline-2.1.zip，解压后，进入解压的目录，运行python3 setup.py install命令进行安装即可
	print("warning: your system have no readline module!")
import os
# from json.decoder import JSONDecodeError # start from python 3.5.x, so no portability

# 当接收到的数据为空时，即连接已经断开，则抛出MyEmptyException异常
class MyEmptyException(Exception):
	"""Base class for other exceptions"""
	def __init__(self, code, msg):
		super(MyEmptyException, self).__init__(code, msg)
		self.code = code

# MyTCPHandler类会在每次接收到连接时被实例化一次，并通过handle方法去处理连接
class MyTCPHandler(socketserver.BaseRequestHandler):
	"""
	The request handler class for our server.

	It is instantiated once per connection to the server, and must
	override the handle() method to implement communication to the
	client.
	"""
	dir_path = None # 当前主执行脚本的目录路径，使用l命令查看源码，以及使用b命令或者u命令时，如果要跟随文件名的话，该文件名需要相对于dir_path
	cur_filename = None # 当前执行脚本的文件名，包括目录路径在内
	cur_line = None # 当前执行代码所在的行号
	main_script_filename = None # 当前主执行脚本的文件名，包括目录路径在内
	filelist = None # 该成员用于缓存l命令获取到的脚本源码
	max_recv_bytes = 81920 # 每次从zenglServer客户端接收数据的最大字节数，如果要接收的数据比较大时，可以适当的调整该成员的值，以字节为单位
	offset = 8 # 使用l命令查看源码时，需要显示的上下偏移行数，例如：当offset为8时，显示第16行的代码，会将第8行到第24行的代码给显示出来

	# 从调试连接中获取zenglServer发送过来的数据
	def myrecv(self, bytes):
		#print('wait recv...')
		# self.request is the TCP socket connected to the client
		recv_msg = self.request.recv(bytes)
		if not recv_msg: # 如果在等待接收数据的过程中，zenglServer断开了连接，则返回None
			# EOF, client closed, just return
			print('listen connection...')
			return None
		recv_msg = recv_msg.decode('utf-8') # 将获取到的数据进行utf8解码，转为unicode字符串
		return recv_msg

	# 通过l命令从zenglServer获取到脚本的源码后，python会根据换行符将源码分割成content_list字符串列表，列表的每一项都对应一行源代码
	# 接着就可以根据line_no行号，以及offset行偏移，来从列表中将这些行的源码给获取出来了
	def get_content_ret_list(self, orig_path, normal_path, content_list, line_no = None, offset = None, show_filename = True):
		cur_normal_path = os.path.normpath(self.cur_filename)
		if(line_no is not None):
			cur_line = line_no
		else:
			cur_line = self.cur_line if(normal_path == cur_normal_path) else 1
		if(offset is None):
			offset = self.offset
		cur_index = cur_line - 1
		if (cur_index - offset) < 0:
			start_index = 0
		else:
			start_index = (cur_index - offset)
			if(start_index > (len(content_list) - 1)):
				start_index = len(content_list) - 1
		if(show_filename):
			if(normal_path == cur_normal_path):
				print("current run line:{} [{}]".format(self.cur_line, self.cur_filename))
			else:
				print("[{}]".format(orig_path))
		ret_list = content_list[start_index:cur_line+offset]
		ret_content = ""
		start_line = start_index + 1
		for line in ret_list:
			if (start_line == self.cur_line) and (normal_path == cur_normal_path):
				ret_content += "{}    {}    <<<---[ current line] ***\n".format(start_line, line) # 将当前执行代码所在的行用 <<<---[ current line] *** 在该行的末尾进行标注
			else:
				ret_content += "{}    {}\n".format(start_line, line)
			start_line += 1
		return ret_content

	# 处理用户输入的l命令，当用户通过l命令查看源码时，python会先将要查看的脚本文件名(相对于主执行脚本的文件路径)发送给zenglServer，由zenglServer将该脚本的源码一次发过来
	# 接着python会将源码根据\n换行符分割为字符串列表(列表的每一项都对应一行源码)，并将该列表存储到filelist词典中，词典的key为脚本文件的常规化后的路径，从而将源码缓存起来
	# 在显示源码时，就只需根据line_no行号和offset行偏移值，从列表中将所需的源码提取出来即可
	def list_command(self, filename = None, line_no = None, offset = None, show_filename = True):
		if self.filelist is None:
			self.filelist = dict()
		if filename is None:
			filename = self.cur_filename.replace(self.dir_path, '')
		orig_path = self.dir_path + filename
		normal_path = os.path.normpath(orig_path)
		if normal_path in self.filelist:
			return self.get_content_ret_list(orig_path, normal_path, self.filelist[normal_path], line_no, offset, show_filename)
		self.request.sendall("l {}".format(filename).encode('utf-8'))
		file_content = self.myrecv(self.max_recv_bytes)
		if not file_content:
			raise MyEmptyException
		self.request.sendall("ok".encode('utf-8'))
		self.filelist[normal_path] = file_content.split("\n")
		return self.get_content_ret_list(orig_path, normal_path, self.filelist[normal_path], line_no, offset, show_filename)

	# 将用户输入的命令根据空格符进行分割，并将分割形成的列表返回
	def get_command_list(self, command):
		command_list = command.split(" ")
		command_list = [x for x in command_list if x]
		for idx, line in enumerate(command_list):
			command_list[idx] = line.strip()
		return command_list

	# handle方法用于处理调试器接收到的zenglServer连接，该方法会将用户输入的调试命令，通过连接发送给zenglServer，并将zenglServer返回的结果显示出来
	def handle(self):
		print("{} connected:".format(self.client_address[0]))
		while(True):
			recv_msg = self.myrecv(1024)
			if not recv_msg:
				return
			try:
				# 如果接收到的是json数据，则说明当前发生了中断(单步执行或者触发断点等发生的中断)，json中包含了中断所在的脚本文件名，行号等信息
				recv_msg_decode = json.loads(recv_msg)
			except ValueError:
				# 如果不是json数据，则是zenglServer发来的其他的输出信息，例如日志断点中日志表达式的执行结果等，这些输出信息则直接通过print打印出来
				print("{}".format(recv_msg))
				self.request.sendall("ok".encode('utf-8')) # 接收到数据后，响应一个ok，表示接收到了数据，zenglServer的调试模块收到响应的ok才会继续执行
				continue
			if(recv_msg_decode['action'] == "debug"):
				self.main_script_filename = recv_msg_decode['main_script_filename'] # 获取主执行脚本的文件名，包括目录路径在内
				if(self.dir_path is None):
					ridx = self.main_script_filename.rfind('/')
					if(ridx >= 0):
						self.dir_path = self.main_script_filename[0:ridx+1] # 设置dir_path即主执行脚本的目录路径
					else:
						self.dir_path = ''
				self.cur_filename = recv_msg_decode['filename'] # 设置当前的执行脚本的文件名(包括目录路径在内)
				self.cur_line = int(recv_msg_decode['line']) # 设置当前执行代码所在的行
				cur_normal_path = os.path.normpath(self.cur_filename)
				main_normal_path = os.path.normpath(self.main_script_filename)
				# 将中断发生的脚本文件名(包括目录路径在内)，行号，触发的断点索引，主执行脚本文件路径等打印出来
				if(cur_normal_path == main_normal_path):
					format_str = "file:{},line:{},breakIndex:{}" # 如果当前执行脚本就是主执行脚本的话，则不显示main_script和dir_path信息
				else:
					format_str = "file:{},line:{},breakIndex:{}  [main_script:{}, dir_path:{}]"
				print(format_str.format(self.cur_filename, self.cur_line, recv_msg_decode['breakIndex'], self.main_script_filename, self.dir_path))
				if type(self.filelist) is not dict or cur_normal_path not in self.filelist: # 如果没有获取过当前执行脚本的源码，则通过list_command方法从zenglServer获取源码
					self.list_command(None, self.cur_line, None, False)
				print("{}    {}\n".format(self.cur_line, self.filelist[cur_normal_path][self.cur_line-1])) # 将当前执行代码所在的行的源码显示出来
				while(True): # 循环接受用户输入的调试命令
					input_command = input('zl debug >>> ').strip()
					command_list = self.get_command_list(input_command)
					command = " ".join(command_list)
					if(command == ''):
						print('command is empty')
						continue
					elif(command_list[0] == 'l'): # l查看源码命令进行单独处理
						filename = None # 用户输入的要查看源码的脚本文件名，相对于主执行脚本的文件路径
						line_no = None # 用户输入的要查看的行号
						offset = None # 要查看的行偏移
						for idx, command_part in enumerate(command_list):
							if(idx == 1): # l命令的第一个参数如果是数字则表示行号，否则就表示文件名
								if(command_part.isdigit()):
									line_no = int(command_part)
								else:
									filename = command_part
							elif(idx == 2): # 第二个参数为行号或者行偏移
								if(filename is not None): # 如果设置过文件名，就是行号
									line_no = int(command_part)
								else: # 否则就是行偏移
									offset = int(command_part)
							elif((idx == 3) and (filename is not None)): # 如果设置过文件名，第三个参数就是行偏移
								offset = int(command_part)
						try:
							print(self.list_command(filename, line_no, offset)) # 通过list_command方法来处理l命令
							continue
						except MyEmptyException:
							return
					self.request.sendall(input_command.encode('utf-8')) # 将其他调试命令发送给zenglServer去处理
					recv_msg = self.myrecv(self.max_recv_bytes) # 等待接收zenglServer的处理结果
					if not recv_msg: # 如果zenglServer关闭了连接，则直接返回
						return
					try:
						# 如果接收到的是json数据，则通过json中的exit字段来判断是否结束当前的中断
						recv_msg_decode = json.loads(recv_msg)
						self.request.sendall("ok".encode('utf-8')) # 响应ok给zenglServer
						if(recv_msg_decode['exit'] == 1): # 如果是c命令等，设置了exit为1，就break跳出内层的循环，从而结束当前的中断，并等待接收下一次的中断信息
							break
					except ValueError:
						# 如果接收到的不是json数据，则直接将信息通过print打印出来
						print("{}".format(recv_msg))
						self.request.sendall("ok".encode('utf-8')) # 响应ok给zenglServer
			else: # 理论上暂时不会执行到这里，目前，如果传递的中断json的action不是debug，就直接将数据打印出来
				print("{}".format(recv_msg))
				self.request.sendall("ok".encode('utf-8'))

if __name__ == "__main__":
	#HOST, PORT = "localhost", 9999
	if len(sys.argv) > 1:
		PORT = int(sys.argv[1]) # 通过第一个参数可以设置需要绑定的端口号，默认为9999
	else:
		PORT = 9999
	HOST = ""

	socketserver.TCPServer.allow_reuse_address = True
	# Create the server, binding to localhost on port 9999
	server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)

	print('listen connection [port:{}]...'.format(PORT))
	try:
		# Activate the server; this will keep running until you
		# interrupt the program with Ctrl-C
		server.serve_forever()
	except:
		print('except...')
		quit()
