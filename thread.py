import threading

class ThreadClass(threading.Thread):
	def run(self,name):
		for i in range(10):
			print name+''+i

f=ThreadClass('f')
s=ThreadClass('s')
t=ThreadClass('t')

f.start()
s.start()
t.start()