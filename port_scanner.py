import threading
from queue import Queue
import socket

# A print_lock is what is used to prevent "double" modification of shared variables.
# This is used so while one thread is using a variable, others cannot access it.
# Once done, the thread releases the print_lock.
# To use it, you want to specify a print_lock per thing you wish to print_lock.
print_lock = threading.Lock()

# target = input("Enter site name: ")
target = 'scanme.nmap.org'
ip = socket.gethostbyname(target)
print("Scanning", target, "for open ports - THREADED")

def portscan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        con = s.connect((target, port))
        with print_lock:
            print('port', port)
        con.close()
    except:
        pass

# The threader thread pulls a worker from the queue and processes it
def threader():
    while True:
        # Gets a worker from the queue
        worker = q.get()
        # Run the example job with the available worker in the queue (thread)
        portscan(worker)
        # Completed with the job
        q.task_done()

# Create the queue and threader
q = Queue()

# Specify the range of ports to scan
for x in range(100):
    t = threading.Thread(target=threader)
    t.daemon = True
    t.start()

# Put the ports to scan into the queue
for worker in range(1, 101):
    q.put(worker)

# Wait until the thread terminates
q.join()
