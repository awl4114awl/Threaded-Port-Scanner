## Threaded Port Scanner

This repository contains a Python script for performing a threaded port scan on a specified target. The script uses multithreading to efficiently scan multiple ports simultaneously, significantly reducing the time required to find open ports.

### Features

- Scans a specified range of ports on a given target.
- Utilizes multithreading to speed up the scanning process.
- Prints open ports as they are discovered.
- Demonstrates basic socket programming and threading in Python.

### Prerequisites

- Python 3.x
- Basic understanding of networking and Python programming.

### Getting Started

1. **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/threaded-port-scanner.git
    cd threaded-port-scanner
    ```

2. **Run the script:**
    ```bash
    python port_scanner.py
    ```

### Script Overview

The script performs the following steps:

1. Imports the necessary libraries: `threading`, `queue`, `time`, and `socket`.
2. Initializes a print lock to prevent multiple threads from printing simultaneously.
3. Defines the target domain (`scanme.nmap.org`) to be scanned and resolves it to an IP address.
4. Defines the `portscan` function that attempts to connect to a specified port and prints the port number if it is open.
5. Defines the `threader` function that continuously gets workers (ports) from the queue and processes them using the `portscan` function.
6. Creates a queue and starts 100 daemon threads running the `threader` function.
7. Puts the port numbers to be scanned into the queue.
8. Waits for all threads to complete their tasks.

### Full Code

```python
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
```

### Customization

- **Target Domain:**
    Change the `target` variable to scan a different domain:
    ```python
    target = 'example.com'
    ```

- **Port Range:**
    Adjust the range in the `for worker in range(1, 101):` loop to scan different ports:
    ```python
    for worker in range(1, 65536):  # Scans all ports from 1 to 65535
    ```

### Contributions

Contributions are welcome! Feel free to open an issue or submit a pull request with any improvements or bug fixes.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### Acknowledgements

- [Python Documentation](https://docs.python.org/3/)
- [Nmap](https://nmap.org) for providing a test target (`scanme.nmap.org`)

### Contact

For any inquiries or feedback, please contact [jordanryancalvert@gmail.com](mailto:jordanryancalvert@gmail.com).
