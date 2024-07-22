from flask import Flask, render_template, request, jsonify
import threading
from queue import Queue
import socket

app = Flask(__name__)

def portscan(port, target, results):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)  # Set a timeout for the connection attempt
    try:
        con = s.connect((target, port))
        results.append(port)
        con.close()
    except:
        pass

def threader(target, q, results):
    while True:
        worker = q.get()
        portscan(worker, target, results)
        q.task_done()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['host']
    start_port = int(request.form['start_port'])
    end_port = int(request.form['end_port'])

    q = Queue()
    results = []

    for x in range(100):
        t = threading.Thread(target=threader, args=(target, q, results))
        t.daemon = True
        t.start()

    for worker in range(start_port, end_port + 1):
        q.put(worker)

    q.join()

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
