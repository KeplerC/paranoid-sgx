import zmq
from time import sleep
import zmq
import threading
import time
from random import choice
from flask import Flask, render_template, request
from proto import capsule_pb2

my_ip = "128.32.37.26"
server_ip = "128.32.37.46"
#my_ip = server_ip = "localhost"
return_addr = "tcp://" + my_ip + ":3007"
local_dispatcher_addr = "tcp://" + server_ip + ":30050"
delimiter = "@@@"
results = ""
logs = ""

class ServerTask(threading.Thread):
    """ServerTask"""
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        global logs
        global results
        context = zmq.Context()
        recv_result_socket = context.socket(zmq.PULL)
        recv_result_socket.bind('tcp://*:3007')

        poll = zmq.Poller()
        poll.register(recv_result_socket, zmq.POLLIN)
        while True:
            sockets = dict(poll.poll())
            if recv_result_socket in sockets:
                if sockets[recv_result_socket] == zmq.POLLIN:
                    msg = recv_result_socket.recv()
                    received_capsule = capsule_pb2.CapsulePDU()
                    print("=========")
                    received_capsule.ParseFromString(msg)
                    #decoded_msg = msg.decode('utf-8', 'backslashreplace')
                    print(received_capsule)
                    logs = received_capsule.__str__() + " \n " + logs
                    results =  "Latest result: " + received_capsule.payload_in_transit.split("@@@")[3] 

def serialize_message(code):
    return (return_addr + delimiter + code).encode()

def main():
    server = ServerTask()
    server.start()
    #server.join()

main()
app = Flask(__name__)

@app.route('/', methods=('GET', 'POST'))
def index():
    if request.method == 'POST':
        print(request.form)
        if (not request.form["num_lambda"] or not request.form["js_code"]):
            pass
        else:
            for i in range(int(request.form["num_lambda"])):
                context = zmq.Context()
                zmq_socket = context.socket(zmq.PUSH)
                zmq_socket.connect(local_dispatcher_addr)
                zmq_socket.send(serialize_message(request.form["js_code"]))
    global logs
    global results
    post = {"result": results, "log": logs}
    return render_template('index.html', posts=post)

app.run(host='0.0.0.0')
