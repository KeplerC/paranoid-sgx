import zmq
from time import sleep
import zmq
import threading
import time
from random import choice

my_ip = "128.32.37.46"
server_ip = "128.32.37.26"
my_ip = server_ip = "localhost"
return_addr = "tcp://" + my_ip + ":3007"
local_dispatcher_addr = "tcp://" + server_ip + ":3005"
delimiter = "@@@"


class ServerTask(threading.Thread):
    """ServerTask"""

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
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
                    print(msg)

def serialize_message(code):
    return (return_addr + delimiter + code).encode()

def main():
    server = ServerTask()
    server.start()
    context = zmq.Context()
    zmq_socket = context.socket(zmq.PUSH)
    zmq_socket.connect(local_dispatcher_addr)
    zmq_socket.send(serialize_message("print(1+1)"))
    server.join()

main()
