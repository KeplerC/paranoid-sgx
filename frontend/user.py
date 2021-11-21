import zmq
from time import sleep
import zmq
import threading
import time
from random import choice


return_addr = "tcp://localhost:3007"
local_dispatcher_addr = "tcp://localhost:3005"



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

def main():
    server = ServerTask()
    server.start()
    context = zmq.Context()
    zmq_socket = context.socket(zmq.PUSH)
    zmq_socket.connect(local_dispatcher_addr)
    zmq_socket.send(b"print(1+1)")
    server.join()

main()