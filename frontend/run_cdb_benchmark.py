import time
import zmq
import threading

NUC_MODE = False
my_ip = server_ip = "localhost"

if (NUC_MODE): 
    my_ip = "128.32.37.55"
    server_ip = "128.32.37.34"

return_addr = "tcp://" + my_ip + ":3007"
local_dispatcher_addr = "tcp://" + server_ip + ":3005"
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
                    msg = recv_result_socket.recv().__str__()
                    print("[" + str(time.time())+ "]" + msg)
                    if "start" in msg:
                        logs += ("\nrecv," + str(time.time()))
                    if "end" in msg:
                        logs += ("\ndone," + str(time.time()))
                    if "dcr" in msg:
                        logs += ("\nack," + str(time.time()))
                    

def serialize_message(code):
    return (return_addr + delimiter + code).encode()

def get_code_from_load():
    times = 1
    print("running trace A (2000 puts) x times: " + str(times))
    with open("../YCSB_traces/tracea_load_a.txt") as f:
        lines = f.read().split("\n")
        cmd = "print(\"start\"); "
        for _ in range(times):
            for line in lines:
                key = line.split(" ")[1]
                value = line.split(" ")[2]
                value = "".join(e for e in value if e.isalpha())
                cmd += "cdb_put(\"" + key + "\",\"" + value + "\"); "
        cmd += "cdb_put(\"" + "Benchmark_End" + "\",\"" + "value" + "\"); "
    cmd += "print(\"end\"); "
    return cmd

def main():
    global logs
    server = ServerTask()
    server.start()
    code = get_code_from_load()
    context = zmq.Context()
    zmq_socket = context.socket(zmq.PUSH)
    zmq_socket.connect(local_dispatcher_addr)
    zmq_socket.send(serialize_message(code))
    logs += ("starting time," + str( time.time()))
    time.sleep(20)
    print(logs)


main()
