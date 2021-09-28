import multiprocessing
import os
import socket
import psutil
import signal
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket

lock = multiprocessing.Semaphore()


def isOpen(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
        s.shutdown(2)
        return True
    except:
        return False


class PushSocket(WebSocket):
    is_up_to_date = False

    def handleMessage(self):
        pass

    def handleConnected(self):
        print(self.address, 'connected')

    def handleClose(self):
        print(self.address, 'closed')


class SocketServer(SimpleWebSocketServer):
    history = []

    def push(self, data):
        self.history.append(data)
        for c in self.connections:
            if not self.connections[c].is_up_to_date:
                for m in self.history.copy():
                    self.connections[c].sendMessage(m)
                self.connections[c].is_up_to_date = True
            self.connections[c].sendMessage(data)


class ServerProcess(multiprocessing.Process):
    def __init__(self, message_queue, sem):
        multiprocessing.Process.__init__(self)
        self.message_queue = message_queue
        self.sem = sem

    def run(self):
        host = '0.0.0.0'
        server = SocketServer(host, 8088, PushSocket)
        while True:
            if not self.message_queue.empty():
                data = self.message_queue.get()
                try:
                    dataint = int(data[1:-1])
                except Exception:
                    dataint = 0
                    pass
                if dataint == 1234:
                    print("Server was closed")
                    server.close()
                    s_proc = psutil.Process(os.getpid())
                    print('Releasing semaphore...')
                    self.sem.release()
                    s_proc.send_signal(signal.SIGTERM)
                    return
                server.push(data)
            server.serveonce()
