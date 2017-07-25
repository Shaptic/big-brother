#!/usr/bin/python2

import os
import sys
import time
import socket
import select
import argparse
import threading

VERBOSITY = 0

def writeln(v, *args):
    args = list(args) + [ "\n" ]
    write(v, *args)

def write(v, *args):
    if VERBOSITY >= v:
        sys.stdout.write(' '.join(args))
        sys.stdout.flush()


class ReadQueue(object):
    """ A queue that combines incoming packets until a complete one is found.

    This is done by continually adding the result of a `socket.read` call until
    the special byte sequence indicating the end of a packet (protocol-specific)
    is found. This is then added to a queue to be processed, _if_ the
    packet can be properly parsed.
    """
    EOB = '\x00'

    def __init__(self):
        self.queue = []
        self.pending = ""

    def read(self, data):
        """ Processes some data into the queue.
        """
        writeln(2, "Received data:", repr(data))
        self.pending += data
        index = self.pending.find(self.EOB)
        if index == -1: return

        writeln(1, "Received full message:", repr(data))
        self.queue.append(self.pending[:index])
        self.pending = self.pending[index + len(ReadQueue.EOB):]

    @property
    def ready(self):
        """ Returns whether or not the queue is ready to be processed. """
        return bool(self.queue)

    def pop(self):
        """ Removes the oldest packet from the queue. """
        return self.queue.pop(0)


class InfiniteThread(threading.Thread):
    """ A utility base thread to run a method forever until its signalled.
    """
    def __init__(self, pause_length=0, **kwargs):
        super(InfiniteThread, self).__init__(**kwargs)
        self.sleep = pause_length
        self.running = True
        self.setDaemon(True)

    def run(self):
        while self.running:
            self._loop_method()
            if self.sleep:
                time.sleep(self.sleep)

    def _loop_method(self):
        raise NotImplemented

    def stop_running(self):
        self.running = False


class ListenerThread(InfiniteThread):
    TIMEOUT = 10     # how long should we wait for the socket to be ready?

    def __init__(self, sock, on_accept):
        """ Creates a thread to listen on a socket.

        :sock       A socket instance that is ready to accept clients.
        :on_accept  A callable handler that is called when clients connect.
                        on_accept(client_address, client_socket)
        """
        super(ListenerThread, self).__init__(name="ListenerThread",
            pause_length=0.2)

        self._on_accept = on_accept
        self.listener = sock

    def _loop_method(self):
        slist = [self.listener]
        rd, _, er = select.select(slist, [], slist, self.TIMEOUT)
        if rd:
            client, addr = self.listener.accept()
            writeln(0, "Established connection to tracker on %s:%d" % (addr[0], addr[1]))
            self._on_accept(addr, client)

        elif er:
            writeln(0, "An error occurred on the listener socket.")
            self.stop_running()


class CorrelationServer(InfiniteThread):
    """
    """
    def __init__(self, addr, port):
        super(CorrelationServer, self).__init__(name="ListenerThread",
            pause_length=0.2)

        self.listener = (addr, port)
        self.trackers = {}  # dict -> { socket: ReadQueue }

    def init(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((args.address, args.port))
        self.sock.listen(10)

    def stop_running(self):
        self.sock.close()
        super(CorrelationServer, self).stop_running()

    def _loop_method(self):
        slist = self.trackers
        readers, _, errors = select.select(slist, [], slist, 1)
        for sock in readers:
            data = sock.recv(64)
            queue = self.trackers[sock]
            queue.read(data)
            if queue.ready:
                message = queue.pop()
                self._on_message(message)

    def _on_message(self, raw_message):
        writeln(3, "Received message:", repr(raw_message))

        message = raw_message
        name, macs = message.split('|')
        writeln(0, "Payload from tracker:", name)
        for mac in macs.split(';'):
            writeln(0, "  - %s" % mac)

    def _on_new_tracker(self, address, tracker_sock):
        """
        """
        self.trackers[tracker_sock] = ReadQueue()

    @property
    def address(self):
        return self.listener[0]

    @property
    def port(self):
        return self.listener[1]


def main(args):
    server = CorrelationServer(args.address, args.port)

    try:
        server.init()
        listen = ListenerThread(server.sock, server._on_new_tracker)
        listen.start()
        server.start()
        for i in xrange(60):
            write(0, "%d, " % i)
            time.sleep(1)

    finally:
        listen.stop_running()
        server.stop_running()
        listen.join(1000)
        server.join(1000)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-a", "--bind", metavar="ADDR", dest="address", default="localhost",
        help="specifies the address on which to bind the listener socket")
    parser.add_argument("-p", "--port", type=int, default=0xC1A,
        help="specifies the port on which to bind the listener socket")
    parser.add_argument("-v", default=1, action="count",
        help="output level (1-3)")
    parser.add_argument("-q", "--quiet", action="store_true",
        help="stop all output, overriding -v")

    args = parser.parse_args()
    VERBOSITY = args.v if not args.quiet else 0

    main(args)
