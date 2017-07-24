#!/usr/bin/python2
import subprocess as sub
import argparse
import time
import sys
import os

import networkparser


CAPTURE_PREFIX = "captures/cap"
SNIFFER_TIME = 8
VERBOSITY = 1   # 0: nothing, 1: normal, 2: extra, 3: all


class PromiscuousAdapter(object):
    """ Allows an adapter to cleanly enter and exit monitor mode.
    """
    def __init__(self, interface):
        self.iface = interface
        self.ifacemon = "%smon" % self.iface

    def __enter__(self):
        writeln(3, "Configuring", self.iface, "for monitor mode.")
        run("./monitor.sh %s start" % self.iface)
        return self.ifacemon

    def __exit__(self, type, value, traceback):
        writeln(3, "Configuring", self.ifacemon, "out of monitor mode.")
        run("./monitor.sh %s stop" % self.ifacemon)


def writeln(v, *args):
    args = list(args) + [ "\n" ]
    write(v, *args)

def write(v, *args):
    if VERBOSITY >= v:
        sys.stdout.write(' '.join(args))
        sys.stdout.flush()

def run(cmd):
    writeln(3, cmd)
    return sub.Popen(cmd, shell=True, stdout=sub.PIPE,
        stderr=sub.PIPE).communicate()

def scan(operation):
    if os.path.exists(operation):
        filename = operation

    else:
        iface = operation
        writeln(2, iface, "isn't a file, treating it as an interface.")

        with PromiscuousAdapter(iface) as mon:
            run("screen -dmS dump sudo airodump-ng -o csv -w %s %s" % (
                CAPTURE_PREFIX, mon))

            write(1, "Running network sniffer.", )
            for i in xrange(SNIFFER_TIME):
                write(1, '.')
                time.sleep(1)
            writeln(1)

            run("screen -XS dump quit")

        time.sleep(5)   # wait for connectivity to restore

        # Grab the latest capture file (by name) for processing.
        path = os.path.dirname(CAPTURE_PREFIX)
        if not path: path = os.getcwd()
        if not os.path.exists(path): os.makedirs(path)
        name = os.path.basename(CAPTURE_PREFIX)

        writeln(3, "Looking for %s/%s*.csv" % (path, name))
        files = sorted([fn for fn in os.listdir(path) \
            if fn.startswith(name) and fn.endswith(".csv")])
        writeln(2, "Available files: %s" % repr(files))
        filename = os.path.join(path, files[-1])

    writeln(2, "Parsing network traffic from", filename)

    networks, clients = [], []
    with open(filename, "r") as csv:
        networks, clients = networkparser.parse_csv(csv)
        networks = networkparser.get_open_networks(networks)
        networks = networkparser.filter_duplicate_names(networks)

    joined_macs = set()
    for nw in networks:
        if nw.name == "n/a":
            writeln(2, "Skipping hidden SSID network:", nw.mac)
            continue

        writeln(1, "Connecting to open network:", nw.name)
        writeln(2, "  BSSID: %s" % nw.mac.upper())
        writeln(2, "  Signal strength: %d%%" % nw.signal)

        stdout, _ = run("./connect.sh %s --forget | %s" % (nw.mac.upper(),
            'grep -iP \'^\s*([A-Fa-f\d]{2}:?){6}\''))

        found_macs = set([x.strip() for x in stdout.split('\n') if x.strip()])
        if not found_macs:
            writeln(1, "  No clients on this network.")
        else:
            writeln(1, "  Found clients:")
            writeln(1, "   ", "\n    ".join(found_macs))

        joined_macs = joined_macs.union(found_macs)
        writeln(1)

    return joined_macs, set([c.mac for c in clients])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=""
        "This script MUST be run as root (for interface monitor mode). "
        "This runs a tracker node, intended to be connected to a surveillance "
        "master server.")
    parser.add_argument("op", metavar="IFACE|FILENAME",
        help="either an interface to scan, or a capture file to process")
    parser.add_argument("-i", "--interval", metavar="SEC", type=int, default=30,
        help="specifies delay between vicinity scans")
    parser.add_argument("-n", "--count", type=int, default=1,
        help="specifies number of scan sequences to perform, 0 means infinite")
    parser.add_argument("-v", default=1, action="count",
        help="output level (1-3)")
    parser.add_argument("-q", "--quiet", action="store_true",
        help="stop all output, overriding -v")
    args = parser.parse_args()

    VERBOSITY = args.v if not args.quiet else 0

    # Check for root permissions by binding a socket to a protected port.
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("localhost", 1023))
    except socket.error, e:
        import errno
        if e[0] in (errno.EPERM, errno.EACCES):
            print "Must be root to run this script."
            sys.exit(e[0])
    finally:
        s.close()
        del s

    n = 0
    while args.count == 0 or n < args.count:
        joined_macs, unassoc_macs = scan(args.op)
        n += 1

        # Don't needlessly sleep on the last run
        if n < args.count:
            writeln(1, "Completed scan, %ds until the next one...\n" % args.interval)
            time.sleep(args.interval)
