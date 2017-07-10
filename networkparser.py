#!/usr/bin/env python2
import os
import sys

import csv
import json
import pprint
import requests
import argparse
import collections

IGNORE_SSIDS = [
    "xfinitywifi",
]

API_KEY = ""
with open(".keys") as f: API_KEY = f.read().strip()
API_URL = "https://www.googleapis.com/geolocation/v1/geolocate?key=%s" % API_KEY


class Network(object):
    networks = []

    def __init__(self, mac, name, security):
        self.mac = mac
        self.name = name.strip() if name else "n/a"
        self.security = security.strip() if security else "???"
        self.clients = []
        self._location = None
        if self.name not in IGNORE_SSIDS:
            Network.networks.append(self)

    def __str__(self):
        return "<%s | %s[%s]>" % (self.mac, self.name, self.security)

    def __repr__(self):
        return str(self)

    @property
    def location(self):
        return self._location["location"] if self._location else None

    @property
    def accuracy(self):
        return self._location["accuracy"] if self._location else None

    def get_location(self, verbosity=0):
        def write(*args):
            if verbosity <= 0: return
            print ' '.join(args)

        args = json.dumps({
            "considerIp": "false",
            "wifiAccessPoints": [{ "macAddress": self.mac.lower()
        }]})

        r = requests.post(API_URL, data=args,
            headers={"Content-Type": "application/json"})

        write("For network:", self.mac)

        if r.status_code == 404:
            write("  No location found.")
            return {"location": None, "accuracy": None}

        j = r.json()
        write("  Location: (%f, %f)" % (j["location"].values()))
        write("  Accuracy: %0.4f" % (j["accuracy"]))
        return j


class Client(object):
    clients = []

    def __init__(self, mac, network, network_name):
        self.mac = mac
        self.network_name = network_name.strip() if network_name else "n/a"
        self._network = None
        for nw in Network.networks:
            if nw.mac == network:
                self._network = nw
                nw.clients.append(self)
        Client.clients.append(self)

    @property
    def network(self):
        return self._network.mac if self._network else "n/a"

    def __str__(self):
        return "<%s => %s[%s]>" % (self.mac, self.network, self.network_name)

    def __repr__(self):
        return str(self)


def parse_csv(csvf, verbosity=0):
    """ Parses an airodump-ng capture file into a collection of networks.

    If there are any unassociated clients found, these are parsed as well.

    :csvf           the CSV file handle, assumed to be seeked to the line before
                    the column headers.
    :verbosity[=0]  determines the level of output when parsing.
    :returns        2-tuple of ([ Network() ], [ Client() ]) objects.
    """
    networks, clients = [], []

    csvf.readline()     # first line is assumed to be blank
    reader = csv.reader(csvf, skipinitialspace=True)
    columns = next(reader)

    if verbosity >= 2:
        print "Available columns:"
        print "  -%s" % ("\n  -".join(columns))

    #
    # The network columns we are interested in are:
    #   - BSSID:    the MAC address of the AP.
    #   - ESSID:    the human-readable name of the AP (if any).
    #   - Privacy:  the security level of the AP (like WPA2, OPN, etc.)
    #
    idxs = [columns.index(s) for s in ["BSSID", "ESSID", "Privacy"]]

    for row in reader:
        if not row: break   # network section has ended

        fields = [row[idx] for idx in idxs]
        nw = Network(*fields)
        networks.append(nw)

        if verbosity >= 1:
            print "  -", nw

    if verbosity >= 2: print "Processing clients now."

    reader = csv.reader(csvf, skipinitialspace=True)
    columns = next(reader)

    #
    # The client columns we are interested in are:
    #   - BSSID:            the MAC address of the client
    #   - Station MAC:      the MAC address of the network that the client is
    #                       connected to, if any (non-disassociated).
    #   - Probed ESSIDs:    the readable name of the AP, if any.
    #
    idxs = [columns.index(s) for s in ["BSSID", "Station MAC", "Probed ESSIDs"]]

    for row in reader:
        if not row: break

        fields = [row[idx] for idx in idxs]
        cli = Client(*fields)
        clients.append(cli)

        if verbosity >= 1:
            print "  -", cli

    return networks, clients


def get_open_networks(network_list):
    """ Finds all of the networks with no security.
    """
    return filter(lambda x: x.security == "OPN", network_list)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=
        "Extracts all open networks from an airodump-ng capture file.")
    parser.add_argument("-f", "--filename", metavar="FNAME", help="capture to extract from")
    parser.add_argument("--address", metavar="BSSID", help="MAC address of AP to lookup")
    parser.add_argument("--exclude", nargs="+", help="ESSIDs to exclude if found")
    parser.add_argument("-c", "--clients", action="store_true",
        help="include any clients that were found")
    parser.add_argument("--open", action="store_true",
        help="only return open network results")
    parser.add_argument("-l", "--location", dest="loc", action="store_true",
        help="include the location information for each network")
    parser.add_argument("-v", dest="v", default=0,
        action="count", help="configures level of output")

    args = parser.parse_args()

    if args.address:
        Network(args.address).get_location()

    elif args.filename:
        fname = args.filename
        fname = os.path.expanduser(fname)

        if not os.path.exists(fname):
            print "The file '%s' does not exist." % args.filename
            sys.exit(1)

        if os.path.splitext(fname)[1].lower() != ".csv":
            print "The file isn't in CSV format."
            sys.exit(1)

        with open(fname, "r") as f:
            nw, cli = parse_csv(f, args.v)
            if args.open:
                nw = get_open_networks(nw)

            for n in nw:
                if n.name in args.exclude:
                    continue

                print "%s | %s[%s]" % (n.mac, n.name, n.security)
                if args.loc:
                    location = n.get_location(args.v)
                    if not location or location["location"] is None:
                        print "  (no location found)"
                        continue

                    print "  (%f, %f) [accuracy=%f]" % (
                        location["location"]["lat"],
                        location["location"]["lng"],
                        location["accuracy"]["lng"])

            if args.clients:
                for c in cli:
                    print "%s [connected-to=%s|%s" % (
                        c.mac, c.network.mac, c.network_name)

    else:
        print "Must choose one of --filename or --address."
