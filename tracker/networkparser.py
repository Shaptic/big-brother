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

# https://developers.google.com/maps/documentation/geolocation/
API_URL = "https://www.googleapis.com/geolocation/v1/geolocate?key=%s" % API_KEY

# https://www.mylnikov.org/archives/1170
BKP_URL = "http://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid=%s"


class Network(object):
    networks = []

    def __init__(self, mac, name, security, signal):
        self.mac = mac
        self.name = name.strip() if name else "n/a"
        self.security = security.strip() if security else "???"

        #
        # As per the airodump specification, -1 has a special meaning for
        # networks:
        #
        #   If the BSSID PWR is -1, then the driver doesn't support signal level
        #   reporting. If the PWR is -1 for a limited number of stations then
        #   this is for a packet which came from the AP to the client but the
        #   client transmissions are out of range for your card.
        #
        # Note: as the signal gets higher you get closer to the AP or the
        # station, but it's a negative number so we need to invert the value.
        #
        if signal != "-1":
            self.signal = 100 - abs(int(signal))
        else:
            self.signal = 0

        self.clients = []
        self._location = None

    def __str__(self):
        return "<%s | %s[%s] | %s%%>" % (self.mac, self.name, self.security,
            self.signal)

    def __repr__(self):
        return str(self)

    @property
    def location(self):
        return self._location["location"] if self._location else None

    @property
    def accuracy(self):
        return self._location["accuracy"] if self._location else None

    def get_location(self, fallback=False, verbosity=0):
        """ Retrieves the location of this WiFi network based on the BSSID.

        :fallback[=False]   specifies whether or not to use the IP address of
                            the outbound request as a fallback for geolocation
                            lookup, in case the WiFi address doesn't exist
        :verbosity[=0]      specifies the detail of the output level

        :returns            a dictionary with keys ["location", "accuracy"]
        """
        def write(v, *args):
            if verbosity < v: return
            print ' '.join([str(x) for x in args])

        args = json.dumps({
            "considerIp": "false" if not fallback else "true",
            "wifiAccessPoints": [{ "macAddress": self.mac.lower()
        }]})

        # import pdb; pdb.set_trace()

        write(3, "Request URL:", API_URL)
        write(3, "  Params:", args)

        response = requests.post(API_URL, data=args,
            headers={"Content-Type": "application/json"})

        write(1, "For network:", self.mac)

        result = {
            "location": None,
            "accuracy": None
        }

        if response.status_code == 404:
            write(2, "  No location found from Google API.")

            url = BKP_URL % self.mac.upper()
            write(2, "  Trying backup API.")
            write(3, "    Request URL:", url)

            response = requests.get(url)
            j = response.json()
            write(3, "   ", j)

            if j["result"] == 200:
                result["location"] = {
                    "lat": j["data"]["lat"],
                    "lng": j["data"]["lon"]
                }
                result["accuracy"] = j["data"]["range"]

        else:
            j = response.json()
            write(3, " ", j)
            result = dict([ pair for pair in j.items() if pair[0] in result ])

        if result["location"] is None:
            write(1, "  No location found.")
        else:
            write(1, "  Location: (%f, %f)" % tuple(result["location"].values()))
            write(1, "  Accuracy: %0.2fm" % (result["accuracy"]))

        return result


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
    #   - Power:    the signal strength of the AP (negative number)
    #
    idxs = [columns.index(s) for s in ["BSSID", "ESSID", "Privacy", "Power"]]

    for row in reader:
        if not row: break   # network section has ended

        fields = [row[idx] for idx in idxs]
        nw = Network(*fields)
        if nw.name not in IGNORE_SSIDS:
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


def filter_open_networks(network_list):
    """ Finds all of the networks with no security.
    """
    return filter(lambda x: x.security == "OPN", network_list)

def filter_signal_threshold(network_list, min_sig, max_sig):
    """ Filters all networks outside of a certain signal strength.
    """
    return filter(lambda x: x.signal >= min_sig and x.signal <= max_sig, network_list)

def filter_duplicate_names(network_list, max_dupes=1):
    filtered = collections.defaultdict(list)
    for nw in network_list:
        results = filtered[nw.name]

        # We always add up to the maximum.
        if len(results) < max_dupes:
            results.append(nw)

        # Otherwise, only add if it's a better network, replacing last.
        elif nw.signal > max([n.signal for n in filtered[nw.name]]):
            results[-1] = nw

        filtered[nw.name] = sorted(results, key=lambda x: x.signal, reverse=True)

    return sum(filtered.values(), [])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=
        "Extracts all open networks from an airodump-ng capture file.")
    parser.add_argument("-f", "--filename", metavar="FNAME", help="capture to extract from")
    parser.add_argument("--address", metavar="BSSID", help="MAC address of AP to lookup")
    parser.add_argument("--exclude", dest="exclude", default=[],
        metavar="ESSID(s)", nargs="+", help="network names to exclude, if found")
    parser.add_argument("-c", "--clients", action="store_true",
        help="include any clients that were found")
    parser.add_argument("--open", action="store_true",
        help="only return open network results")
    parser.add_argument("-l", "--location", dest="loc", action="store_true",
        help="include the location information for each network")
    parser.add_argument("--fallback", action="store_true",
        help="when combined with -l, specifies that geoip should also be used")
    parser.add_argument("-v", dest="v", default=0,
        action="count", help="configures level of output")

    args = parser.parse_args()

    if args.address:
        # 04:DA:D2:1E:B2:02
        loc = Network(args.address, "", "", 0).get_location(
            fallback=args.fallback,
            verbosity=args.v)

        sys.exit(os.EX_DATAERR if loc["location"] is None else 0)

    elif args.filename:
        fname = args.filename
        fname = os.path.expanduser(fname)

        if not os.path.exists(fname):
            print "The file '%s' does not exist." % args.filename
            sys.exit(os.EX_OSFILE)

        if os.path.splitext(fname)[1].lower() != ".csv":
            print "The file isn't in CSV format."
            sys.exit(os.EX_NOINPUT)

        with open(fname, "r") as f:
            nw, cli = parse_csv(f, args.v)
            if args.open:
                nw = get_open_networks(nw)

            for n in nw:
                if n.name in args.exclude:
                    continue

                print "%s | %s[%s]" % (n.mac, n.name, n.security)
                if args.loc:
                    location = n.get_location(fallback=args.fallback, verbosity=args.v)
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
