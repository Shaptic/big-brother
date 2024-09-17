# Big Brother #
A proof-of-concept suite of scripts to track device locations via MAC
addresses, based on [this blog post](https://teapowered.dev/posts/mac-address-tracking).

This set of scripts is made up of two components, one of which is a tracker
module that monitors a particular location -- the intention is that there are
tens or hundreds of these distributed across a wide area -- and the other,
which is a centralized server that correlates information from the individual
trackers to monitor location.

### Trackers ###
Located in `tracker/`, the main module is `tracker.py`, which looks like so:

```bash

$ ./tracker.py -h
usage: tracker.py [-h] [-i SEC] [-n COUNT] [-v] [-q] IFACE|FILENAME

This script MUST be run as root (for interface monitor mode). This runs a
tracker node, intended to be connected to a surveillance master server.

positional arguments:
  IFACE|FILENAME        either an interface to scan, or a capture file to
                        process

optional arguments:
  -h, --help            show this help message and exit
  -i SEC, --interval SEC
                        specifies delay between vicinity scans
  -n COUNT, --count COUNT
                        specifies number of scan sequences to perform, 0 means
                        infinite
  -v                    output level (1-3)
  -q, --quiet           stop all output, overriding -v

$ sudo ./tracker.py wlp4s0 -n 1
Running network sniffer.........
Connecting to open network: HOMEGROWN WiFi 
  No clients on this network. 

Connecting to open network: Google Starbucks 
  BSSID: [redacted]
  Signal strength: 43% 
  Found clients: 
    [redacted]

Connecting to open network: HP-Print-EA-LaserJet 1102 
  No clients on this network. 
```
