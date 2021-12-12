# ethical-BD_ADDR-scan

This code was made for CS 8803 EMS (at Georgia Tech)

To run this code, clone the repo and run $ python3 scanScrip.py
(Note: This code requires sudo access to use your device for bluetooth scanning.
Also, this code was only tested on Ubuntu 20.04)

Python dependencies: os, time, sys, bluetooth, uuid, hashlib, collections, requests

This code will scan for bluetooth connections in your area. General, anonymized
information will be written to file named "overall_scan_results.txt". This file
will hold:
unique_devices count,
scan_duration,
number of devices vulnerable to each exploit,
number of devices seen from each manufacturer (if above anonymization threshold),
and a list of seen_device_hashes

The other produced file is named "vulnerability_by_manufacturer.txt". This file
contains dictionaries for the number of devices we found from a manfacturer that
is vulnerable to a specific exploit.
Example: in the braktooth section, we may have something like this -->
"Apple Inc." : 13,
"Google Inc." : 27
This means that 13 Apple devices scanned are vulnerable to braktooth, and 27
Google devices scanned are vulnerable to braktooth
