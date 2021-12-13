import os
import time
import sys
import bluetooth # we will use a better library in actual run

import uuid
import hashlib
from collections import Counter
import requests

start = time.time()
end = time.time()

# this is an up-to-date api that translates BD_ADDR prefixes to manufacturer names
web_api = 'https://macaddresschanger.com/bluetooth-mac-lookup/'
threshold = 10
packet_size = 600

def get_peppered_sha256_hash(pepper, lower_bits):
    return hashlib.sha256(pepper.encode() + lower_bits.encode()).hexdigest()

def remove_colons(bits):
    return ''.join(bits.split(':'))

def bits_to_manufacturer(upper_bits):
    # this calls a public, updated API
    req = f'{web_api}{upper_bits}'
    resp = requests.get(req).text

    search_string = f"{upper_bits}</td><td>"
    try:
        lower_index = resp.index(search_string) + len(search_string)
        upper_index = lower_index + resp[lower_index:].index('<')

    except ValueError:
        # Could not identify manufacturer
        return 'No manufacturer found'
        # the above will cause the if-statements to be false

    return resp[lower_index:upper_index]

def remove_low_counters(counter, to_remove):
    new_counter = Counter()

    for k,v in counter.items():
        if k in to_remove:
            continue
        else:
            new_counter[k] = v

    return new_counter

def get_remove_list(counter):
    manufacturers_to_remove = set()

    for k,v in counter.items():
        if v < threshold:
            manufacturers_to_remove.add(k)

    return manufacturers_to_remove

def scan_bluetooth():
    start = time.time()
    pepper = uuid.uuid4().hex


    seen_devices = set()
    vulnerability_counters = Counter()  # maps vulnerability to num_devices vulnerable
                                        # example --> "braktooth": 23

    manufacturer_counters = Counter()   # maps manufacturer to num_devices seen
                                        # example --> "Apple Inc.": 37

    found_manufacturers_vulnerable_to_tracking = Counter()
    # maps manufacturer name to number of devices vulnerable to tracking
    # example --> "Apple Inc.": 12
    # the other 3 are defined the same way for their respective vulnerabilities

    found_manufacturers_vulnerable_to_bluesmack = Counter()
    found_manufacturers_vulnerable_to_braktooth = Counter()
    #found_manufacturers_vulnerable_to_blueborne = Counter()


    # Below manufacturer names were added from public repos
    # These are the names of bluetooth chip manufacturers with known vulnerabilities
        # to braktooth
    known_manufacturers_vulnerable_to_braktooth = set(['Texas Instruments', 'Qualcomm Inc.'] +
        ['Intel Corporation', 'Intel Corporate', 'Intel Wireless Network Group'] +
        ['Samsung', 'Samsung Electronics Co.,Ltd', 'SAMSUNG ELECTRO MECHANICS CO., LTD.'] +
        ['SAMSUNG TECHWIN CO.,LTD', 'SAMSUNG HEAVY INDUSTRIES CO., LTD.', 'Samsung Thales'] +
        ['SAMSUNG ELECTRO-MECHANICS(THAILAND)', 'Samsung Electronics Co., Ltd. ARTIK'] +
        ['Airoha Technology Corp.,', 'Mediatek Corp.', 'MediaTek Inc.'])

    #known_manufacturers_vulnerable_to_blueborne = set()  # add manufacturer names here if we decide to do it this way
    try:
        while True:
            print("Scanning for bluetooth devices: ")
            devices = bluetooth.discover_devices(lookup_names = False, lookup_class = False)
            # above flushes cache by default

            number_of_devices = len(devices)
            print(number_of_devices, "devices found")
            for addr in devices:

                upper_bits = addr[:8]
                lower_bits = addr[9:]
                sha256_hash = get_peppered_sha256_hash(pepper, lower_bits)
                device_manufacturer = ""

                if sha256_hash not in seen_devices:
                    # device has yet to be seen in current scan
                    device_manufacturer = bits_to_manufacturer(upper_bits)
                    manufacturer_counters[device_manufacturer] += 1

                    seen_devices.add(sha256_hash)
                    # all seen devices are vulnerable to tracking
                    vulnerability_counters['tracking'] += 1
                    found_manufacturers_vulnerable_to_tracking[device_manufacturer] += 1
                else:
                    # device was already seen
                    del(upper_bits)
                    del(lower_bits)
                    continue

                returned_value = os.system('sudo l2ping -i hci0 -c 1 -s ' + str(packet_size) + " " + addr)

                if returned_value != 256:
                    # device echoed back a 600B packet
                    # --> is susceptible to bluesmacking
                    vulnerability_counters['bluesmack'] += 1
                    found_manufacturers_vulnerable_to_bluesmack[device_manufacturer] += 1

                # This is an extra, unnecessary step since no researcher will
                # see the terminal that this script was run on
                os.system("clear && clear")
                print("Terminal cleared")


                if device_manufacturer in known_manufacturers_vulnerable_to_braktooth:
                    vulnerability_counters['braktooth'] += 1
                    found_manufacturers_vulnerable_to_braktooth[device_manufacturer] += 1

                #if device_manufacturer in known_manufacturers_vulnerable_to_blueborne:
                #    vulnerability_counters['blueborne'] += 1
                #    found_manufacturers_vulnerable_to_blueborne[device_manufacturer] += 1

                del(upper_bits)
                del(lower_bits)
                del(device_manufacturer)

            del(devices)
            time.sleep(0.1)
    except KeyboardInterrupt:
        end = time.time()
        del(pepper)

        manufacturers_to_remove = get_remove_list(manufacturer_counters)

        manufacturer_counters = remove_low_counters(manufacturer_counters, manufacturers_to_remove)
        found_manufacturers_vulnerable_to_tracking = remove_low_counters(found_manufacturers_vulnerable_to_tracking, manufacturers_to_remove)
        found_manufacturers_vulnerable_to_bluesmack = remove_low_counters(found_manufacturers_vulnerable_to_bluesmack, manufacturers_to_remove)
        found_manufacturers_vulnerable_to_braktooth = remove_low_counters(found_manufacturers_vulnerable_to_braktooth, manufacturers_to_remove)
        #found_manufacturers_vulnerable_to_blueborne = remove_low_counters(found_manufacturers_vulnerable_to_blueborne, manufacturers_to_remove)


        # written to encrypted file
        f = open("overall_scan_results.txt", "w")
        f.write(f"unique_devices: {len(seen_devices)}\n")
        f.write(f"scan_duration: {(end - start)/60}\n") # time in minutes

        f.write("\nVulnerability counts\n")
        for vulnerability,num_devices in vulnerability_counters.items():
            # f.write(f"We found {num_devices} devices were vulnerable to {vulnerability}\n")
            f.write(f"{vulnerability}: {num_devices}\n")

        f.write("\nManufacturer counts\n")
        for manufacturer,num_devices in manufacturer_counters.items():
            # f.write(f"We found {num_devices} devices were manufactured by {manufacturer}\n")
            f.write(f"{manufacturer}: {num_devices}\n")

        f.write("\nseen_device_hashes:[\n")
        for i, h in enumerate(seen_devices):
            # f.write(f"We found {num_devices} devices were manufactured by {manufacturer}\n")
            if i < len(seen_devices) - 1:
                f.write(f"{h},\n")
            else:
                f.write(f"{h}\n]")
        f.close()

        # written to encrypted file
        f = open("vulnerability_by_manufacturer.txt", "w")
        f.write("Manufacturer counts vulnerable to tracking\n")
        for key,val in found_manufacturers_vulnerable_to_tracking.items():
            f.write(f"{key} : {val}\n")

        f.write("\nManufacturer counts vulnerable to bluesmack\n")
        for key,val in found_manufacturers_vulnerable_to_bluesmack.items():
            f.write(f"{key} : {val}\n")

        f.write("\nManufacturer counts vulnerable to braktooth\n")
        for key,val in found_manufacturers_vulnerable_to_braktooth.items():
            f.write(f"{key} : {val}\n")

#         f.write("\nManufacturer counts vulnerable to blueborne\n")
#         for key,val in found_manufacturers_vulnerable_to_blueborne.items():
#             f.write(f"{key} : {val}\n")
        f.close()

    return

if __name__ == '__main__':
    scan_bluetooth()
