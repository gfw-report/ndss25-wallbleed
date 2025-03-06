#!/usr/bin/env python3

import ipaddress
import sys
import getopt
import glob
import re
import csv
import os

import dpkt

# use path to file relative to the script
script_dir = os.path.dirname(os.path.abspath(__file__))
v4_ip_pool_filename = os.path.join(script_dir, 'ordered-ip-pool-injector-3-a.txt')
v6_ip_pool_filename = os.path.join(script_dir, 'ordered-ip-pool-injector-3-aaaa.txt')

def usage(f=sys.stderr):
    program = sys.argv[0]
    f.write(f"""\
Usage: {program} [FILENAME...]
This script reads UDP payloads from files. If a packet is a GFW injected answer, write the UDP payload and answer in CSV. With no FILE, or when FILE is -, read standard input. By default, print results to stdout and log to stderr.

  -h, --help            show this help
  -o, --out             write to file
  -b, --binary          read input as binary (default: False)
  -4, --pool-v4         file path to a pool of forged type A IPs by Injector 3 (default: {v4_ip_pool_filename})
  -6, --pool-v6         file path to a pool of forged type AAAA IPs by Injector 3 (default: {v6_ip_pool_filename})
  -d, --header          write header to output file (default: False)
  -f, --format          input format (default: pcap)
  -t, --fields          output fields (default: src_ip,payload,answer_ip,payload_len) (options: timestamp,src_ip,dst_port,payload,answer_ip,payload_len)

Example:
  {program} --format hex < input.txt > output.csv

  {program} --format pcap --fields src_ip,dst_port,payload,answer_ip,payload_len input.pcap > output.csv
""")

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def input_files(args, binary=False):
    STDIN =  sys.stdin.buffer if binary else sys.stdin
    MODE = 'rb' if binary else 'r'
    if not args:
        yield STDIN
    else:
        for arg in args:
            if arg == "-":
                yield STDIN
            else:
                for path in glob.glob(arg):
                    with open(path, MODE) as f:
                        yield f

def extract_udp_payloads_from_pcap(pcap_file):
    pcap_reader = dpkt.pcap.Reader(pcap_file)
    try:
        for timestamp, buf in pcap_reader:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                # convert binary bytes to IPv4 address
                src_ip = ipaddress.IPv4Address('.'.join(str(x) for x in ip.src))
                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    #eprint(f"Timestamp: {timestamp}, UDP Payload: {udp.data}")
                    # intialize a dictionary to store the extracted fields
                    packet_info = {
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "dst_port": udp.dport,
                        "payload": udp.data,
                    }
                    yield packet_info
    except dpkt.dpkt.NeedData as e:
        print(f"Error parsing pcap: {pcap_file}: {e}")


    

# Precompiled regular expressions for the known forms of injected
# A and AAAA resource records. The `....` stands for a variable TTL.
A_RR    = re.compile(rb"\xc0\x0c\x00\x01\x00\x01....\x00\x04(.{4})\Z", flags=re.DOTALL)
AAAA_RR = re.compile(rb"\xc0\x0c\x00\x1c\x00\x01....\x00\x10(.{16})\Z", flags=re.DOTALL)

# If payload ends in an resource record that matches the signs of being a forged
# response, return the IP address contained in the resource record. Otherwise
# return None. in_v4_pool and in_v6_pool are predicate functions that decide
# whether an extracted IP address belongs to a pool we're looking for, for A and
# AAAA responses respectively.
def forged_response_address(payload, in_v4_pool, in_v6_pool):
    a_match = A_RR.search(payload)
    if a_match:
        addr_bytes = a_match.group(1)
        # convert binary bytes to IPv4 address
        addr = ipaddress.IPv4Address('.'.join(str(x) for x in addr_bytes))
        if in_v4_pool(addr):
            return addr
        else:
            eprint(f"A match but not in the pool,{payload},{addr}")
            return None

    aaaa_match = AAAA_RR.search(payload)
    if aaaa_match:
        addr_bytes = aaaa_match.group(1)
        # convert binary bytes to IPv6 address
        addr = ipaddress.IPv6Address(':'.join(f'{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}' for i in range(0, len(addr_bytes), 2)))
        if in_v6_pool(addr):
            return addr
        else:
            eprint(f"AAAA match but not in the pool,{payload},{addr}")
            return None

def packet_info_to_csv_row(packet_info, output_fields):
    row = []
    for field in output_fields:
        if field == "payload":
            value = packet_info["payload"].hex()
        elif field == "payload_len":
            value = str(len(packet_info["payload"]))
        else:
            value = str(packet_info[field])
        row.append(value)
    return row

# Parse a set of IP addresses, one per line. Return the result as a set of
# ipaddress._BaseAddress.
def parse_ip_address_set(f):
    pool = set()
    for line in f:
        addr = ipaddress.ip_address(line.strip())
        if addr in pool:
            eprint(f"warning: duplicate address {addr}")
        pool.add(addr)
    return pool

if __name__ == '__main__':
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "ho:b4:6:df:t:", ["help", "out=", "binary", "pool-v4=", "pool-v6=","header", "format=", "fields="])
    except getopt.GetoptError as err:
        eprint(err)
        usage()
        sys.exit(2)

    output_file = sys.stdout
    binary_input = False

    header = False
    input_format = 'pcap'
    fields = "src_ip,payload,answer_ip,payload_len"
    for o, a in opts:
        if o == "-h" or o == "--help":
            usage()
            sys.exit(0)
        if o == "-o" or o == "--out":
            output_file = open(a, 'a+')
        if o == "-b" or o == "--binary":
            binary_input = True
        if o == "-4" or o == "--pool-v4":
            ip_pool_file_v4 = a
        if o == "-6" or o == "--pool-v6":
            ip_pool_file_v6 = a
        if o == "-d" or o == "--header":
            header = True
        if o == "-f" or o == "--format":
            input_format = a
        if o == "-t" or o == "--fields":
            fields = a

    with open(v4_ip_pool_filename) as f:
        v4_ip_pool = parse_ip_address_set(f)

    with open(v6_ip_pool_filename) as f:
        v6_ip_pool = parse_ip_address_set(f)

    # The forged_response_address will use these two predicate functions to
    # decide whether an extracted IP address belongs to a pool of interest.
    def in_v4_pool(addr):
        return addr in v4_ip_pool
    def in_v6_pool(addr):
        return addr in v6_ip_pool

    output_fields = fields.split(',')

    # create a CSV writer whose output fileds depends on the parameters
    # passed to the script.
    csv_writer = csv.writer(output_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    if header:
        if input_format == "pcap":
            csv_writer.writerow(output_fields)
        elif input_format == "hex":
            csv_writer.writerow(["payload", "answer", "payload_len"])
        else:
            eprint(f"Invalid input format: {input_format}")
            usage()
            sys.exit(2)


    if input_format == "pcap":
        for f in input_files(args, binary=True):
            for packet_info in extract_udp_payloads_from_pcap(f):
                answer_ip = forged_response_address(packet_info["payload"], in_v4_pool, in_v6_pool)
                packet_info["answer_ip"] = answer_ip
                if answer_ip is not None:
                    csv_writer.writerow(packet_info_to_csv_row(packet_info, output_fields))

    elif input_format == "hex":
        for f in input_files(args, binary=False):
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = bytes.fromhex(line)
                except ValueError:
                    eprint(f"Invalid payload: {line}")
                    continue
                answer_ip = forged_response_address(payload, in_v4_pool, in_v6_pool)
                if answer_ip is not None:
                    csv.writerow([payload.hex(), str(answer_ip), str(len(payload))])
    else:
        eprint(f"Invalid input format: {input_format}")
        usage()
        sys.exit(2)

    output_file.close()
