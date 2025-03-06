sSHELL := /bin/bash
PYTHON = python3

ROOT_DIR=../..

# The output files are determined by replacing the extension .pcap with .csv
# from all source files.

ALL = \
		ordered-ip-pool-injector-3.txt\

ordered-ip-pool-injector-3.txt: recover.py pcap/side-channel-sport-53-exp-11-*.csv
	grep -e ,20002, -e ,20003, pcap/side-channel-sport-53-exp-11-*.csv | cut -d, -f4 | head -n1000000 | ./recover.py --initial 208.77.47.172 > "$@"

test: test.py recover.py
	(for i in {1..10}; do $(PYTHON) test.py; done) | $(PYTHON) recover.py --initial 0 | sort -n -c && echo "OK" || echo "FAIL"
