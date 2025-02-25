#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>  // for ntohs function
#include <string.h> // for strdup function
#include <getopt.h>

// have a usage function that prints out the usage of the program
void usage(char *progname) {
    fprintf(stderr,
        "Usage:\n"
        "\t%1$s [--filter <filter_expression>] [path]\n"
        "Examples:\n"
        "\tParse all packets in a pcap file whose destination port is 53:\n"
        "\t    %1$s --filter \"dst port 53\" ../sample-pcap/memory_slow_but_long_shortest_2023-01-19_00-51-45_05-16-00-51.pcap\n"
        "\tabove example is equivalent to:\n"
        "\t    tcpdump -X -n \"dst port 53\" -r ../sample-pcap/memory_slow_but_long_shortest_2023-01-19_00-51-45_05-16-00-51.pcap -w - | %1$s -\n"
        "\tOne can also send self-crafted packets and get it parsed by the program:\n"
        "\t  In one terminal, run:\n"
        "\t    sudo tcpdump sudo tcpdump -i lo \"dst port 5300\" -Uw - | %1$s -\n"
        "\t  In another terminal, run:\n"
        "\t    (perl -e 'print \"\\x33\\x33\\x01\\x20\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07rsf.org\\x00\\x00\\x01\\x00\\x01\"'; cat) | ncat -x /dev/stderr --udp 127.0.0.1 5300\n"
        ,
        progname
    );    
}

// extract qclass and qtype from the UDP data
void extract_qclass_qtype(uint8_t* buf, uint8_t* qname, int* qname_len) {
    // blindly read in four more bytes
    fprintf(stdout, "blindly read in 4 more bytes as qclass and qtype: ");
    for (int i = 0; i < 4; i++) {
        qname[(*qname_len)++] = *buf;
        fprintf(stdout, "0x%02x ", *buf);
        buf++;
    }
    fprintf(stdout, "\n");
}

void extract_qname(uint8_t* buf, int udplen, uint8_t* qname, int* qname_len) {
    // skip the first 12 bytes of the UDP header
    buf += 12;

    *qname_len = 0; // initialize qname_len

    while (1) {
        // Reads in 1 byte as length label
        uint8_t length_label = *buf;
        // append length_label to qname_byte
        qname[(*qname_len)++] = length_label;
        buf++;
        fprintf(stdout, "read in 1-byte length label: %d (0x%02x)\n", length_label, length_label);
        

        if (length_label == 0) {
            fprintf(stdout, "stop reading because length_label == 0\n");
            extract_qclass_qtype(buf, qname, qname_len);
            return;
        }

        if (*qname_len >= udplen - 12) { // 12 bytes for DNS header
            fprintf(stdout, "stop reading because qname_len (%d) >= udplen (%d) -12\n", *qname_len, udplen);
            extract_qclass_qtype(buf, qname, qname_len);
            return;
        }

        fprintf(stdout, "read in label bytes: ");
        for (int i = 0; i < length_label; i++) {
            if (*qname_len > 125) {
                fprintf(stdout, "\nstop reading because qname_len (%d) > 125\n", *qname_len);
                extract_qclass_qtype(buf, qname, qname_len);
                return;
            }

            // read in 1 byte to qname
            uint8_t qname_byte = *buf;
            fprintf(stdout, "0x%02x ", qname_byte);
            qname[(*qname_len)++] = qname_byte;
            buf++;
        }
        fprintf(stdout, "\n");
    }
}

void extract_question(uint8_t* buf, int udplen, uint8_t* qname, int* qname_len) {
    extract_qname(buf, udplen, qname, qname_len);
    // we moved extract_qclass_qtype call to the end of extract_qname,
    // otherwise, the 4 bytes for qclass and qtype will be read are somehow always the same
    //extract_qclass_qtype(buf, qname, qname_len);
}

void process_packet(uint8_t* packet_data, int length) {
    int ETH_HEADER_LEN = 14;
    int IP_HEADER_LEN_MIN = 20; // This is for a minimal header. Options can make it longer.
    int UDP_HEADER_OFFSET_LEN = 4;  // Offset to get to the Length field in the UDP header

    // Pointer to the start of the UDP header
    uint8_t* udp_header = packet_data + ETH_HEADER_LEN + IP_HEADER_LEN_MIN;

    // Extracting udplen. We use ntohs to convert from network byte order to host byte order.
    uint16_t udplen = ntohs(*(uint16_t*)(udp_header + UDP_HEADER_OFFSET_LEN));

    // Now, you can continue with your processing.
    // For example, to get to the start of the UDP data:
    uint8_t* udp_data = udp_header + 8; // 8 bytes for the UDP header

    // Extract the qname
    uint8_t question[131];
    int question_len;
    extract_question(udp_data, udplen, question, &question_len);

    // print out the result as hex bytes
    printf("final question field (qname + qclass + qtype) is %d bytes: ", question_len);
    for (int i = 0; i < question_len; i++) {
        printf("%02x", question[i]);
    }
    printf("\n\n");
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filter_exp = NULL;
    char *path = NULL;
    pcap_t *handle;

    char *progname = argv[0];

    
    static struct option long_options[] = {
        {"filter", required_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "f:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'f':
                filter_exp = optarg;
                break;
            case 'h':
                usage(progname);
                return 0;
            default:
                fprintf(stderr, "Usage: %s [--filter <filter_expression>] [path]\n", argv[0]);
                return 1;
        }
    }

    if (optind < argc) {
        path = argv[optind];
    }

    if (!path || strcmp(path, "-") == 0) {
        handle = pcap_fopen_offline(stdin, errbuf);
    } else {
        handle = pcap_open_offline(path, errbuf);
    }

    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap: %s\n", errbuf);
        usage(progname);
        return 1;
    }

    struct pcap_pkthdr header;
    const uint8_t* packet;

    // Compile and apply the filter
    struct bpf_program fp;
    if (filter_exp) {
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return 1;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Could not apply filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return 1;
        }
    }

    // Read packets from the file and process them
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // the header.len is the length of the packet in bytes
        process_packet((uint8_t*)packet, header.len);
    }

    pcap_close(handle);
    return 0;
}
