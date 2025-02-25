/*
Usage:
	./blackbox
	./blackbox -patched
When run with no command-line arguments, runs the test cases for the pre-patched
version of the DNS parser. When run with -patched, runs the test cases for the
first incomplete patch.
*/

#include <ctype.h>
#include <regex.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TYPE_A = 1,
	TYPE_AAAA = 28,
};

#define TTL         "TTTT"
#define A_SUFFIX    "\xc0\x0c\x00\x01\x00\x01" TTL "\x00\x04" "4444"
#define AAAA_SUFFIX "\xc0\x0c\x00\x1c\x00\x01" TTL "\x00\x10" "6666666666666666"

// Print n bytes starting at s to stdout, hex-escaping non-friendly characters.
void print_escaped(const char *s, size_t n)
{
	printf("\"");
	for (size_t i = 0; i < n; i++) {
		if (isprint(s[i]) && !isspace(s[i]) && s[i] != '\\' && s[i] != '"')
			printf("%c", s[i]);
		else
			printf("\\x%02x", (unsigned char) s[i]);
	}
	printf("\"");
}

// Copy src[0..src_len] to dst[dst_len..dst_cap], discarding any overflow. Like
// a bounds-checked memcpy. Return the number of bytes copied.
size_t append(char *dst, size_t dst_len, size_t dst_cap, const char *src, size_t src_len)
{
	if (dst_len + src_len > dst_cap)
		src_len = dst_cap - dst_len;
	memcpy(dst + dst_len, src, src_len);
	return src_len;
}

// Return the value of the 16-bit big-endian unsigned integer at s.
uint16_t get_uint16(const char *s)
{
	return (((uint16_t) (unsigned char) s[0]) << 8) | ((uint16_t) (unsigned char) s[1]);
}

// Store u as a 16-bit big-endian unsigned integer at s.
void put_uint16(char *s, uint16_t u)
{
	s[0] = (unsigned char) (u >> 8);
	s[1] = (unsigned char) (u & 0xff);
}

// Return true if name matches blocklist, false otherwise. name is a
// null-terminated string.
bool name_is_censored(const char *name, const regex_t *blocklist)
{
	return regexec(blocklist, name, 0, NULL, 0) == 0;
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

// Decide whether the DNS message in query[0..query_len] is a DNS query that
// should be censored, according to blocklist. If so, store a DNS response in
// resp_buf and its length (up to a maximum of resp_buf_len bytes) in *resp_len.
// Also return the flattened dot-delimited null-terminated QNAME that is used
// for blocklist matching in caller_name_buf and *caller_name_len. Return true
// if the message should be censored, false otherwise.
bool response(
	const char *query, size_t query_len, const regex_t *blocklist,
	bool patched,
	char *resp_buf, size_t *resp_len, size_t resp_buf_len,
	char *caller_name_buf, size_t *caller_name_len, size_t caller_name_buf_len
)
{
	*resp_len = 0;
	*caller_name_len = 0;

	// Ensure we have at least ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
	// It is not certain whether this check uses query length or the UDP length.
	if (query_len < 12)
		return false;

	// Do nothing if the DNS message is not actually a query; i.e. if QR = 1.
	if ((query[2] & 0x80) != 0)
		return false;

	// Ignore QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
	// Assume there is exactly one question.

	// We will flatten QNAME from the query into a dot-delimited,
	// null-terminated string in name_buf. name_i is how many bytes have
	// been stored in name_buf so far.
	char name_buf[126];
	size_t name_i = 0;
	// This is the QNAME parsing loop. The variable query_i is the current
	// index into query. The variable qname_end is evidently intended to
	// track query_i and be equal to query_i at the end of the loop. This
	// equality holds in the usual cases, when the loop is terminated
	// because of a zero label length or because there are no more bytes in
	// query, but it fails to hold in the case that a label is too long to
	// fit into what is left of name_buf. The desync of query_i and
	// qname_end has only a minor effect: it changes what bytes are looked
	// at as the QTYPE below, when deciding whether to append a A or AAAA
	// resource record.
	size_t query_i = 12;
	size_t qname_end;
	for (;;) {
		// Bug: reads the next label length before checking whether
		// query_i is still in bounds; permits a 1-byte overread.
		size_t label_len = (unsigned char) query[query_i++];
		// Re-sync qname_end with query_i.
		qname_end = query_i;

		// Break the loop on an empty label.
		if (label_len == 0)
			break;
		// Break the loop if we have reached the end of the message.
		if (query_i > query_len)
			break;

		if (!patched) {
			// Break the loop if there is no room left in name_buf for a
			// dot, at least 1 byte of the next label, and a null
			// terminator.
			if (name_i + 1 + 1 + 1 > sizeof(name_buf))
				break;
		} else {
			// Advance query_i by only as much of the label as will fit in
			// name_buf, along with a preceding dot (even though there may
			// not be a preceding dot if this is the first label) and a null
			// terminator.
			// Bug: query_i may not remain in bounds.
			query_i += MIN(label_len, sizeof(name_buf) - 1 - name_i - 1);
			// Break the loop if there is no room left in name_buf for a
			// dot, the next label, and a null terminator.
			// Bug: qname_end is not equal to query_i in this case.
			if (name_i + 1 + label_len + 1 > sizeof(name_buf))
				break;
		}

		// Append a label separator dot, unless this is the first label.
		if (name_i > 0)
			name_buf[name_i++] = '.';
		// Append the label. Bug: there is no check that reading from
		// query stays in bounds. This missing bounds check is the
		// direct cause of Wallbleed.
		size_t n = append(name_buf, name_i, sizeof(name_buf) - 1, query + qname_end, label_len);

		// Advance name_i and query_i by the number of label bytes
		// copied into name_buf (which may be less than label_len, if
		// the label was too long to fit completely).
		name_i += n;
		if (!patched) {
			// Bug: query_i may not remain in bounds.
			query_i += n;
			// If the label *was* too long to fit completely, break the loop.
			// Bug: qname_end is not equal to query_i in this case.
			if (n < label_len)
				break;
		}
	}
	// Finally, null-terminate the flattened QNAME string.
	name_buf[name_i] = '\0';

	// Make a copy of the flattened QNAME string for the caller.
	if (caller_name_buf_len > 0) {
		*caller_name_len = append(caller_name_buf, 0, caller_name_buf_len - 1, name_buf, name_i + 1);
		caller_name_buf[*caller_name_len] = '\0';
	}

	// Bug: because the blocklist lookup uses a C string rather than
	// structured labels, dot characters within labels are effectively
	// treated as additional label separators, and a null byte within the
	// label prematurely terminates the string.
	if (!name_is_censored(name_buf, blocklist)) {
		// This is not a name that should not be censored.
		return false;
	}

	// This step uses qname_end to locate the end of QNAME. The copies below
	// instead use query_i, which may point to a higher address.
	uint16_t qtype  = get_uint16(query + qname_end + 0);
	uint16_t qclass = get_uint16(query + qname_end + 2);
	if (patched) {
		if (qclass != 0x0001)
			return false;
	}

	// Construct the response in resp_buf.
	// Copy everything from the query up to query_i (the index at which we
	// stopped parsing QNAME), plus 4 bytes for QTYPE and QCLASS.
	*resp_len += append(resp_buf, *resp_len, resp_buf_len, query, query_i + 4);
	// Convert the query into a response.
	// For the FLAGS, always set the QR bit (0x8000). If the RD bit (0x0100
	// "recursion desired") is unset in the query, set the AA bit (0x0400
	// "authoritative answer") in the response. If the RD bit is set in the
	// query, set the RD bit and the RA bit (0x0080 "recursion available")
	// in the response.
	if ((resp_buf[2] & 0x01) == 0) {
		resp_buf[2] = 0x84; resp_buf[3] = 0x00;
	} else {
		resp_buf[2] = 0x81; resp_buf[3] = 0x80;
	}
	put_uint16(resp_buf +  4, 1); // QDCOUNT = 1
	put_uint16(resp_buf +  6, 1); // ANCOUNT = 1
	put_uint16(resp_buf +  8, 0); // NSCOUNT = 0
	put_uint16(resp_buf + 10, 0); // ARCOUNT = 0

	// Append the answer section. Append an AAAA record if the QTYPE was
	// AAAA, or an A record for any other QTYPE.
	if (qtype == TYPE_AAAA)
		*resp_len += append(resp_buf, *resp_len, resp_buf_len, AAAA_SUFFIX, sizeof(AAAA_SUFFIX) - 1);
	else
		*resp_len += append(resp_buf, *resp_len, resp_buf_len, A_SUFFIX, sizeof(A_SUFFIX) - 1);

	return true;
}

// The regular expression that defines what DNS names (represented in the
// familiar dot-delimited format) should be blocked. This is only a small
// representative sample of the real injector's blocklist.
const char *BLOCKLIST_REGEX =
	// An impossible first pattern in the alternation, just to make
	// the following "|" lines more regular.
	"$.^"
	// 69.mu matches anywhere. (This was true when the test cases using
	// 69.mu were created, but at some later point 69.mu became
	// end-anchored.)
	"|" "69\\.mu"
	// facebook.com is end-anchored, subdomains also match.
	"|" "(^|\\.)facebook\\.com$"
	// rsf.org is end-anchored, subdomains also match.
	"|" "(^|\\.)rsf\\.org$"
	// 3.tt and 4.tt are end-anchored, subdomains also match.
	"|" "(^|\\.)3\\.tt$"
	"|" "(^|\\.)4\\.tt$"
	// google.com is end-anchored, subdomains also match.
	"|" "(^|\\.)google\\.com$"
	// shadowvpn.com is start-anchored.
	"|" "^shadowvpn\\.com"
	;

struct test_case {
	char *query;
	// query_len controls how many bytes are copied to working
	// memory. udp_len (which may be greater than query_len)
	// controls the size of the query for the purpose of parsing.
	size_t query_len;
	size_t udp_len;
	char *expected;
	// expected_len == 0 means no response is expected.
	size_t expected_len;
	// When we began experiments, the first 4 bytes of leaked memory
	// appeared different, not connecting logically to the bytes
	// that followed. We started calling these 4 bytes "digest"
	// bytes, and they are distinguished from other leaked bytes in
	// tests cases. At some point, "digest" bytes stopped appearing
	// in leaked memory. The uses_digest flag attached to each test
	// case defines whether the observation was made during the
	// with-digest or without-digest regime.
	bool uses_digest;
};

// The test cases are stored in separate files.
#define NELEMS(a) (sizeof(a) / sizeof(a[0]))
const struct test_case TESTS_UNPATCHED[] = {
#include "blackbox-tests.inc"
};
const size_t NUM_TESTS_UNPATCHED = NELEMS(TESTS_UNPATCHED);
const struct test_case TESTS_PATCHED[] = {
#include "blackbox-tests-patched.inc"
};
const size_t NUM_TESTS_PATCHED = NELEMS(TESTS_PATCHED);

int main(int argc, char *argv[])
{
	// Compile the blocklist regular expression.
	regex_t blocklist;
	int rc;
	rc = regcomp(&blocklist, BLOCKLIST_REGEX, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if (rc != 0) {
		char errbuf[512];
		regerror(rc, &blocklist, errbuf, sizeof(errbuf));
		fprintf(stderr, "Error compiling blocklist regular expression: %s\n", errbuf);
		exit(1);
	}

	// Parse command-line arguments.
	bool patched = 0;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-patched") == 0) {
			patched = true;
		} else {
			fprintf(stderr, "Unknown argument: %s\n", argv[i]);
			exit(1);
		}
	}

	const struct test_case *TESTS = TESTS_UNPATCHED;
	size_t NUM_TESTS = NUM_TESTS_UNPATCHED;
	if (patched) {
		TESTS = TESTS_PATCHED;
		NUM_TESTS = NUM_TESTS_PATCHED;
	}

	bool any_failed = false;
	for (unsigned int i = 0; i < NUM_TESTS; i++) {
		// Simulate copying the DNS query from the network interface
		// into memory.
		char query_buf[512];
		// Fill the buffer with 'X' to represent preexisting memory.
		memset(query_buf, 'X', sizeof(query_buf));
		// Zero the first 18 bytes of the buffer. The reason for this is
		// unknown, but the real injectors seem to do it. It only makes
		// a difference for very short queries (17 bytes or less, which
		// means a QNAME of 5 bytes or less).
		memset(query_buf, '\x00', 18);
		// Ensure there is plenty of room in the buffer after the actual
		// query, so that the buffer overreads in the response function
		// do not actually access uninitialized memory.
		if (TESTS[i].query_len + 256 > sizeof(query_buf))
			abort();
		// Copy the query into the beginning of the buffer.
		memcpy(query_buf, TESTS[i].query, TESTS[i].query_len);
		if (TESTS[i].uses_digest) {
			// If this test is meant to represent running under the
			// "digest" regime, copy 4 'D' bytes immediately after
			// the query. 'D' also represents leaked memory, but is
			// distinct from 'X'.
			if (TESTS[i].query_len + 4 > sizeof(query_buf))
				abort();
			memset(query_buf + TESTS[i].query_len, 'D', 4);
		}

		// Initialize the contents of the resp_buf array. Unlike the 'X'
		// bytes in query_buf, it should never be possible for these 'A'
		// bytes to be output.
		char resp_buf[512];
		size_t resp_len;
		memset(resp_buf, 'A', sizeof(resp_buf));
		// The response function stores the flattened QNAME string in
		// name_buf, so we may display it.
		char name_buf[128];
		size_t name_len;

		bool is_censored = response(
			query_buf, TESTS[i].udp_len, &blocklist,
			patched,
			resp_buf, &resp_len, sizeof(resp_buf),
			name_buf, &name_len, sizeof(name_buf)
		);

		if (i > 0)
			printf("\n");
		printf("== %u\n", i);
		printf("   query ");
		print_escaped(query_buf, TESTS[i].udp_len);
		printf("\n");
		printf("   QNAME ");
		print_escaped(name_buf, strlen(name_buf));
		printf("\n");
		printf("expected ");
		print_escaped(TESTS[i].expected, TESTS[i].expected_len);
		printf("\n");
		if (is_censored == (TESTS[i].expected_len > 0) && memcmp(resp_buf, TESTS[i].expected, resp_len) == 0) {
			printf("== %u ok\n", i);
		} else {
			any_failed = true;
			printf("     got ");
			print_escaped(resp_buf, resp_len);
			printf("\n");
			printf("== %u FAILED\n", i);
		}
	}

	// Free the blocklist regular expression.
	regfree(&blocklist);

	return any_failed ? 1 : 0;
}
