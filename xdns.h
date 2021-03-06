#ifndef xdns_h
#define xdns_h

#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h> 

#define BUFF_SIZE 65536
#define HOST_SIZE 512

#define XDNS_INET4 AF_INET
#define XDNS_INET6 AF_INET6

/*
 * QR
 */
#define XDNS_QR_QEURY    0
#define XDNS_QR_RESPONSE 1

/*
 * OPCODE
 */
#define XDNS_OPCODE_STD_QUERY 0
#define XDNS_OPCODE_IVS_QUERY 1
#define XDNS_OPCODE_STS_QUERY 2

/*
 * RCODE
 */
#define XDNS_RCODE_OK          0
#define XDNS_RCODE_FORMAT_ERR  1
#define XDNS_RCODE_SERVER_FAIL 2
#define XDNS_RCODE_NAME_ERR    3
#define XDNS_RCODE_NOT_IMPL    4
#define XDNS_RCODE_REFUSED_ERR 5

/*
 * Type values
 */
#define XDNS_TYPE_A      1   /* a host address */
#define XDNS_TYPE_NS     2   /* an authoritative name server */
#define XDNS_TYPE_MD     3   /* a mail destination (Obsolete - use MX) */
#define XDNS_TYPE_MF     4   /* a mail forwarder (Obsolete - use MX) */
#define XDNS_TYPE_CNAME  5   /* the canonical name for an alias */
#define XDNS_TYPE_SOA    6   /* marks the start of a zone of authority */
#define XDNS_TYPE_MB     7   /* a mailbox domain name (EXPERIMENTAL) */
#define XDNS_TYPE_MG     8   /* a mail group member (EXPERIMENTAL) */
#define XDNS_TYPE_MR     9   /* a mail rename domain name (EXPERIMENTAL) */
#define XDNS_TYPE_NULL   10  /* a null RR (EXPERIMENTAL) */
#define XDNS_TYPE_WKS    11  /* a well known service description */
#define XDNS_TYPE_PTR    12  /* a domain name pointer */
#define XDNS_TYPE_HINFO  13  /* host information */
#define XDNS_TYPE_MINFO  14  /* mailbox or mail list information */
#define XDNS_TYPE_MX     15  /* mail exchange */
#define XDNS_TYPE_TXT    16  /* text strings */
#define XDNS_TYPE_AAAA   28  /* IPv6 address */

/*
 * QType values
 */
#define XDNS_QTYPE_AXFR   252  /* A request for a transfer of an entire zone */
#define XDNS_QTYPE_MAILB  253  /* A request for mailbox-related records (MB, MG or MR) */
#define XDNS_QTYPE_MAILA  254  /* A request for mail agent RRs (Obsolete - see MX) */
#define XDNS_QTYPE_ALL    255  /* A request for all records */

/*
 * Class type values
 */
#define XDNS_CLASS_IN 1  /* The Internet */
#define XDNS_CLASS_CS 2  /* The CSNET class */
#define XDNS_CLASS_CH 3  /* The CHAOS class */
#define XDNS_CLASS_HS 4  /* Hesiod */


/*
 * dns header
 */
struct xdns_header {
	uint16_t id;  /* identifier */

	uint8_t rd: 1;  /* Recursion Desired */
	uint8_t tc: 1;  /* Truncation */
	uint8_t aa: 1;  /* Authoritative Answer */
	uint8_t opcode: 4;
	uint8_t qr: 1;  /* query (0) or response (1) */

	uint8_t rcode: 4;  /* Response code */
	uint8_t zero: 3;   /* Reserved for future use. Must be zero in all queries and response */
	uint8_t ra: 1;     /* Recursion Available */

	uint16_t qd_count;  /* the number of entries in the question section */
	uint16_t an_count;  /* the number of resource records in the answer section */
	uint16_t ns_count;  /* the number of name server resource records in the authority records section */
	uint16_t ar_count;  /* the number of resource records in the additional records section */
};

/*
 * dns question 
 */
struct xdns_question {
	uint16_t qtype;
	uint16_t qclass;
};


#pragma pack(push, 1)
struct xresource {
	uint16_t type;       /* This field specifies the meaning of the data in the RDATA field */
	uint16_t class;      /* which specify the class of the data in the RDATA field */
	uint32_t ttl;        /*  the time interval that the resource record may be cached 
			         before the source of the information should again be consulted */
	uint16_t rdata_len;  /* specifies the length in octets of the RDATA field */
};
#pragma pack(pop)

/* SOA rdata format */
struct soa_resource {
	uint32_t serial;
	int32_t refresh;
	int32_t retry;
	int32_t expire;
	uint32_t minimum;
};

struct soa {
	unsigned char *mname;
	unsigned char *rname;
	struct soa_resource *resource;
};

struct mx {
	int16_t preference;
	unsigned char *exchange;
};

struct txt {
	uint8_t txt_len;
	unsigned char *txt;
};

struct xrecord {
	unsigned char *name;
	struct xresource *resource;
	union {
		unsigned char *address;  /* A or AAAA rdata */
		unsigned char *rname;    /* NS or cname rdata */
		struct soa soa_data;     /* SOA rdata */
		struct mx mx_data;       /* MX rdata */
		struct txt txt_data;     /* TXT rdata */
	} rdata;
};

struct xdns_request {
	struct xdns_header header;
	struct xdns_question question;
	unsigned char qname[HOST_SIZE];
};

struct xdns_response {
	struct xdns_header header;

	int qname_len;
	unsigned char qname[HOST_SIZE];
	struct xdns_question question;

	int an_count;
	struct xrecord **answer_section;

	int ns_count;
	struct xrecord **authority_section;

	int ar_count;
	struct xrecord **additional_section;
};

struct xdns_client {
	int fd;
	int inet; /* AF_INET or AF_INET6 */
	union {
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} srv_addr;
	char dns_server[HOST_SIZE];
};

int xdns_client_open(struct xdns_client *client, const char *dns_server, int inet, int timeout);
void xdns_client_close(struct xdns_client *client);
uint16_t xdns_type2qtype(const char *type);
void xdns_client_set_request(struct xdns_request *request, const char *host, uint16_t qtype, uint16_t qclass);
int xdns_client_send(struct xdns_client *client, struct xdns_request *request);
int xdns_client_recv(struct xdns_client *client, struct xdns_response *response);
void xdns_response_destroy(struct xdns_response *response);
void xdns_response_print_answer(struct xdns_response *response);
void xdns_response_print_authority(struct xdns_response *response);
void xdns_response_print_additional(struct xdns_response *response);

#endif  /* xdns_h */

