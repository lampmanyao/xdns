#include "xdns.h"
#include "bopt/bopt.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PROGRAM "xdns"

extern int xdns_debug;

static void usage()
{
	printf("Usage: %s --server dns_server [--ipv6] --host host --type qtype [--debug] \n", PROGRAM);
	printf(" --server    the dns server to query\n");
	printf(" --ipv6      use IPv6 dns server, default is IPv4 dns server\n");
	printf(" --host      the name of the resource record that is to be looked up\n");
	printf(" --type      the resource record type to query\n");
	printf(" --debug     debug mode, print send data and receive data\n");
	printf(" --help      print this message\n");
	exit(-1);
}

static int type2qtype(const char *type, uint16_t *qtype)
{
	int ret = 0;
	if (strcmp(type, "A") == 0) {
		*qtype = XDNS_TYPE_A;
	} else if (strcmp(type, "AAAA") == 0) {
		*qtype = XDNS_TYPE_AAAA;
	} else if (strcmp(type, "MX") == 0) {
		*qtype = XDNS_TYPE_MX;
	} else if (strcmp(type, "HINFO") == 0) {
		*qtype = XDNS_TYPE_HINFO;
	} else if (strcmp(type, "CNAME") == 0) {
		*qtype = XDNS_TYPE_CNAME;
	} else {
		ret = -1;
	}

	return ret;
}

int main(int argc, char **argv)
{
	int c;
	char *server;
	char *host;
	char *type = NULL;
	int inet = XDNS_INET4;

	struct xdns_client xdns_client;
	uint16_t qtype = XDNS_TYPE_A;  /* default query type */

	struct boption opts[] = {
		{ "server", brequired_argument, 's', &server},
		{ "host",   brequired_argument, 'h', &host },
		{ "type",   boptional_argument, 't', &type },
		{ "debug",  bno_argument,       'd', NULL },
		{ "ipv6",   bno_argument,       'p', NULL},
		{ "help",   bno_argument,       'H', NULL },
		{ NULL, 0, 0, NULL }
	};

	while ((c = bgetopt(argc, argv, opts)) > 0) {
		switch (c) {
		case  's':
			server = boptarg;
			break;

		case 'h':
			host = boptarg;
			break;

		case 't':
			type = boptarg;
			break;

		case 'd':
			xdns_debug = 1;
			break;

		case 'p':
			inet = XDNS_INET6;
			break;

		case 'H':
			usage();
			break;

		case ':':
			printf("option `%s' missing argument\n", boptarg);
			usage();
			break;

		default:
			usage();
			break;
		}
	}

	if (type) {
		if (type2qtype(type, &qtype) != 0) {
			printf("type: %s is not support yet\n", type);
			exit(-1);
		}
	}

	if (xdns_client_init(&xdns_client, server, inet, host) < 0) {
		printf("xdns_client_init() error\n");
		exit(-1);
	}

	if (xdns_client_query(&xdns_client, qtype, XDNS_CLASS_IN) < 0) {
		printf("xdns_client_query() error\n");
	} else {
		xdns_client_print_answer(&xdns_client);
		xdns_client_print_authority(&xdns_client);
		xdns_client_print_additional(&xdns_client);
	}

	xdns_client_destroy(&xdns_client);

	return 0;
}

