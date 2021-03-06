#include "xdns.h"
#include "bopt/bopt.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PROGRAM "xdns"

extern int xdns_debug;

static void usage()
{
	printf("Usage: %s --server dns_server [--ipv6] --host host --type qtype [--timeout seconds] [--debug]\n", PROGRAM);
	printf(" --server    the dns server to query\n");
	printf(" --ipv6      use IPv6 dns server, default is IPv4 dns server\n");
	printf(" --host      the name of the resource record that is to be looked up\n");
	printf(" --type      the resource record type to query\n");
	printf(" --timeout   set the request timeout\n");
	printf(" --debug     debug mode, print send data and receive data\n");
	printf(" --help      print this message\n");
	exit(-1);
}


int main(int argc, char **argv)
{
	int c;
	char *server;
	char *host;
	char *type = NULL;
	char *timeout = NULL;
	int inet = XDNS_INET4;
	int default_timeout = 3;

	int ret;
	struct xdns_client xdns_client;
	struct xdns_request request;
	struct xdns_response response;

	uint16_t qtype = XDNS_TYPE_A;  /* default query type */

	struct boption opts[] = {
		{ "server", brequired_argument, 's', &server},
		{ "host",   brequired_argument, 'h', &host },
		{ "type",   boptional_argument, 't', &type },
		{ "timeout", boptional_argument, 'T', &timeout },
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

		case 'T':
			timeout = boptarg;
			default_timeout = atoi(timeout);
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
		if ((qtype = xdns_type2qtype(type)) == 0) {
			printf("type: %s is not support yet\n", type);
			exit(-1);
		}
	}

	if (( ret = xdns_client_open(&xdns_client, server, inet, default_timeout)) < 0) {
		printf("xdns_client_open() error\n");
		exit(-1);
	}

	xdns_client_set_request(&request, host, qtype, XDNS_CLASS_IN);

	if ((ret = xdns_client_send(&xdns_client, &request)) < 0) {
		goto out;
	}

	if ((xdns_client_recv(&xdns_client, &response)) < 0) {
		goto out;
	}

	xdns_response_print_answer(&response);
	xdns_response_print_authority(&response);
	xdns_response_print_additional(&response);

out:
	xdns_client_close(&xdns_client);
	if (ret == 0) {
		xdns_response_destroy(&response);
	}

	return 0;
}

