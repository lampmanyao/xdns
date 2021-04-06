#include "xdns.h"

#include <stdio.h>
#include <stdlib.h>  /* malloc() */
#include <unistd.h>  /* getpid() */
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#define PORT 53

int xdns_debug = 0;

static void set_qname(unsigned char *qname, unsigned char *host);
static void set_dns_header(struct xdns_header *dns_header);
static void set_dns_question(struct xdns_question *dns_question, uint16_t qtype, uint16_t qclass);
static void print_dns_header(struct xdns_header *dns_header);
static void print_dns_question(struct xdns_question *question);
static unsigned char *parse_name(unsigned char *record_pos, unsigned char *buffer, int *count);
static int parse_qname(unsigned char *qname, unsigned char *buffer);
static void section_free(struct xrecord **record, int count);
static void print_hex(unsigned char *buff, size_t len);
static void parse_response(struct xdns_response *response, unsigned char **record_pos, unsigned char *buffer);


int xdns_client_open(struct xdns_client *client, const char *dns_server, int inet)
{

	strncpy(client->dns_server, dns_server, HOST_SIZE - 1);
	client->dns_server[HOST_SIZE - 1] = '\0';

	client->inet = inet;

	if (inet == XDNS_INET6) {
		client->fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (client->fd < 0) {
			return -1;
		}
		memset(&client->srv_addr.addr6, 0, sizeof(struct sockaddr_in6));
		client->srv_addr.addr6.sin6_family = AF_INET6;
		client->srv_addr.addr6.sin6_port = htons(53);

		if (inet_pton(AF_INET6, dns_server, &client->srv_addr.addr6.sin6_addr) < 0) {
			return -1;
		}
	} else if (inet == XDNS_INET4) {
		client->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (client->fd < 0) {
			return -1;
		}
		client->srv_addr.addr4.sin_family = AF_INET;
		client->srv_addr.addr4.sin_port = htons(53);
		client->srv_addr.addr4.sin_addr.s_addr = inet_addr(dns_server);
	}

	return 0;
}

void xdns_client_close(struct xdns_client *client)
{
	close(client->fd);
}

uint16_t xdns_type2qtype(const char *type)
{
	if (strcmp(type, "A") == 0) {
		return XDNS_TYPE_A;
	} else if (strcmp(type, "AAAA") == 0) {
		return XDNS_TYPE_AAAA;
	} else if (strcmp(type, "MX") == 0) {
		return XDNS_TYPE_MX;
	} else if (strcmp(type, "HINFO") == 0) {
		return XDNS_TYPE_HINFO;
	} else if (strcmp(type, "MINFO") == 0) {
		return XDNS_TYPE_MINFO;
	} else if (strcmp(type, "CNAME") == 0) {
		return XDNS_TYPE_CNAME;
	} else if (strcmp(type, "WKS") == 0) {
		return XDNS_TYPE_WKS;
	} else if (strcmp(type, "TXT") == 0) {
		return XDNS_TYPE_TXT;
	} else {
		return 0;
	}
}

static unsigned char *parse_name(unsigned char *record_pos, unsigned char *buffer, int *count)
{
	unsigned char *name;
	unsigned int pos = 0;
	uint8_t pointer;
	uint16_t offset = 0;
	char *poffset = (char *)&offset;
	int i, j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	while (*record_pos != 0) {
		pointer = *record_pos;
		/* the first of two bits is `11', means it is a pointer */
		if (pointer == 0xc0) {
			/* calculate the offset */
			poffset[1] = *record_pos;
			poffset[0] = *(record_pos + 1);
			offset -= 0xc000;
			record_pos = buffer + offset - 1;
		} else {
			name[pos++] = *record_pos;
		}

		record_pos = record_pos + 1;

		if (offset == 0) {
			*count = *count + 1;
		}
	}

	name[pos] = '\0';

	if (offset > 0) {
		*count = *count + 1;
	}

	for (i = 0; i < (int)strlen((const char *)name); i++) {
		pos = name[i];
		for (j = 0; j < (int)pos; j++) {
			name[i] = name[i + 1];
			i = i + 1;
		}
		name[i] = '.';
	}

	name[i - 1] = '\0';

	return name;
}

static void set_qname(unsigned char *qname, unsigned char *host)
{
	unsigned int dot = 0, i;
	strcat((char *)host, ".");

	for (i = 0 ; i < strlen((char *)host); i++) {
		if (host[i] == '.') {
			*qname++ = i - dot;
			for (; dot < i; dot++) {
				*qname++ = host[dot];
			}
			dot++;
		}
	}

	*qname++ = '\0';
}

static void set_dns_header(struct xdns_header *dns_header)
{
	dns_header->id = (uint16_t)htons(getpid());
	dns_header->qr = 0;
	dns_header->opcode = XDNS_OPCODE_STD_QUERY;
	dns_header->aa = 0;
	dns_header->tc = 0;
	dns_header->rd = 1;
	dns_header->ra = 0;
	dns_header->zero = 0;
	dns_header->rcode = 0;
	dns_header->qd_count = htons(1);
	dns_header->an_count = 0;
	dns_header->ns_count = 0;
	dns_header->ar_count = 0;
}

static void print_dns_header(struct xdns_header *dns_header)
{
	if (dns_header->qr == XDNS_QR_QEURY) {
		printf("QUERY: ");
	} else if (dns_header->qr == XDNS_QR_RESPONSE) {
		printf("ANSWER: ");
	} else {
		exit(-1);
	}
	printf("RCODE: %d, QDCOUNT: %d, ANCOUNT: %d, NSCOUNT: %d, ARCOUNT: %d\n",
		dns_header->rcode,
		ntohs(dns_header->qd_count), ntohs(dns_header->an_count),
		ntohs(dns_header->ns_count), ntohs(dns_header->ar_count));
}

static void set_dns_question(struct xdns_question *dns_question, uint16_t qtype, uint16_t qclass)
{
	dns_question->qtype = htons(qtype);
	dns_question->qclass = htons(qclass);
}

static void section_free(struct xrecord **record, int count)
{
	for (int i = 0; i < count; i++) {
		struct xrecord *curr = record[i];

		if (curr->name)
			free(curr->name);

		if (curr->resource->type == XDNS_TYPE_A || curr->resource->type == XDNS_TYPE_AAAA) {
			free(curr->rdata.address);
		} else if (curr->resource->type == XDNS_TYPE_CNAME || curr->resource->type == XDNS_TYPE_NS) {
			free(curr->rdata.rname);
		} else if (curr->resource->type == XDNS_TYPE_SOA) {
			if (curr->rdata.soa_data.mname)
				free(curr->rdata.soa_data.mname);

			if (curr->rdata.soa_data.rname)
				free(curr->rdata.soa_data.rname);
		} else if (curr->resource->type == XDNS_TYPE_MX) {
			free(curr->rdata.mx_data.exchange);
		} else if (curr->resource->type == XDNS_TYPE_TXT) {
			free(curr->rdata.txt_data.txt);
		} else {
			printf("%s:%d **WARN**: type(%d) unimplemented\n",
				__FILE__, __LINE__, curr->resource->type);
		}

		free(curr);
	}

	if (record)
		free(record);
}

static void print_hex(unsigned char *buff, size_t len)
{
	size_t nline = len / 16;
	size_t remaining = len % 16;
	unsigned char *c = buff;
	unsigned char *h = buff;

	int linenum = 0;
	for (size_t i = 0; i < nline; i++) {
		printf("%08x  ", linenum++);
		for (int j = 0; j < 16; j++) {
			printf("%02x ", *c++);
		}

		printf("  ");

		for (int j = 0; j < 16; j++) {
			if (isprint(*h) != 0) {
				printf("%c", *h);
			} else {
				printf(".");
			}
			h++;
		}
		printf("\n");
	}

	printf("%08x  ", linenum++);
	for (size_t i = 0; i < remaining; i++) {
		printf("%02x ", *c++);
	}

	for (size_t i = 0; i < 16 - remaining + 1; i++) {
		printf("   ");
	}

	for (size_t i = 0; i < remaining; i++) {
		if (isprint(*h) != 0) {
			printf("%c", *h);
		} else {
			printf(".");
		}
		h++;
	}

	printf("\n");
}


void xdns_client_set_request(struct xdns_request *request, const char *host, uint16_t qtype, uint16_t qclass)
{
    set_dns_header(&request->header);
    set_qname(request->qname, (unsigned char *)host);
    set_dns_question(&request->question, qtype, qclass);
}

int xdns_client_send(struct xdns_client *client, struct xdns_request *request)
{
	ssize_t ret;
	char buff[BUFF_SIZE] = { 0 };
	size_t len = 0;
	char *p = buff;
    
	memcpy(p, &request->header, sizeof(request->header));
	p += sizeof(request->header);
    
	memcpy(p, request->qname, strlen((char *)request->qname));
	p += strlen((char *)request->qname) + 1;
    
	memcpy(p, &request->question, sizeof(request->question));
	p += sizeof(request->question);
    
	len = p - buff;
    
	if (client->inet == XDNS_INET6) {
		ret = sendto(client->fd, buff, len, 0,
			     (struct sockaddr *)&client->srv_addr.addr6,
			     sizeof(client->srv_addr.addr6));
	} else {
		ret = sendto(client->fd, buff, len, 0,
			     (struct sockaddr *)&client->srv_addr.addr4,
			     sizeof(client->srv_addr.addr4));
	}

	print_hex((unsigned char *)buff, len);

	return ret < 0 ? -1 : 0;
}


struct xdns_response *xdns_client_recv(struct xdns_client *client)
{
	struct xdns_response *response = NULL;
	ssize_t ret;
	socklen_t srv_addr_len;
	unsigned char *record_pos;
	char buff[BUFF_SIZE] = { 0 };

	if (client->inet == XDNS_INET6) {
		srv_addr_len = sizeof(client->srv_addr.addr6);
		ret = recvfrom(client->fd, buff, BUFF_SIZE, 0,
				(struct sockaddr *)&client->srv_addr.addr6,
				&srv_addr_len);
	} else {
		srv_addr_len = sizeof(client->srv_addr.addr4);
		ret = recvfrom(client->fd, buff, BUFF_SIZE, 0,
				(struct sockaddr *)&client->srv_addr.addr4,
				&srv_addr_len);
	}

	if (ret < 0) {
		return response;
	}

	response = calloc(1, sizeof(struct xdns_response));

	/* header */
	memcpy(&response->header, (struct xdns_header *)buff, sizeof(struct xdns_header));

	/* qname */
	response->qname_len = parse_qname(response->qname, (unsigned char *)(buff + sizeof(struct xdns_header)));
	record_pos = (unsigned char *)&buff[sizeof(struct xdns_header) + response->qname_len + 1 +
					    sizeof(struct xdns_question)];

	/* question */
	memcpy(&response->question,
		(struct xdns_question *)(buff + sizeof(struct xdns_header) + response->qname_len + 1),
		sizeof(struct xdns_question));

	parse_response(response, &record_pos, (unsigned char *)buff);

	print_dns_header(&response->header);
	print_dns_question(&response->question);
	print_hex((unsigned char *)buff, ret);

	return response;
}

void xdns_response_print_answer(struct xdns_response *response)
{
	struct xrecord **record = response->answer_section;

	if (record)
		printf("ANSWER SECTION:\n");

	for (int i = 0; i < response->an_count; i++) {
		uint16_t type = record[i]->resource->type;
		printf("%s ", record[i]->name);
		if (type == XDNS_TYPE_A) {
			struct sockaddr_in addr;
			addr.sin_addr.s_addr = *(in_addr_t *)record[i]->rdata.address;
			printf("A %s", inet_ntoa(addr.sin_addr));
		} else if (type == XDNS_TYPE_AAAA) {
			struct sockaddr_in6 addr;
			char ipv6[INET6_ADDRSTRLEN];
			memcpy(&addr.sin6_addr.s6_addr, record[i]->rdata.address, 16);
			inet_ntop(AF_INET6, record[i]->rdata.address, ipv6, INET6_ADDRSTRLEN);
			printf("AAAA %s", ipv6);
		} else if (type == XDNS_TYPE_CNAME) {
			printf("CNAME %s", record[i]->rdata.rname);
		} else if (type == XDNS_TYPE_MX) {
			printf("PREFERENCE: %d MX %s", record[i]->rdata.mx_data.preference,
				record[i]->rdata.mx_data.exchange);
		} else if (type == XDNS_TYPE_TXT) {
			printf("TXT \"%s\"", record[i]->rdata.txt_data.txt);
		} else {
			printf("%s:%d **WARN**: type(%d) unimplemented\n", __FILE__, __LINE__, type);
		}

		printf("\n");
	}
}

void xdns_response_print_authority(struct xdns_response *response)
{
	struct xrecord **record = response->authority_section;

	if (record)
		printf("AUTHORITY SECTION:\n");

	for (int i = 0; i < response->ns_count; i++) {
		printf("%s ", record[i]->name);
		uint16_t type = record[i]->resource->type;
		if (type == XDNS_TYPE_NS) {
			printf("NS %s", record[i]->rdata.rname);
		} else if (type == XDNS_TYPE_SOA) {
			printf("SOA %s %s %d %d %d %d %d\n",
				record[i]->rdata.soa_data.rname,
				record[i]->rdata.soa_data.mname,
				record[i]->rdata.soa_data.resource->serial,
				record[i]->rdata.soa_data.resource->refresh,
				record[i]->rdata.soa_data.resource->retry,
				record[i]->rdata.soa_data.resource->expire,
				record[i]->rdata.soa_data.resource->minimum);
		} else {
			printf("%s:%d **WARN**: type(%d) unimplemented\n", __FILE__, __LINE__, type);
		}

		printf("\n");
	}
}

void xdns_response_print_additional(struct xdns_response *response)
{
	struct xrecord **record = response->additional_section;

	if (record)
		printf("ADDITIONAL SECTION:\n");

	for (int i = 0; i < response->ar_count; i++) {
		printf("%s ", record[i]->name);
		uint16_t type = record[i]->resource->type;
		if (type == XDNS_TYPE_A) {
			struct sockaddr_in addr;
			addr.sin_addr.s_addr = *(in_addr_t *)record[i]->rdata.address;
			printf("has IPv4 address: %s", inet_ntoa(addr.sin_addr));
		} else {
			printf("%s:%d **WARN**: type(%d) unimplemented\n", __FILE__, __LINE__, type);
		}
		printf("\n");
	}
}

void xdns_response_destroy(struct xdns_response *response)
{
	section_free(response->answer_section, response->an_count);
	section_free(response->authority_section, response->ns_count);
	section_free(response->additional_section, response->ar_count);
	free(response);
}

static int parse_qname(unsigned char *qname, unsigned char *buffer)
{
	int i = 0, j = 0;
	unsigned int pos = 0;
	unsigned char *p = buffer;

	while (*p != 0) {
		qname[i++] = *p++;
	}

	qname[i] = '\0';

	for (i = 0; i < (int)strlen((const char *)qname); i++) {
		pos = qname[i];
		for (j = 0; j < (int)pos; j++) {
			qname[i] = qname[i + 1];
			i = i + 1;
		}
		qname[i] = '.';
	}

	qname[i] = '\0';
	return i;
}


static void print_dns_question(struct xdns_question *question)
{
	printf("QTYPE: %d CLASS: %d\n", ntohs(question->qtype), ntohs(question->qclass));
}


static void parse_response(struct xdns_response *response, unsigned char **record_pos, unsigned char *buffer)
{
	int offset = 0;
	int i, j;

	/* answer section */
	response->an_count = ntohs(response->header.an_count);
	if (response->an_count > 0)
		response->answer_section = calloc(response->an_count, sizeof(struct xrecord *));

	for (i = 0; i < response->an_count; i++) {
		struct xrecord *answer = (struct xrecord *)malloc(sizeof(struct xrecord));
		memset(answer, 0, sizeof(struct xrecord));

		answer->name = parse_name(*record_pos, buffer, &offset);
		*record_pos = *record_pos + offset;

		answer->resource = (struct xresource *)(*record_pos);
		answer->resource->type = ntohs(answer->resource->type);
		answer->resource->class = ntohs(answer->resource->class);
		answer->resource->ttl = ntohl(answer->resource->ttl);
		answer->resource->rdata_len = ntohs(answer->resource->rdata_len);

		*record_pos = *record_pos + sizeof(struct xresource);

		if (answer->resource->type == XDNS_TYPE_A || answer->resource->type == XDNS_TYPE_AAAA) {
			answer->rdata.address = (unsigned char *)malloc(answer->resource->rdata_len + 1);
			for (j = 0; j < answer->resource->rdata_len; j++) {
				answer->rdata.address[j] = (*record_pos)[j];
			}

			answer->rdata.address[answer->resource->rdata_len] = '\0';
			*record_pos = *record_pos + answer->resource->rdata_len;
                } else if (answer->resource->type == XDNS_TYPE_NS ||
			   answer->resource->type == XDNS_TYPE_CNAME)
		{
			answer->rdata.rname = parse_name(*record_pos, buffer, &offset);
			*record_pos = *record_pos + offset;
                } else if (answer->resource->type == XDNS_TYPE_MX) {
			answer->rdata.mx_data.preference = ntohs(*(int16_t *)(*record_pos));
			*record_pos += 2;
			answer->rdata.mx_data.exchange = parse_name(*record_pos, buffer, &offset);
			*record_pos = *record_pos + offset;
		} else if (answer->resource->type == XDNS_TYPE_TXT) {
			answer->rdata.txt_data.txt_len = *(uint8_t *)(*record_pos);
			answer->rdata.txt_data.txt = parse_name(*record_pos, buffer, &offset);
			*record_pos = *record_pos + offset;
		} else {
			printf("%s:%d **WARN**: type(%d) unimplemented\n",
				__FILE__, __LINE__, answer->resource->type);
		}

		response->answer_section[i] = answer;
	}

	/* authority section */
	response->ns_count = ntohs(response->header.ns_count);
	if (response->ns_count > 0)
		response->authority_section = calloc(response->ns_count, sizeof(struct xrecord *));

	for (i = 0; i < response->ns_count; i++) {
		struct xrecord *auth = (struct xrecord *)malloc(sizeof(struct xrecord));
		memset(auth, 0, sizeof(struct xrecord));

		auth->name = parse_name(*record_pos, buffer, &offset);
		*record_pos += offset;

		auth->resource = (struct xresource *)(*record_pos);
		auth->resource->type = ntohs(auth->resource->type);
		auth->resource->class = ntohs(auth->resource->class);
		auth->resource->ttl = ntohl(auth->resource->ttl);
		auth->resource->rdata_len = ntohs(auth->resource->rdata_len);

		*record_pos += sizeof(struct xresource);

		if (auth->resource->type == XDNS_TYPE_SOA) {
			auth->rdata.soa_data.rname = parse_name(*record_pos, buffer, &offset);
			*record_pos += offset;

			auth->rdata.soa_data.mname = parse_name(*record_pos, buffer, &offset);
			*record_pos += offset;

			auth->rdata.soa_data.resource = (struct soa_resource *)(*record_pos);
			auth->rdata.soa_data.resource->serial = ntohl(auth->rdata.soa_data.resource->serial);
			auth->rdata.soa_data.resource->refresh = ntohl(auth->rdata.soa_data.resource->refresh);
			auth->rdata.soa_data.resource->retry = ntohl(auth->rdata.soa_data.resource->retry);
			auth->rdata.soa_data.resource->expire = ntohl(auth->rdata.soa_data.resource->expire);
			auth->rdata.soa_data.resource->minimum = ntohl(auth->rdata.soa_data.resource->minimum);
		} else {
			printf("%s:%d **WARN**: type(%d) unimplemented\n", __FILE__, __LINE__, auth->resource->type);
		}
		response->authority_section[i] = auth;
	}

	/* additional record section */
	response->ar_count = ntohs(response->header.ar_count);
	if (response->ar_count > 0)
		response->additional_section = calloc(response->ar_count, sizeof(struct xrecord *));

	for (i = 0; i < response->ar_count; i++) {
		struct xrecord *addit = (struct xrecord *)malloc(sizeof(struct xrecord));
		memset(addit, 0, sizeof(struct xrecord));

		addit->name = parse_name(*record_pos, buffer, &offset);
		*record_pos += offset;

		addit->resource = (struct xresource *)(*record_pos);
		addit->resource->type = ntohs(addit->resource->type);
		addit->resource->class = ntohs(addit->resource->class);
		addit->resource->ttl = ntohl(addit->resource->ttl);
		addit->resource->rdata_len = ntohs(addit->resource->rdata_len);

		printf("type: %d, class: %d, ttl: %d, rdata_len: %d\n",
			addit->resource->type,
			addit->resource->class,
			addit->resource->ttl,
			addit->resource->rdata_len);

		*record_pos += sizeof(struct xresource);

		if (addit->resource->type == XDNS_TYPE_A || addit->resource->type == XDNS_TYPE_AAAA) {
			addit->rdata.address = (unsigned char *)malloc(addit->resource->rdata_len + 1);
			for (j = 0; j < addit->resource->rdata_len; j++)
				addit->rdata.address[j] = (*record_pos)[j];

			addit->rdata.address[addit->resource->rdata_len] = '\0';
			*record_pos += ntohs(addit->resource->rdata_len);
		} else {
			addit->rdata.rname = parse_name(*record_pos, buffer, &offset);
			*record_pos += offset;
		}
		response->additional_section[i] = addit;
	}
}

