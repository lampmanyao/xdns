#include "xdns.h"

#include <stdio.h> 
#include <stdlib.h>  /* malloc() */
#include <unistd.h>  /* getpid() */
#include <string.h> 
#include <errno.h>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <netdb.h>

#define PORT 53

static void set_qname(unsigned char *qname, unsigned char *host);
static void set_dns_header(struct xdns_header *dns_header);
static void set_dns_question(struct xdns_question *dns_question, uint16_t qtype, uint16_t qclass);
static void print_dns_header(struct xdns_header *dns_header);
static unsigned char *parse_name(unsigned char *record_pos, unsigned char *buffer, int *count);
static struct xrecord *parse_answer_section(struct xdns_header *dns_header,
					     unsigned char **record_pos, unsigned char *buffer);
static struct xrecord *parse_authority_section(struct xdns_header *dns_header,
						unsigned char **record_pos, unsigned char *buffer);
static struct xrecord *parse_additional_section(struct xdns_header *dns_header,
						 unsigned char **record_pos, unsigned char *buffer);
static void section_free(struct xrecord *section);


int xdns_client_init(struct xdns_client *xdns_client, char *dns_server, const char *host)
{
	strcpy(xdns_client->dns_server, dns_server);
	strncpy((char *)xdns_client->host, host, HOST_SIZE - 1);
	xdns_client->host[HOST_SIZE - 1] = '\0';

	xdns_client->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (xdns_client->fd < 0) {
		return -1;
	}

	xdns_client->answer_section = NULL;
	xdns_client->authority_section = NULL;
	xdns_client->additional_section = NULL;

	xdns_client->dest.sin_family = AF_INET;
	xdns_client->dest.sin_port = htons(53);
	xdns_client->dest.sin_addr.s_addr = inet_addr(dns_server);

	return 0;
}

void xdns_client_destroy(struct xdns_client *xdns_client)
{
	section_free(xdns_client->answer_section);
	section_free(xdns_client->authority_section);
	section_free(xdns_client->additional_section);
	close(xdns_client->fd);
}

int xdns_client_query(struct xdns_client *xdns_client, uint16_t qtype, uint16_t qclass)
{
	ssize_t ret;
	size_t len;
	unsigned char *record_pos;
	socklen_t dest_len;

	struct xdns_header *dns_header = NULL;
	struct xdns_question *dns_question = NULL;

	dns_header = (struct xdns_header *)&xdns_client->sbuf;
	set_dns_header(dns_header);

	print_dns_header(dns_header);

	xdns_client->qname = (unsigned char *)&xdns_client->sbuf[sizeof(struct xdns_header)];
	set_qname(xdns_client->qname, xdns_client->host);

	dns_question = (struct xdns_question *)&xdns_client->sbuf[sizeof(struct xdns_header) +
			strlen((char *)xdns_client->qname) + 1];
	set_dns_question(dns_question, qtype, qclass);

	len = sizeof(struct xdns_header) + strlen((char *)xdns_client->qname) + 1 + sizeof(struct xdns_question);

	ret = sendto(xdns_client->fd, (char *)xdns_client->sbuf, len, 0,
		     (struct sockaddr *)&xdns_client->dest, sizeof(xdns_client->dest));
	if (ret < 0) {
		return -1;
	}

	dest_len = sizeof(xdns_client->dest);
	ret = recvfrom(xdns_client->fd, (char *)xdns_client->rbuf, BUFF_SIZE, 0,
			(struct sockaddr *)&xdns_client->dest, &dest_len);
	if (ret < 0) {
		return -1;
	}

	dns_header = (struct xdns_header *)xdns_client->rbuf;
	print_dns_header(dns_header);

	record_pos = &xdns_client->rbuf[sizeof(struct xdns_header) +
					(strlen((char *)xdns_client->qname) + 1) +
					sizeof(struct xdns_question)];

	xdns_client->answer_section = parse_answer_section(dns_header, &record_pos, xdns_client->rbuf);
	xdns_client->authority_section = parse_authority_section(dns_header, &record_pos, xdns_client->rbuf);
	xdns_client->additional_section = parse_additional_section(dns_header, &record_pos, xdns_client->rbuf);

	return 0;
}

void xdns_client_print_answer(struct xdns_client *xdns_client)
{
	printf("ANSWER SECTION:\n");

	struct xrecord *head = xdns_client->answer_section;

	while (head) {
		printf("Name: %s ", head->name);
		if (head->resource->type == XDNS_TYPE_A) {
			struct sockaddr_in addr;
			addr.sin_addr.s_addr = *(long *)head->rdata.address;
			printf("has IPv4 address: %s", inet_ntoa(addr.sin_addr));
		}

		if (head->resource->type == XDNS_TYPE_AAAA) {
			struct sockaddr_in6 addr;
			char ipv6[INET6_ADDRSTRLEN];
			memcpy(&addr.sin6_addr.s6_addr, head->rdata.address, 16);
			inet_ntop(AF_INET6, head->rdata.address, ipv6, INET6_ADDRSTRLEN);
			printf("has IPv6 address: %s", ipv6);
		}
		
		if (head->resource->type == XDNS_TYPE_CNAME) {
			printf("has alias name: %s", head->rdata.rname);
		}

		head = head->next;
		printf("\n");
	}
	printf("\n");
}

void xdns_client_print_authority(struct xdns_client *xdns_client)
{
	printf("AUTHORITY SECTION:\n");

	struct xrecord *head = xdns_client->authority_section;
	while (head) {
		printf("Name: %s ", head->name);

		if (head->resource->type == XDNS_TYPE_NS) {
			printf("has nameserver: %s", head->rdata.rname);
		}

		if (head->resource->type == XDNS_TYPE_SOA) {
			printf("%s %d %d %d %d %d\n",
				head->rdata.soa_data.mname,
				head->rdata.soa_data.resource->serial,
				head->rdata.soa_data.resource->refresh,
				head->rdata.soa_data.resource->retry,
				head->rdata.soa_data.resource->expire,
				head->rdata.soa_data.resource->minimum);
		}

		head = head->next;
		printf("\n");
	}
	printf("\n");
}

void xdns_client_print_additional(struct xdns_client *xdns_client)
{
	printf("ADDITIONAL SECTION:\n");

	struct xrecord *head = xdns_client->additional_section;
	while (head) {
		printf("Name: %s ", head->name);
		if (head->resource->type == XDNS_TYPE_A) {
			struct sockaddr_in addr;
			addr.sin_addr.s_addr = *(long *)head->rdata.address;
			printf("has IPv4 address: %s", inet_ntoa(addr.sin_addr));
		}
		head = head->next;
		printf("\n");
	}
	printf("\n");
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

static struct xrecord *parse_answer_section(struct xdns_header *dns_header,
					     unsigned char **record_pos, unsigned char *buffer)
{
	struct xrecord *answer_section = NULL;
	int offset = 0;
	int i, j;

	for (i = 0; i < ntohs(dns_header->an_count); i++) {
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

		printf("type: %d, class: %d, ttl: %d, rdata_len: %d\n",
			answer->resource->type,
			answer->resource->class,
			answer->resource->ttl,
			answer->resource->rdata_len);

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
		} else {
                        printf("unimplement\n");
		}

		if (answer_section == NULL) {
			answer_section = answer;
		} else {
			/* Append to tail */
			struct xrecord *head = answer_section;
			struct xrecord *curr = NULL;
			while (head) {
				curr = head;
				head = head->next;
			}
			curr->next = answer;
		}
	}

	return answer_section;
}

static struct xrecord *parse_authority_section(struct xdns_header *dns_header,
						unsigned char **record_pos, unsigned char *buffer)
{
	int offset = 0;
	int i;

	struct xrecord *authority_section = NULL;

	for (i = 0; i < ntohs(dns_header->ns_count); i++) {
		struct xrecord *auth = (struct xrecord *)malloc(sizeof(struct xrecord));
		memset(auth, 0, sizeof(struct xrecord));

		auth->name = parse_name(*record_pos, buffer, &offset);
		*record_pos += offset;

		auth->resource = (struct xresource *)(*record_pos);
		auth->resource->type = ntohs(auth->resource->type);
		auth->resource->class = ntohs(auth->resource->class);
		auth->resource->ttl = ntohl(auth->resource->ttl);
		auth->resource->rdata_len = ntohs(auth->resource->rdata_len);

		printf("type: %d, class: %d, ttl: %d, rdata_len: %d\n",
			auth->resource->type,
			auth->resource->class,
			auth->resource->ttl,
			auth->resource->rdata_len);

		*record_pos += sizeof(struct xresource);

		auth->rdata.rname = parse_name(*record_pos, buffer, &offset);
		*record_pos += offset;

		if (auth->resource->type == XDNS_TYPE_SOA) {
			auth->rdata.soa_data.mname = parse_name(*record_pos, buffer, &offset);
			*record_pos += offset;

			auth->rdata.soa_data.resource = (struct soa_resource *)(*record_pos);
			auth->rdata.soa_data.resource->serial = ntohl(auth->rdata.soa_data.resource->serial);
			auth->rdata.soa_data.resource->refresh = ntohl(auth->rdata.soa_data.resource->refresh);
			auth->rdata.soa_data.resource->retry = ntohl(auth->rdata.soa_data.resource->retry);
			auth->rdata.soa_data.resource->expire = ntohl(auth->rdata.soa_data.resource->expire);
			auth->rdata.soa_data.resource->minimum = ntohl(auth->rdata.soa_data.resource->minimum);
		}

		if (authority_section == NULL) {
			authority_section = auth;
		} else {
			/* Append to tail */
			struct xrecord *head = authority_section;
			struct xrecord *curr = NULL;
			while (head) {
				curr = head;
				head = head->next;
			}
			curr->next = auth;
		}
	}

	return authority_section;
}

static struct xrecord *parse_additional_section(struct xdns_header *dns_header,
						 unsigned char **record_pos, unsigned char *buffer)
{
	int offset = 0;
	int i, j;

	struct xrecord *additional_section = NULL;

	for (i = 0; i < ntohs(dns_header->ar_count); i++) {
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

		if (additional_section == NULL) {
			additional_section = addit;
		} else {
			/* Append to tail */
			struct xrecord *head = additional_section;
			struct xrecord *curr = NULL;
			while (head) {
				curr = head;
				head = head->next;
			}
			curr->next = addit;
		}
	}

	return additional_section;
}

static void section_free(struct xrecord *section)
{
	struct xrecord **record = &section;
	while (*record) {
		struct xrecord *curr = *record;
		*record = (*record)->next;

		if (curr->name)
			free(curr->name);

		if (curr->resource->type == XDNS_TYPE_A || curr->resource->type == XDNS_TYPE_AAAA)
			free(curr->rdata.address);


		if (curr->resource->type == XDNS_TYPE_CNAME || curr->resource->type == XDNS_TYPE_NS)
			free(curr->rdata.rname);

		if (curr->resource->type == XDNS_TYPE_SOA) {
			if (curr->rdata.soa_data.mname)
				free(curr->rdata.soa_data.mname);

			if (curr->rdata.soa_data.rname)
				free(curr->rdata.soa_data.rname);
		}

		free(curr);
	}
}

