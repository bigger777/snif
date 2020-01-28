#include <string.h>
#include <pcap.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

#define SIZE_ETHERNET	14
#define ETHER_ADDR_LEN	6
#define MAX_SESSIONS	10000
#define MAX_PACKETS	20
#define NUM_THREADS	4

struct session
{
	struct in_addr dst_ip;	/* ip получателя */
	struct in_addr src_ip;	/* ip отправителя */
	u_short dstport;	/* порт получателя */
	u_short srcport;	/* порт отправителя */
	int pack_count;		/* счетчик пакетов каждой сессии */
/* !добавить таймаут! */
};

struct hand_fd
{
	pcap_dumper_t *dumpfile;
	pcap_t *hand;
};

struct s_packets
{
	u_char *packs_array[MAX_SESSIONS][MAX_PACKETS];		/* массив пакетов */
	unsigned int packetSize[MAX_SESSIONS][MAX_PACKETS];	/* массив размеров payload*/	
};

struct ses_pack
{
	struct session ses_array[MAX_SESSIONS];		/* массив сессий */
	struct s_packets packet;
	int ses_count;					/* счетчик сессий */
};

/* Заголовок Ethernet */
struct sniff_ethernet 
{
	u_char ether_dhost[ETHER_ADDR_LEN];	/* Адрес назначения */
	u_char ether_shost[ETHER_ADDR_LEN];	/* Адрес источника */
	u_short ether_type;			/* IP? ARP? RARP? и т.д. */
};

/* IP header */
struct sniff_ip 
{
	u_char ip_vhl;			/* версия << 4 | длина заголовка >> 2 */
	u_char ip_tos;			/* тип службы */
	u_short ip_len;			/* общая длина */
	u_short ip_id;			/* идентефикатор */
	u_short ip_off;			/* поле фрагмента смещения */
	#define IP_RF 0x8000		/* reserved флаг фрагмента */
	#define IP_DF 0x4000		/* dont флаг фрагмента */
	#define IP_MF 0x2000		/* more флаг фрагмента */
	#define IP_OFFMASK 0x1fff	/* маска для битов фрагмента */
	u_char ip_ttl;			/* время жизни */
	u_char ip_p;			/* протокол */
	u_short ip_sum;			/* контрольная сумма */
	struct in_addr ip_src,ip_dst;
};


#define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp 
{
	u_short th_sport;	/* порт источника */
	u_short th_dport;	/* порт назначения */
	tcp_seq th_seq;		/* номер последовательности */
	tcp_seq th_ack;		/* номер подтверждения */
	u_char th_offx2;	/* смещение данных, rsvd */
	#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* окно */

	u_short th_sum;		/* контрольная сумма */
	u_short th_urp;		/* экстренный указатель */
};

void* hlight_template(void *arg)
{

	void print_hex_ascii_line(const u_char *payload, int len, int offset)
	{

		int i;
		int gap;
		const u_char *ch;
		printf("%05d   ", offset);
		ch = payload;
		for(i = 0; i < len; i++) {
			printf("%02x ", *ch);
			ch++;
			if (i == 7)
				printf(" ");
		}
		if (len < 8)
			printf(" ");
		if (len < 16) {
			gap = 16 - len;
			for (i = 0; i < gap; i++) {
				printf("   ");
			}
		}
		printf("   ");
		ch = payload;
		for(i = 0; i < len; i++) {
			if (isprint(*ch))
				printf("%c", *ch);
			else
				printf(".");
			ch++;
		}
		printf("\n");
	return;
	}

	void print_payload(const u_char *payload, int len)
	{

		int len_rem = len;
		int line_width = 16;
		int line_len;
		int offset = 0;
		const u_char *ch = payload;
		if (len <= 0)
			return;
		if (len <= line_width) {
			print_hex_ascii_line(ch, len, offset);
			return;
		}
		for ( ;; ) {
			line_len = line_width % len_rem;
			print_hex_ascii_line(ch, line_len, offset);
			len_rem = len_rem - line_len;
			ch = ch + line_len;
			offset = offset + line_width;
			if (len_rem <= line_width) {
				print_hex_ascii_line(ch, len_rem, offset);
				break;
			}
		}
	return;
	}

	struct ses_pack *all = (struct ses_pack *) arg;
	int s = all->ses_count;
	for (int i = s-30; i < s; ++i)
	{
		printf("Session number: %d\n", i+1);
		printf("       Packets: %d\n", all->ses_array[i].pack_count);
		printf("          From: %s\n", inet_ntoa(all->ses_array[i].src_ip));
		printf("            To: %s\n", inet_ntoa(all->ses_array[i].dst_ip));
		printf("      Src port: %d\n", all->ses_array[i].srcport);
		printf("      Dst port: %d\n", all->ses_array[i].dstport);
		for(int j = 0; j < all->ses_array[i].pack_count; ++j)
		{
			printf("   Payload bytes:%d\n", 
				all->packet.packetSize[i][j]);
			printf("   Packet number:%d\n", j + 1);
			print_payload(all->packet.packs_array[i][j], 
				all->packet.packetSize[i][j]);
		}
	}
	return 0;
}

void got_packet(u_char *dump_handle, const struct pcap_pkthdr *header, const u_char *packet)
{

	static long long count = 1;		/* packet counter */
	static long long fcount = 1;		/* счетчик файлов */
	static unsigned int fsize = 0;		/* размер файла */
	static struct ses_pack all;
	static bool in_use = false;

	const struct sniff_ethernet *ethernet;	/* The ethernet header [1] */
	const struct sniff_ip *ip;		/* The IP header  */
	const struct sniff_tcp *tcp;		/* The TCP header */
	const char *payload;			/* Packet payload */
	static char fname[12] = "dumps/dump1";
	static struct hand_fd a;
	pthread_t thread;

	int size_ip;
	int size_tcp;
	int size_payload;
	if (count == 1)
	{
		memcpy(&a, dump_handle, sizeof(a));
	}
	if (pcap_dump_ftell(a.dumpfile) >= 52428800)
	{
		if (fcount>=10)
		{
			fname[10] = (fcount / 10) + '0';
			fname[11] = (fcount % 10) + '0';
			a.dumpfile = pcap_dump_open(a.hand, fname);
		}

		else
		{
			fname[10] = fcount + '0';
			a.dumpfile = pcap_dump_open(a.hand, fname);
		}
		fcount++;
	}

	pcap_dump((unsigned char *)a.dumpfile, header, packet);
	count++;
	ethernet = (struct sniff_ethernet*)(packet);

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20)
	{
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20)
	{
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if (((tcp->th_flags & TH_SYN)+(tcp->th_flags & TH_ACK)) == 18) /* запись tcp сессии в массив */
	{
		all.ses_array[all.ses_count].srcport = ntohs(tcp->th_sport);
		all.ses_array[all.ses_count].dstport = ntohs(tcp->th_dport);
		all.ses_array[all.ses_count].src_ip.s_addr = (ip->ip_src).s_addr;
		all.ses_array[all.ses_count].dst_ip.s_addr = (ip->ip_dst).s_addr;
		all.ses_count++;
		if (in_use % 31 == 0)
			in_use = false;
	}

	/* запись пакета в массив в соотв. с № tcp сессии */
	if ((((tcp->th_flags & TH_SYN) + (tcp->th_flags & TH_ACK)) != 18) && (size_payload > 0))
	{
		for (int i = 0; i < all.ses_count; ++i)
		{
			if (((all.ses_array[i].srcport == ntohs(tcp->th_sport)) &&
				(all.ses_array[i].dstport == ntohs(tcp->th_dport)) &&
				(all.ses_array[i].src_ip.s_addr == (ip->ip_src).s_addr) &&
				(all.ses_array[i].dst_ip.s_addr == (ip->ip_dst).s_addr)) ||
				((all.ses_array[i].srcport == ntohs(tcp->th_dport)) &&
				(all.ses_array[i].dstport == ntohs(tcp->th_sport)) &&
				(all.ses_array[i].src_ip.s_addr == (ip->ip_dst).s_addr) &&
				(all.ses_array[i].dst_ip.s_addr == (ip->ip_src).s_addr)))
			{
				all.packet.packs_array[i][all.ses_array[i].pack_count] =
					malloc((size_t)size_payload);

				memcpy(all.packet.packs_array[i][all.ses_array[i].pack_count],
						(char *) payload, size_payload);
				all.packet.packetSize[i][all.ses_array[i].pack_count] = size_payload;
				(all.ses_array[i].pack_count)++;

				if ((all.ses_count != 0) && (all.ses_count % 30 == 0) && (in_use == false))
				{
					in_use = true;
					pthread_create(&thread, NULL, hlight_template, (void*) &all);
					pthread_join(thread, NULL);
				}
			}
		}
	}
	return;
}

int main(int argc, char *argv[])
{
	//pcap_t *handle;						/* Дескриптор сессии */
	char *dev;							/* Устройство для сниффинга */
	char errbuf[PCAP_ERRBUF_SIZE];					/* Строка для хранения ошибки */
	pcap_t *handle = pcap_open_offline("pokebat-13:01:34.pcap", errbuf);
	struct bpf_program fp;						/* Скомпилированный фильтр */
	char *filter_exp = argv[1];					/* Выражение фильтра */
	struct pcap_pkthdr header;					/* Заголовок который нам дает PCAP */
	const u_char *packet;						/* Пакет */
	int num_packets = 50000;
	char *fname="dumps/dump1";
	
	struct hand_fd dump_handle;
	dump_handle.hand = handle;
	dump_handle.dumpfile = pcap_dump_open(handle, fname);
	char data[sizeof(dump_handle)];
	memcpy(data, &dump_handle, sizeof(dump_handle));

	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	/* Захват пакета */
	pcap_loop(handle, num_packets, got_packet, (unsigned char *)data );
	pcap_close(handle);
	return 0;
}
