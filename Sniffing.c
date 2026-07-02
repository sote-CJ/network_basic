#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void print_mac(const char *label, const u_char *mac)
{
  printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n",
         label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  (void)args;

  if (header->caplen < sizeof(struct ethheader)) {
    return;
  }

  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    if (header->caplen < sizeof(struct ethheader) + sizeof(struct ipheader)) {
      return;
    }

    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    if (ip->iph_protocol != IPPROTO_TCP) {
      return;
    }

    int ip_header_len = ip->iph_ihl * 4;
    if (header->caplen < sizeof(struct ethheader) + ip_header_len
                       + sizeof(struct tcpheader)) {
      return;
    }

    struct tcpheader *tcp = (struct tcpheader *)
                            (packet + sizeof(struct ethheader) + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;
    if (header->caplen < sizeof(struct ethheader) + ip_header_len
                       + tcp_header_len) {
      return;
    }

    const u_char *http_msg = packet + sizeof(struct ethheader)
                             + ip_header_len + tcp_header_len;
    int ip_total_len = ntohs(ip->iph_len);
    int http_msg_len = ip_total_len - ip_header_len - tcp_header_len;

    printf("\n===== TCP Packet =====\n");
    print_mac("Ethernet Src MAC:", eth->ether_shost);
    print_mac("Ethernet Dst MAC:", eth->ether_dhost);
    printf("IP Src: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("IP Dst: %s\n", inet_ntoa(ip->iph_destip));
    printf("TCP Src Port: %u\n", ntohs(tcp->tcp_sport));
    printf("TCP Dst Port: %u\n", ntohs(tcp->tcp_dport));

    if (http_msg_len > 0) {
      printf("HTTP Message:\n");
      for (int i = 0; i < http_msg_len; i++) {
        if (http_msg[i] >= 32 && http_msg[i] <= 126) {
          printf("%c", http_msg[i]);
        } else if (http_msg[i] == '\r' || http_msg[i] == '\n') {
          printf("%c", http_msg[i]);
        }
      }
      printf("\n");
    }

    printf("Protocol: TCP\n");
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth1", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Could not open device eth1: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  // Step 2: Compile filter_exp into BPF psuedo-code
  if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    pcap_perror(handle, "pcap_compile");
    pcap_close(handle);
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      pcap_freecode(&fp);
      pcap_close(handle);
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_freecode(&fp);
  pcap_close(handle);   //Close the handle
  return 0;
}
