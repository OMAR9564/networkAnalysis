/*
 ============================================================================
 Name        : networkA.c
 Author      : OMAR ALFAROUK ALMOHAMAD
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void selectedMethod(void);
void selectedInterface(char **interfaceName);
void printPacketSize(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void printIO(unsigned char *userData, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);

int main(void) {

    selectedMethod();
    return 0;
}

void selectedInterface(char **interfaceName) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    int ret = pcap_findalldevs(&interfaces, errbuf);
    int i = 0;
    int selectedInterfaceIndex = 0;

    printf("Scanning The Threats Of The Surrounding Networks\n");
    printf("--------------------------------\n");

    if (ret == -1) {
        fprintf(stderr, "\nError listing network interfaces: %s\n", errbuf);
        return;
    }

    // Sayılan arayüzlerin sayısını bul
    int num_interfaces = 0;
    for (pcap_if_t *interface = interfaces; interface != NULL; interface = interface->next) {
        num_interfaces++;
    }

    char **interface_names = malloc(num_interfaces * sizeof(char *));
    if (interface_names == NULL) {
        fprintf(stderr, "Memory allocation error.\n");
        pcap_freealldevs(interfaces);
        return;
    }

    printf("Interfaces:\n\n");

    for (pcap_if_t *interface = interfaces; interface != NULL; interface = interface->next) {
        interface_names[i] = strdup(interface->name);
        i++;
        printf("%d. Interface name: %s\n", i, interface->name);
        if (interface->description) {
            printf("\tDescription: %s\n", interface->description);
        }
        for (pcap_addr_t *address = interface->addresses; address != NULL; address = address->next) {
            if (address->addr) {
                if (address->addr->sa_family == AF_INET) {
                    struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)address->addr;
                    printf("\tIPv4 Address: %s\n", inet_ntoa(ipv4_addr->sin_addr));
                } else if (address->addr->sa_family == AF_INET6) {
                    struct sockaddr_in6 *ipv6_addr = (struct sockaddr_in6 *)address->addr;
                    char ipv6_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &(ipv6_addr->sin6_addr), ipv6_str, INET6_ADDRSTRLEN);
                    printf("\tIPv6 Address: %s\n", ipv6_str);
                }
            }
        }
    }

    printf("Please select the interface you want to analyze...\n");
    printf("Interface: ");
    scanf("%d", &selectedInterfaceIndex);

    if (selectedInterfaceIndex < 1 || selectedInterfaceIndex > num_interfaces) {
        fprintf(stderr, "Invalid interface selection.\n");
        pcap_freealldevs(interfaces);
        free(interface_names);
        return;
    }

    *interfaceName = strdup(interface_names[selectedInterfaceIndex - 1]);

    pcap_freealldevs(interfaces);
    free(interface_names);
}

void selectedMethod() {
    int selectedValue = 0;
    char *interfaceName = NULL;

    int *numOfDes = malloc(sizeof(int));
    *numOfDes = 1;

    selectedInterface(&interfaceName);

    pcap_t *handle;
    char errorBuffer[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errorBuffer);
    if (handle == NULL) {
        fprintf(stderr, "Ağ cihazı açılırken hata oluştu: %s\n", errorBuffer);
        free(interfaceName);
        return;
    }
    printf("\nPlease Select A Method\n");
    printf("1. Check Input Package Size\n");
    printf("2. Check Inputs Outputs\n");

    printf("Enter The Number Of Method: ");
    scanf("%d", &selectedValue);

    switch (selectedValue) {
        case 1:
            pcap_loop(handle, 0, printPacketSize, NULL);
            break;
        case 2:
            pcap_loop(handle, 0, printIO, (unsigned char *)numOfDes);
            break;
        default:
            printf("Please enter a valid value.\n");
            break;
    }

    pcap_close(handle);
    free(interfaceName);
    free(numOfDes);

}

void printPacketSize(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int packetSize = pkthdr->len;
    printf("Packet Size: %d byte\n", packetSize);
}

void printIO(unsigned char *userData, const struct pcap_pkthdr *pkthdr, const unsigned char *packet){

    struct ether_header *ethHeader;
    struct ip *ipHeader;
    struct tcphdr *tcpHeader;
    struct udphdr *udpHeader;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    int packetSize = pkthdr->len;
    int threshold = 6000; // Danger size of Package
    int *i = (int *)userData;

    ethHeader = (struct ether_header *) packet;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip *) (packet + sizeof(struct ether_header));
        struct in_addr srcAddr, destAddr;
        srcAddr = ipHeader->ip_src;
        destAddr = ipHeader->ip_dst;
        strcpy(sourceIP, inet_ntoa(srcAddr));
        strcpy(destIP, inet_ntoa(destAddr));

        if (packetSize > threshold) {
            printf("%d. Aşırı büyük paket tespit edildi!\n\tKaynak IP: %s,\n\tHedef IP: %s\n",
                   *i,sourceIP, destIP);
            (*i)++;
        }
        else if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));

            if (ntohs(tcpHeader->th_dport) == 22) {
                printf("%d. SSH trafiği tespit edildi!\n\tKaynak IP: %s,\n\tHedef IP: %s\n", *i, sourceIP, destIP);
                (*i)++;
            }
        }
        else if (ipHeader->ip_p == IPPROTO_ICMP) {
            printf("%d. ICMP trafiği tespit edildi!\n\tKaynak IP: %s,\n\tHedef IP: %s\n",*i, sourceIP, destIP);
            (*i)++;
        }
        else if (ipHeader->ip_p == IPPROTO_UDP) {
            udpHeader = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));

            if (ntohs(udpHeader->uh_dport) == 53) {
                printf("%d. DNS trafiği tespit edildi!\n\tKaynak IP: %s,\n\tHedef IP: %s\n", *i, sourceIP, destIP);
                (*i)++;
            }
            if (ntohs(udpHeader->uh_dport) == 123) {
                printf("%d. NTP trafiği tespit edildi!\n\tKaynak IP: %s,\n\tHedef IP: %s\n", *i, sourceIP, destIP);
                (*i)++;
            }
        }
    }

}
