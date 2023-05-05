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
#include <stdlib.h>
#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    int ret = pcap_findalldevs(&interfaces, errbuf);
    int i = 0;
    int selectedInterface = 0;

    printf("Scovering The Threats Of The Surrounding Networks\n");
    printf("--------------------------------");


    if (ret == -1) {
        fprintf(stderr, "\nError listing network interfaces: %s\n", errbuf);
        return 1;
    }
    // count number of interfaces
    int num_interfaces = 0;
    for (pcap_if_t *interface = interfaces; interface != NULL; interface = interface->next) {
        num_interfaces++;
    }

    char **interface_names = malloc(num_interfaces * sizeof(char *));
    if (interface_names == NULL) {
        fprintf(stderr, "Memory allocation error.\n");
        pcap_freealldevs(interfaces);
        return 1;
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
                }
                else if (address->addr->sa_family == AF_INET6) {
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
	scanf("%d", &selectedInterface);
    printf("\n\n%s", interface_names[selectedInterface - 1]);

    pcap_freealldevs(interfaces);
    return 0;
}
