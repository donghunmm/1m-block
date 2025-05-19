#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <set>
#include <string>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iostream>
#include <algorithm>

std::set<std::string> blocked_sites;

void dump(unsigned char* buf, int size) {
    for (int i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static u_int32_t extract_packet_info(struct nfq_data *tb, unsigned char **data) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    ret = nfq_get_payload(tb, data);
    return id;
}

bool load_blocked_sites(const char* filename) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return false;
    }

    std::string line;
    int count = 0;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string rank, domain;
        if (std::getline(ss, rank, ',') && std::getline(ss, domain)) {
            domain.erase(std::remove_if(domain.begin(), domain.end(), 
                [](unsigned char c) { return std::isspace(c); }), domain.end());
            
            blocked_sites.insert(domain);
            count++;
            if (count <= 5) {
                std::cout << "Sample domain loaded: " << domain << std::endl;
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    std::cout << "Loaded " << blocked_sites.size() << " sites in " << diff.count() << " seconds" << std::endl;
    
    return true;
}

int blocked_site(unsigned char* data) {
    unsigned char *http_data = data + ((data[0] & 0x0F) * 4) + ((data[20] & 0xF0) >> 4) * 4;
    const char *ptr = strstr((const char *) http_data, "Host: ");
    
    if (ptr) {
        char host[256];
        sscanf(ptr, "Host: %255s", host);
        
        bool found = blocked_sites.find(host) != blocked_sites.end();
        
        if (found) {
            const char *method = (const char *)http_data;
            std::cout << "Blocked " << method << " request to: " << host << std::endl;
            return 1;
        }
    }
    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    unsigned char *packet_data;
    u_int32_t id = extract_packet_info(nfa, &packet_data);

    if (blocked_site(packet_data)) {
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <site list file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!load_blocked_sites(argv[1])) {
        exit(EXIT_FAILURE);
    }

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("Starting packet filtering...\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(EXIT_FAILURE);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        nfq_close(h);
        exit(EXIT_FAILURE);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        nfq_close(h);
        exit(EXIT_FAILURE);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        nfq_close(h);
        exit(EXIT_FAILURE);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        exit(EXIT_FAILURE);
    }

    fd = nfq_fd(h);

    for (;;) {
        rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("Warning: losing packets!\n");
            continue;
        }
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    exit(0);
}
