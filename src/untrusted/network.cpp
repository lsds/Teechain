#include <sys/epoll.h> 
#include <iostream>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "network.h"
#include "teechain.h"
#include "utils.h"

// Network connection globals
struct Connection connections[MAXCONN];

int epoll_fd = -1;
struct epoll_event event;
struct epoll_event events[MAX_EVENTS];

int connect_to_socket(std::string socket_hostname, int socket_port) {
    struct addrinfo *addr;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", socket_port); 

    if (getaddrinfo(socket_hostname.c_str(), port_str, 0, &addr) < 0) {
        error("getaddrinfo");
    }

    // loop through all the results and connect to the first we can
    struct addrinfo *p;
    int sockfd;
    for (p = addr; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, SOCK_STREAM, 0)) < 0) {
            continue;
        }
    
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
            close(sockfd);
            continue;
        }
    
        break; // if we get here, we must have connected successfully
    }

    if (p == NULL) {
        // couldn't connect to any addrinfo
        std::cout <<  "Error when connecting: " << strerror(errno) << "\n"; 
        error("connect");
    } 

    //log_debug("connect_to_socket(%s,%d)", socket_hostname.c_str(), socket_port);
    return sockfd;
}

void send_on_socket(char* msg, long msglen, int sockfd) {
    char msglenbuf[MSG_LEN_BYTES];
    long total_length = msglen + MSG_LEN_BYTES;
    memcpy(msglenbuf,  &total_length, sizeof(long));
    
    int n = write(sockfd, msglenbuf, MSG_LEN_BYTES);
    if (n < 0) {
        error("send_on_socket write message length");
    }

    n = write(sockfd, msg, msglen);
    if (n < 0) {
        error("send_on_socket write message");
    }
}

void read_from_socket(int sockfd, char* buf, long length) {
    int num_bytes = 0; // number of bytes read from response

    // read until we get packet length
    while (num_bytes < MSG_LEN_BYTES) {
        int read = recv(sockfd, &buf[num_bytes], MSG_LEN_BYTES, 0);
        if (read <= 0) {
            error("socket closed");
        }
        num_bytes += read;
    }

    // read until we get full packet
    long pktlen = *((long* ) buf);
    if (pktlen > length) {
        printf("response: %ld %ld", pktlen, length);
        error("response longer than expected!");
    }

    while (num_bytes < pktlen) {
        int read = recv(sockfd, &buf[num_bytes], pktlen - MSG_LEN_BYTES, 0);
        if (read <= 0) {
            error("socket closed");
        }
        num_bytes += read;
    }
}

