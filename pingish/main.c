//
//  main.c
//  pingish
//
//  Created by Steve Loughran on 25/12/2017.
//

// see https://github.com/hayderimran7/advanced-socket-programming/blob/master/ping.c

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>

#define PACKET_SIZE     4096
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  4
#define RX_BUF_SIZE 50 * 1024

#define PING_OUTSTANDING 0
#define PING_SUCCESS 1
#define PING_FAIL 2
#define PING_TIMEOUT 3
#define PING_MISMATCH 4
#define PING_PACKET_TOO_SMALL 5



char sendpacket[PACKET_SIZE];
struct icmp* icmpSendPacket = (struct icmp*)sendpacket;

char recvpacket[PACKET_SIZE];
struct icmp* icmpRecvPacket = (struct icmp*)recvpacket;

int sockfd = 0;
int datalen = 56;

int nsend = 0;
int nreceived = 0;

struct sockaddr_in dest_addr;

pid_t pid;

struct sockaddr_in from;

typedef struct timeval timestamp;
timestamp tvrecv;

/* A ping */
typedef struct {
  int status;
  int seq;
  int len;
  struct in_addr dest_addr;
  timestamp sent;
  timestamp received;
  double rtt;
  int ttl;
  char *text;
} ping_t;

timestamp tvrecv;

// forward declarations

void statistics(int signo);

unsigned short cal_chksum(unsigned short *addr, int len);

//int build_packet(int packet_id);

//void send_packet(void);

//void recv_packet(void);

//int unpack(char *buf, long len);


int quit(int code, const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(code);
  return code;
}

int pexit(int code, const char *msg) {
  perror(msg);
  exit(code);
  return code;
}

/*
 subtract time.

 */

void tv_sub(timestamp *time, timestamp *diff) {

  if ((time->tv_usec -= diff->tv_usec) < 0)  {
    --time->tv_sec;
    time->tv_usec += 1000000;
  }
  time->tv_sec -= diff->tv_sec;
}


void shutdown_app(int code) {
  if (sockfd != 0) {
    close(sockfd);
    sockfd = 0;
  }
  exit(code);
}

/*
 Callback on a signal.
 Print some stats to stderr; then exit
 */
void statistics(int signo) {
  fprintf(stderr, "\n%d packets transmitted, %d received , %d%% lost\n",
          nsend,
         nreceived,
          (nsend - nreceived) / nsend * 100);
  shutdown_app(0);
}


/* Calculate the checksum. */
unsigned short cal_chksum(unsigned short *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;
  while (nleft > 1)   {
    sum +=  *w++;
    nleft -= 2;
  }

  if (nleft == 1)  {
    *(unsigned char*)(&answer) = *(unsigned char*)w;
    sum += answer;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

/*
 Build a packet in icmpSendPacket.
 packet_id: id to use in sequence ID.
 */

int build_packet(int packet_id, timestamp* now)
{
  int packsize;
  timestamp *tval;
  icmpSendPacket->icmp_type = ICMP_ECHO;
  icmpSendPacket->icmp_code = 0;
  icmpSendPacket->icmp_cksum = 0;
  icmpSendPacket->icmp_seq = packet_id;
  icmpSendPacket->icmp_id = pid;
  packsize = 8 + datalen;
  tval = (timestamp*)icmpSendPacket->icmp_data;
  *tval = *now;
  icmpSendPacket->icmp_cksum = cal_chksum((unsigned short*)icmpSendPacket, packsize);
  return packsize;
}

/*
 Send a packet
  ping: ping struct to summarise the request
  seq: sequence ID
 */
int send_packet(ping_t *ping, int seq)
{
  int packetsize;
  timestamp now;
  // ping_t *ping = malloc(sizeof(ping_t));
  memset(ping, 0, sizeof(ping_t));
  gettimeofday(&now, NULL);
  packetsize = build_packet(nsend, &now);
  if (sendto(sockfd, sendpacket, packetsize, 0,
             (struct sockaddr*) &dest_addr, sizeof(dest_addr)) < 0) {
    perror("sendto error");
    return 0;
  } else {
    fprintf(stderr, "sent packet %d\n", nsend);
    fflush(stderr);
    ping->sent = now;
    ping->status = PING_OUTSTANDING;
    ping->seq = seq;
    ping->text = NULL;
    ping->len = packetsize;
    nsend++;
    return 1;
  }
}


void flush() {
  fflush(stdout);
}

void print_header() {
  printf("\"outcome\",  \"sequence\", \"length\", \"dest\",\"ttl\", \"rtt\", \"text\"\n");
  fflush(stdout);
}

void print_packet(ping_t *ping) {
  printf("%d, %d, %d, \"%s\", %d, %0.3f, \"%s\"\n",
         ping->status,
         ping->seq,
         ping->len,
         (ping->dest_addr.s_addr
           ? inet_ntoa(ping->dest_addr)
           : ""),
         ping->ttl,
         ping->rtt,
         ping->text);
}

ping_t *received_ping(ping_t *ping,
              int status,
              int seq,
              int len,
              struct in_addr *dest_addr,
              timestamp *sent,
              int ttl,
              double rtt,
              char *text) {
  memset(ping, 0, sizeof(ping_t));
  ping->status = status;
  ping->seq = seq;
  if(dest_addr) ping->dest_addr = *dest_addr;
  if (sent) ping->sent = *sent;
  ping->ttl = ttl;
  ping->rtt = rtt;
  ping->text = text;
  return ping;
}

int unpack(char *buf, long len, ping_t *ping, timestamp* now) {

  int iphdrlen;
  struct ip *ip;
  struct icmp *icmp;
  timestamp *tvsend;
  double rtt;
  ip = (struct ip*)buf;
  iphdrlen = ip->ip_hl << 2;
  icmp = (struct icmp*)(buf + iphdrlen);
  len -= iphdrlen;
  int rv = -1;
  if (len < 8) {
    fprintf(stderr, "ICMP packets length less than 8: %ld\n", len);
/*
 printf("%d, %d, \"\", 0, 0, 0, \"packet too small\"\n",
           PING_PACKET_TOO_SMALL,
           (int)len);
 */
    received_ping(ping, PING_PACKET_TOO_SMALL, 0, 0, NULL, NULL, 0, 0, "Packet too short");
  } else if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))  {
    tvsend = (timestamp*)icmp->icmp_data;
    tv_sub(&tvrecv, tvsend);
    rtt = tvrecv.tv_sec * 1000+tvrecv.tv_usec / 1000;
    fprintf(stderr,
            "%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n",
            (int)len,
            inet_ntoa(from.sin_addr),
            icmp->icmp_seq,
            ip->ip_ttl,
            rtt);
    // Good value
    // success, length, from, sequence, ttl, rtt
    /*
    printf("%d, %d, \"%s\", %u, %d, %0.3f, \"\"\n",
           PING_SUCCESS,
           icmp->icmp_id,
           (int)len,
           &from.sin_addr,
           icmp->icmp_seq,
           ip->ip_ttl,
           rtt);
     */
    received_ping(ping,
                  PING_SUCCESS,
                  icmp->icmp_seq,
                  (int)len,
                  &from.sin_addr,
                  tvsend,
                  ip->ip_ttl,
                  rtt,
                  "");
    rv = 0;
  } else {
/*
 printf("%d, %d, \"%s\", %u, 0, 0, \"wrong packet type/id\"\n",
           PING_MISMATCH,
           (int)len,
           inet_ntoa(from.sin_addr),
           icmp->icmp_seq);
 */
    received_ping(ping,
                  PING_MISMATCH,
                  icmp->icmp_seq,
                  (int)len,
                  &from.sin_addr,
                  NULL,
                  0,
                  0,
                  "Wrong packet");
  }
  return rv;
}


int recv_packet(ping_t *ping) {
  ssize_t n;
  socklen_t fromlen;
  extern int errno;

  fromlen = sizeof(from);

  alarm(MAX_WAIT_TIME);
  if ((n = recvfrom(sockfd,
                    recvpacket,
                    sizeof(recvpacket), 0,
                    (struct sockaddr*) &from, &fromlen)) < 0)
  {
    if (errno == EINTR) {
      return 0;
    }
    perror("recvfrom error");
    return 0;
  }
  gettimeofday(&tvrecv, NULL);
  unpack(recvpacket, n, ping, &tvrecv);
  nreceived++;
  return 1;

}


int main(int argc, const char * argv[]) {
//  struct hostent *host;
  struct protoent *protocol;
//  unsigned long inaddr = 0l;
//  int waittime = 10 * 60 * 1000;
  int size = RX_BUF_SIZE;

  if (argc != 2) {
    return quit(1, "Usage: pingish: <ipaddr>");
  }
  protocol = getprotobyname("icmp");
  assert(protocol != NULL);

  if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)  {
    pexit(1, "socket error");
  }
  pid = getpid();
  print_header();
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

  bzero(&dest_addr, sizeof(dest_addr));

  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
  if (INADDR_NONE == dest_addr.sin_addr.s_addr) {
    return quit(-1, "Unknown address");
  }

  signal(SIGALRM, statistics);
  ping_t ping, rx;
  if (send_packet(&ping, 1)) {
    if (recv_packet(&rx)) {
      print_packet(&rx);
      flush();
    }
  }
  printf("done\n");
  statistics(SIGALRM);
  return 0;

}
