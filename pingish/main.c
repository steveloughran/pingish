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
#define MAX_NO_PACKETS  1
#define RX_BUF_SIZE 50 * 1024


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

struct timeval tvrecv;

struct sockaddr_in from;

struct timeval tvrecv;

void statistics(int signo);

unsigned short cal_chksum(unsigned short *addr, int len);

int pack(int pack_no);

void send_packet(void);

void recv_packet(void);

int unpack(char *buf, long len);


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

void tv_sub(struct timeval *out, struct timeval *in) {

  if ((out->tv_usec -= in->tv_usec) < 0)  {
    --out->tv_sec;
    out->tv_usec += 1000000;
  }
  out->tv_sec -= in->tv_sec;
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
  fprintf(stderr, "\n%d packets transmitted, %d received , %%%d lost\n",
          nsend,
         nreceived,
          (nsend - nreceived) / nsend * 100);
  shutdown_app(0);
}


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
  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}


int pack(int pack_no)
{
  int packsize;
  struct timeval *tval;
  icmpSendPacket->icmp_type = ICMP_ECHO;
  icmpSendPacket->icmp_code = 0;
  icmpSendPacket->icmp_cksum = 0;
  icmpSendPacket->icmp_seq = pack_no;
  icmpSendPacket->icmp_id = pid;
  packsize = 8 + datalen;
  tval = (struct timeval*)icmpSendPacket->icmp_data;
  gettimeofday(tval, NULL);
  icmpSendPacket->icmp_cksum = cal_chksum((unsigned short*)icmpSendPacket, packsize);
  return packsize;
}





void send_packet()
{

  int packetsize;

  while (nsend < MAX_NO_PACKETS) {
    nsend++;
    packetsize = pack(nsend);
    if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr*)
               &dest_addr, sizeof(dest_addr)) < 0) {
      perror("sendto error");
      continue;
    }
    sleep(1);

  }

}





void recv_packet()

{
  ssize_t n;
  socklen_t fromlen;
  extern int errno;

  signal(SIGALRM, statistics);
  fromlen = sizeof(from);

  while (nreceived < nsend) {

    alarm(MAX_WAIT_TIME);
    if ((n = recvfrom(sockfd,
                      recvpacket,
                      sizeof(recvpacket), 0,
                      (struct sockaddr*) &from, &fromlen)) < 0)

    {

      if (errno == EINTR) {
        continue;
      }

      perror("recvfrom error");

      continue;

    }
    gettimeofday(&tvrecv, NULL);

    if (unpack(recvpacket, n) ==  - 1) continue;

    nreceived++;

  }

}





int unpack(char *buf, long len) {

  int iphdrlen;

  struct ip *ip;

  struct icmp *icmp;

  struct timeval *tvsend;

  double rtt;

  ip = (struct ip*)buf;

  iphdrlen = ip->ip_hl << 2;

  icmp = (struct icmp*)(buf + iphdrlen);

  len -= iphdrlen;

  if (len < 8)  {
    fprintf(stderr, "ICMP packets length less than 8: %ld\n", len);
    return  - 1;
  }

  if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))  {

    tvsend = (struct timeval*)icmp->icmp_data;

    tv_sub(&tvrecv, tvsend);

    rtt = tvrecv.tv_sec * 1000+tvrecv.tv_usec / 1000;
    fprintf(stderr,
            "%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n",
            (int)len,
           inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
    // TODO? Good value
    return 0;
  }  else {

    return  - 1;
  }
}



int main(int argc, const char * argv[]) {
  struct hostent *host;
  struct protoent *protocol;
  unsigned long inaddr = 0l;
  int waittime = 10 * 60 * 1000;
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

  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

  bzero(&dest_addr, sizeof(dest_addr));

  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
  if (INADDR_NONE == dest_addr.sin_addr.s_addr) {
    return quit(-1, "Unknown address");
  }

  send_packet();
  recv_packet();
  statistics(SIGALRM);
  return 0;

}
