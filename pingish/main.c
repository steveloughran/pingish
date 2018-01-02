//
//  main.c
//  pingish
//
//  Created by Steve Loughran on 25/12/2017.
//

// see https://github.com/hayderimran7/advanced-socket-programming/blob/master/ping.c

//#define _POSIX_C_SOURCE 200112L

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


/** size of a packet */
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
#define PING_IO_FAILURE 6
#define PING_INTERRUPTED 7
#define PING_SEND_FAIL 8


char sendpacket[PACKET_SIZE];
struct icmp* icmpSendPacket = (struct icmp*)sendpacket;

char recvpacket[PACKET_SIZE];
struct icmp* icmpRecvPacket = (struct icmp*)recvpacket;

/**
 Socket to send to
 */
int sockfd = 0;
int datalen = 56;

/** Count of sent packets (or attempted to be sent). */
int sent_packets = 0;

/** Count of valid packets received. */
int successfully_received_packets = 0;

/**
 Process ID, used in echo header.
 */
pid_t pid;

/** Origin for records. */
const char * origin;

/**
 Socket address where the packets are sent from.
 */
struct sockaddr_in from;

/**
 Destination socket address
 */
struct sockaddr_in dest_addr;

typedef struct timeval timestamp;

/** Time the last packet was received. */
timestamp tvrecv;

/** shared error text. */
//char *ping_error_text = malloc(256 * sizeof(char));

#define ERROR_TEXTLEN 1024
char* ping_error_text;

/* A ping structure. */
typedef struct {
  int status;
  int seq;
  int len;
  struct in_addr dest_addr;
  timestamp sent;
  timestamp received;
  double rtt;
  int ttl;
  int code1;
  int code2;
  const char *text;
} ping_t;

/** time a packet was received. */
timestamp tvrecv;

// forward declarations

void signalled(int signo);

/**
 Log the text to stderr.
 @param txt text to print
 */
void log_debug(char *txt) {
  fprintf(stderr, "%s\n", txt);
}

/**
 Close the socket and shut down.
 @param code exit code
 */
void shutdown_app(int code) {
  if (sockfd != 0) {
    close(sockfd);
    sockfd = 0;
  }
  exit(code);
}

/**
 Print the message, shut down the app.
 */
int quit(int code, const char *msg) {
  fprintf(stderr, "%s\n", msg);
  shutdown_app(code);
  return code;
}

/**
 Print the system error, then a message, then exit.
 @param code exit code
 @param msg string for perror()
 */
void pexit(int code, const char *msg) {
  perror(msg);
  exit(code);
}

/**
 subtract time, leaving the source time with the difference (i.e. this is destructive).
 @param time intial/updated time.
 @param diff difference; value subtracted
 @return difference in millis
 */

long subtract_times(timestamp *time, const timestamp *diff) {

  if ((time->tv_usec -= diff->tv_usec) < 0)  {
    --time->tv_sec;
    time->tv_usec += 1000000;
  }
  time->tv_sec -= diff->tv_sec;
  return time->tv_sec * 1000 + time->tv_usec / 1000;
}


/**
 Print the current statistics.
 */
void print_stats() {
  int lost = sent_packets - successfully_received_packets;
  fprintf(stderr, "\n%d packets transmitted, %d received , %d%% failed\n",
          sent_packets,
         successfully_received_packets,
          lost  * 100 / sent_packets);
}

/**
 Callback on a signal.
 Print some stats to stderr; then exit
 @param signo received
 */
void signalled(int signo) {
  fprintf(stderr, "\nreceived signal %d\n", signo);
  print_stats();
  shutdown_app(0);
}


/**
 Calculate the checksum.
 @param addr buffer address
 @param len length of buffer
 @return the checksum
 */
unsigned short cal_chksum(unsigned short *addr, int len) {
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;
  while (nleft > 1)   {
    sum +=  *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(unsigned char*)(&answer) = *(unsigned char*)w;
    sum += answer;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

/**
 Build a packet in icmpSendPacket.
 @param packet_id id to use in sequence ID
 @param now timestamp
 @return packet size
 */

int build_packet(int packet_id, const timestamp* now) {
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

/**
 Send a packet.
  @param ping ping struct to summarise the request
  @param seq sequence ID
  @return error code from sendto.
 */
int send_packet(ping_t *ping, int seq) {
  int packetsize;
  timestamp now;
  // ping_t *ping = malloc(sizeof(ping_t));
  memset(ping, 0, sizeof(ping_t));
  gettimeofday(&now, NULL);
  packetsize = build_packet(sent_packets, &now);
  sent_packets++;
  errno = 0;
  ssize_t sent = sendto(sockfd, sendpacket, packetsize, 0,
                    (struct sockaddr*) &dest_addr, sizeof(dest_addr));

  ping->sent = now;
  ping->seq = seq;
  ping->text = NULL;
  ping->len = packetsize;

  if (sent < 0) {
    ping->status = PING_SEND_FAIL;
    ping->code1 = errno;

    // this is using a shared buffer here, but it is that or switch to always freeing the ref
    char *etext = strerror(errno);
    strncpy(ping_error_text, etext, ERROR_TEXTLEN);
    ping->text =ping_error_text;
    //fprintf(stderr, "Error on send exit code %d text %s\n", errno, ping_error_text);
    //perror("sending");


    return -1;
  } else {
//    fprintf(stderr, "sent packet %d\n", sent_packets);
  //  fflush(stderr);
    ping->status = PING_OUTSTANDING;
    ping->seq = seq;
    return 0;
  }
}

/**
 Flush stdout.
 */
void flush() {
  fflush(stdout);
}

/**
 Print the csv header to stdout.
 */
void print_header() {
  printf("timestamp, date, outcome, sequence, origin, dest, length, ttl, rtt, code1, code2, text\n");
  fflush(stdout);
}

/**
 Print a packet.
 Does not flush stdout
 @param ping ping result to print
 */
void print_packet(const ping_t *ping) {

  char printtime[256];
  char *ttext;
  if(ping->sent.tv_sec > 0) {
    // darwin not consistent w posix here.
    time_t t = (time_t)ping->sent.tv_sec;
    strftime(printtime, 256, "%Y-%m-%d %H:%M:%S", localtime(&t));
    ttext = printtime;
  }else {
    ttext = "";
  }

  printf("%ld, \"%s\", %d, %d, \"%s\", \"%s\", %d, %d, %0.3f, %d, %d, \"%s\"\n",
         ping->sent.tv_sec,
         ttext,
         ping->status,
         ping->seq,
         origin,
         (ping->dest_addr.s_addr
           ? inet_ntoa(ping->dest_addr)
           : ""),
         ping->len,
         ping->ttl,
         ping->rtt,
         ping->code1,
         ping->code2,
         ping->text);
}

/**
 Handle a received ping.
 @return the status passed in.
 */
int received_ping(ping_t *rx_ping,
              int status,
              int seq,
              int len,
              const struct in_addr *dest_addr,
              const timestamp *sent,
              const timestamp *received,
              int ttl,
              double rtt,
              int code1,
              const char *text) {
  memset(rx_ping, 0, sizeof(ping_t));
  rx_ping->status = status;
  rx_ping->seq = seq;
  if (dest_addr) rx_ping->dest_addr = *dest_addr;
  if (sent) rx_ping->sent = *sent;
  rx_ping->received = *received;
  rx_ping->ttl = ttl;
  rx_ping->rtt = rtt;
  rx_ping->text = text;
  rx_ping->code1 = code1;
  return status;
}

/**
 Does the ping status code indicate success?
 @param ping to examine
 */
int is_success(const ping_t *ping) {
  return ping->status == PING_SUCCESS;
}

/*
 Unpack the packet into a ping struct.
 @return the ping status field.
 */
int unpack(char *buf, long len, ping_t *rx_ping, const ping_t *tx_ping, timestamp* now) {
  int iphdrlen;
  struct ip *ip;
  struct icmp *icmp;
  timestamp *tvsend;
  timestamp now_t = *now;
  double rtt;
  ip = (struct ip*)buf;
  iphdrlen = ip->ip_hl << 2;
  icmp = (struct icmp*)(buf + iphdrlen);
  len -= iphdrlen;
  if (len < 8) {
    fprintf(stderr, "ICMP packets length less than 8: %ld\n", len);
    return received_ping(rx_ping,
                         PING_PACKET_TOO_SMALL,
                         0,
                         (int)len,
                         &from.sin_addr,
                         NULL,
                         now,
                         0,
                         0,
                         0,
                         "Packet too short");
  } else if (icmp->icmp_type == ICMP_ECHOREPLY)  {
    tvsend = (timestamp*)icmp->icmp_data;
    rtt = subtract_times(&now_t, tvsend);
    // Good packet type
    // success, length, from, sequence, ttl, rtt
    int expectedPid = (icmp->icmp_id == pid);
    return received_ping(rx_ping,
                  expectedPid ? PING_SUCCESS : PING_MISMATCH,
                  icmp->icmp_seq,
                  (int)len,
                  &from.sin_addr,
                  tvsend,
                  now,
                  ip->ip_ttl,
                  rtt,
                  expectedPid ? 0 : icmp->icmp_id,
                  expectedPid ? "" : "Wrong icmp_id");

  } else {
    received_ping(rx_ping,
                  PING_MISMATCH,
                  icmp->icmp_seq,
                  (int)len,
                  &from.sin_addr,
                  &(tx_ping->sent),
                  now,
                  0,
                  subtract_times(&now_t, &(tx_ping->sent)),
                  icmp->icmp_type,
                  "Wrong packet icmp_type");
    rx_ping->code2 = icmp->icmp_code;
    return rx_ping->status;
  }
}

// see http://www.gnu.org/software/libc/manual/html_node/Waiting-for-I_002fO.html#Waiting-for-I_002fO
/**
 Wait for a packet to be received
 @param rx_ping the ping to fill in.
 @param tx_ping sent the original sent packet
 @return the ping status
 */
int recv_packet(ping_t *rx_ping, const ping_t *tx_ping, int wait_time_s) {
  ssize_t n;
  socklen_t fromlen;
  extern int errno;
  fd_set selection;
  timestamp timeout;
  timestamp select_duration;

  /* Initialize the file descriptor set. */
  FD_ZERO(&selection);
  FD_SET(sockfd, &selection);

  /* Initialize the timeout data structure. */
  timeout.tv_sec = wait_time_s;
  timeout.tv_usec = 0;
 // alarm(MAX_WAIT_TIME);

  /* now await the packet */
//  log_debug("waiting");
  int select_outcome = select(FD_SETSIZE,
          &selection,
          NULL,
          NULL,
          &timeout);
  gettimeofday(&tvrecv, NULL);
  select_duration = tvrecv;
  long interval = subtract_times(&select_duration, &tx_ping->sent);


  if (select_outcome == 0) {
    // timeout
//    log_debug("timeout");
    return received_ping(rx_ping,
                         PING_TIMEOUT,
                         0,
                         0,
                         NULL,
                         &tx_ping->sent, &tvrecv,
                         0,
                         interval,
                         wait_time_s,
                         "Timeout");
  } else if (select_outcome == -1) {
    perror("select failure");
    return received_ping(rx_ping,
                         PING_IO_FAILURE,
                         0,
                         0,
                         NULL,
                         &tx_ping->sent,
                         &tvrecv,
                         0,
                         interval,
                         errno,
                         "select failure");
  }
  fromlen = sizeof(from);

  if ((n = recvfrom(sockfd,
                    recvpacket,
                    sizeof(recvpacket), 0,
                    (struct sockaddr*) &from, &fromlen)) < 0)
  {
    if (errno == EINTR) {
      log_debug("interrupted");
      return PING_INTERRUPTED;
    }
    perror("recvfrom error");
    return PING_IO_FAILURE;
  }
  gettimeofday(&tvrecv, NULL);
  return unpack(recvpacket, n, rx_ping, tx_ping, &tvrecv);
}

/**
 Execute a single ping send/receive sequence.
 @param wait wait time
 @param seq_no sequence number for the packet
 @return a new ping
 */
ping_t ping_once(int wait, int seq_no) {
  ping_t received;
  ping_t sent;
  ping_t result;
  int outcome;

  if (0 == send_packet(&sent, seq_no)) {
    outcome = recv_packet(&received, &sent, wait);
    result = received;
  } else {
    outcome = sent.status;
    result = sent;
  }
  switch (outcome) {
    case PING_INTERRUPTED:
    case PING_IO_FAILURE:
      fprintf(stderr, "outcome=%d", outcome);
      break;

    case PING_SUCCESS:
    default:
      print_packet(&result);
      flush();
      break;
    }
  return result;
}

/**
 Entry point.
 */
int main(int argc, const char * argv[]) {
//  struct hostent *host;
  struct protoent *protocol;
//  unsigned long inaddr = 0l;
//  int waittime = 10 * 60 * 1000;
  int size = RX_BUF_SIZE;

  if (argc != 3) {
    return quit(1, "Usage: pingish: <origin> <ipaddr>");
  }
  origin = argv[1];
  // destination hostname or IPAddr
  const char *dest = argv[2];

  ping_error_text = malloc(ERROR_TEXTLEN);
  strcpy(ping_error_text, "unset");

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
  in_addr_t dest_s_addr = inet_addr(dest);

  if (INADDR_NONE == dest_s_addr) {
    // look up hostname. Requires DNS to be up or /etc/hosts to have the destination
    struct hostent *desthost = gethostbyname(dest);
    if (!desthost) {
      herror("gethostbyname");
      return quit(1, "hostname lookup failure");
    }
    memcpy((char*) &dest_addr.sin_addr, desthost->h_addr, desthost->h_length);

  } else {
    dest_addr.sin_addr.s_addr = dest_s_addr;
  }

  signal(SIGALRM, signalled);
  signal(SIGINT, signalled);
  signal(SIGINT, signalled);
  int wait = 2;
  int sleeptime = 2;
  int total = 2048;
  int seq_no = 1;
  do {
    ping_t received = ping_once(wait, seq_no++);
    if (is_success(&received)) {
      successfully_received_packets++;
    }
    if (!(seq_no % 15)) {
      print_stats();
    }
    if (total--) {
      sleep(sleeptime);
    }
  } while (total);
  printf("done\n %d", total);
  print_stats();
  return 0;
}
