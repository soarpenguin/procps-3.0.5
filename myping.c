#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define PACKET_SIZE     4096
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  3
#ifndef MAXHOSTNAMELEN 
#define MAXHOSTNAMELEN 64
#endif

char sendpacket[PACKET_SIZE]; // store the send package 
char recvpacket[PACKET_SIZE]; // stroe the recevice package
int sockfd, datalen = 56;
int nsend = 0, nreceived = 0;
struct sockaddr_in dest_addr; // store the destination address info
struct sockaddr_in from;// store the localhost address info
struct timeval tvrecv;	// store the time info when a package received
pid_t pid;				// store the process id of main program
int options;			// store option from the command line arguments
char *hostname = NULL;	// store the host name(from the command line)
char hnamebuf[MAXHOSTNAMELEN];
char *prgname = NULL;   // store the program name

char usage[] = 
"usage:%s [-h?dr] [--help] [(hostname/IP address) [count]]\n";

void statistics(int signo);
unsigned short cal_chksum(unsigned short *addr, int len);
int pack(int pack_no);
int unpack(char *buf, int len);
void send_packet(void);
void recv_packet(void);
void tv_sub(struct timeval *out, struct timeval *in);

void 
statistics(int signo)
{     
	putchar('\n');
	fflush(stdout);
	printf("\n-----------%s PING statistics-----------\n", hostname);
	if(nsend > 0)
		printf("%d packets transmitted, %d received , %2.0f%%  lost\n",
				nsend,nreceived,(float)(nsend-nreceived)/nsend*100);
	else
		printf("have problem in send packets!\n");
	
	if(sockfd)
		close(sockfd);
	exit(0);
}

/*
 * 校验和算法
 */
unsigned short 
cal_chksum(unsigned short *addr,int len)
{   
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

   /*
	* 把ICMP报头二进制数据以2字节为单位累加起来
	*/
	while(nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/*
	 * 若ICMP报头为奇数个字节，会剩下最后一字节。
	 * 把最后一个字节视为一个2字节数据的高
	 * 字节，这个2字节数据的低字节为0，继续累加
	 */
	if( nleft == 1) {   
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}

/*
 * 设置ICMP报头
 */
int 
pack(int pack_no)
{       
	int packsize;
	struct icmp *icmp;
	struct timeval *tval;

	icmp = (struct icmp*)sendpacket;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = pack_no;
	icmp->icmp_id = pid;
	packsize = 8 + datalen;
	tval = (struct timeval *)icmp -> icmp_data;
	gettimeofday(tval, NULL);    /*记录发送时间*/
	/*
	 * 校验算法
	 */
	icmp->icmp_cksum = cal_chksum( (unsigned short *)icmp, packsize); 
	return packsize;
}

/*
 * 剥去ICMP报头
 */
int 
unpack(char *buf,int len)
{       
	int iphdrlen;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;
	double rtt;

	ip = (struct ip *)buf;
	//求ip报头长度,即ip报头的长度标志乘4,
	//头长度指明头中包含的4字节字的个数。
	//可接受的最小值是5，最大值是15

	iphdrlen = ip->ip_hl << 2;    
	icmp = (struct icmp *)(buf + iphdrlen);  /*越过ip报头,指向ICMP报头*/
	len -= iphdrlen;            /*ICMP报头及ICMP数据报的总长度*/
	
	/*
	 * 小于ICMP报头长度则不合理
	 */
	if(len < 8) {       
		printf("ICMP packets\'s length is less than 8\n");
		return -1;
	}

	/*
	 * 确保所接收的是先前所发的的ICMP数据包的回应
	 */
	if( (icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid) ) {       
		tvsend = (struct timeval *)icmp->icmp_data;
		tv_sub(&tvrecv,tvsend);  /*接收和发送的时间差*/
		rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;  /*以毫秒为单位计算rtt*/
		/*显示相关信息*/
		printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n",
			len, inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
	}
	else   
		return -1;

	return 0;
}

/*
 *发送ICMP报文
 */
void 
send_packet()
{       
	int packetsize;
       
	nsend++;
	packetsize = pack(nsend); /*设置ICMP报头*/
	
	//sendpacket为要发送的内容，由pack()函数设定，dest_addr是目的地址，
	if( sendto(sockfd, sendpacket, packetsize, 0,
			  (struct sockaddr *)&dest_addr, sizeof(dest_addr) ) < 0  ) {
		perror("sendto error");
		nsend--;
	}
	sleep(1); /*每隔一秒发送一个ICMP报文*/
}

/*
 * 接收ICMP报文
 */
void 
recv_packet()
{      
	unsigned int n,fromlen;
	extern int errno;

	signal(SIGALRM, statistics);
	fromlen = sizeof(from);
	while(nreceived < nsend) {       

		//alarm()用来设置信号SIGALRM在经过参数seconds指定的秒数后传送给目前的进程 
		//alarm(MAX_WAIT_TIME);
		if( (n=recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0,
						(struct sockaddr *)&from, &fromlen)) < 0) {
			if(errno == EINTR)   
				continue;
			perror("recvfrom error");
			continue;
		}

		gettimeofday(&tvrecv, NULL);  /*记录接收时间*/
		if(unpack(recvpacket,n) == -1)
			continue;
		nreceived++;
	}

}

/*
 * 通过两个timeval结构相减计算时间差
 */
void 
tv_sub(struct timeval *out,struct timeval *in)
{       
	if( (out->tv_usec -= in->tv_usec) < 0) {       
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

/*
 * 处理命令行参数,以位模式保存与options
 */
int
process_command_line_arguments(int *argc, char **argv)
{
	char **av = argv;
	int count = *argc;

	(*argc)--, av++;
	while((*argc > 0) && ('-' == *av[0])) {
		// for case of command option like '--xxx'
		// 'xxx' treat as a option in program 
		if('-' == *(av[0]+1)) {
			char *temp = av[0];
			if(!strcmp(temp + 2, "help")) {
				printf(usage, prgname);
				exit(0);
			} else {
				printf("Bad arguments in command line!\n");
				printf(usage, prgname);
				exit(1);
			} 
		}
		// for case of '-a' or '-ax', 
		// every letter treat as a option 
		while(*++av[0]) switch(*av[0]) {
				case 'h':
				case '?':
					printf(usage, prgname);
					exit(0);
				case 'd':
					options |= SO_DEBUG;
					//printf("%c\n", *av[0]);
					break;
				case 'r':
					options |= SO_DONTROUTE;
					//printf("%c\n", *av[0]);
					break;
				default:
					fprintf(stderr, "Bad arguments in command line. \n");
					exit(1);
		}
		(*argc)--, av++;
	}

	return (count - *argc);
}

/*
 *
 *			main
 *
 */
 
int 
main(int argc,char *argv[])
{       
	struct hostent *host;
	struct protoent *protocol;
	unsigned long inaddr=0l;
	//int waittime = MAX_WAIT_TIME;    //#define MAX_WAIT_TIME   5
	int size = 50 * 1024;
	int cmd_line_opts_start = 1;
	unsigned int pgcount = 0;
	int on = 1;

	prgname = strrchr(argv[0], '/');
	if(prgname)
		prgname++;
	else
		prgname = argv[0];

	cmd_line_opts_start = process_command_line_arguments(&argc, argv);

	if(argc < 1 || argc > 2) {       
		printf(usage, prgname);
		exit(1);
	}
	
	if(1 == argc) {
		hostname = argv[cmd_line_opts_start];
	} else {
		hostname = argv[cmd_line_opts_start];
		pgcount = (unsigned int)strtol(argv[++cmd_line_opts_start], NULL, 10);
	}

	//getprotobyname("icmp")返回对应于给定协议名的包含名字和协议号的protoent结构指针。
	if( (protocol = getprotobyname("icmp") ) == NULL) {       
		perror("getprotobyname");
		exit(1);
	}

	/*
	 * 生成使用ICMP的原始套接字,这种套接字只有root才能生成
	 */
	if( (sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto) )<0) {       
		perror("socket error");
		exit(1);
	}

	/*
	 * 回收root权限,设置当前用户权限
	 */
	setuid(getuid());

	/*
	 * 扩大套接字接收缓冲区到50K这样做主要为了减小接收缓冲区溢出的
	 * 的可能性,若无意中ping一个广播地址或多播地址,将会引来大量应答
	 */
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size) );
	if(options & SO_DEBUG) {
		printf(".....debug on.....\n");
		setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, &on, sizeof(on));
	}
	/*
	 * SO_DONTROUTE设置项的意思是发送ICMP数据包时不通过路由表
	 * 网关当主机与目标机器直接相连时可以直接发送,否则将发生
	 * 网络不可达的错误.
	 */
	if(options & SO_DONTROUTE) {
		setsockopt(sockfd, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on));
	}

	bzero(&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;

	/*
	 * 判断是主机名还是ip地址
	 * inet_addr:
	 *	Convert Internet host address from num-and-dots(172.0.0.1)
	 *	into binary data in network byte order
	 */
	if((inaddr = inet_addr(hostname)) == INADDR_NONE) {
		/*是主机名*/
		if((host = gethostbyname(hostname)) == NULL) {       
			perror("gethostbyname error");
			exit(1);
		}
		memcpy((char *)&dest_addr.sin_addr, host->h_addr, host->h_length);
		strncpy(hnamebuf, host->h_name, MAXHOSTNAMELEN-1);
		hostname = hnamebuf;
	} else {    
		/*是ip地址*/
		//struct in_addr ipv4addr;
		//host = gethostbyaddr(&ipv4addr, sizeof(ipv4addr), AF_INET);
		//hostname = host->h_name;
		//strncpy(hnamebuf, hostname, MAXHOSTNAMELEN-1);	
		dest_addr.sin_addr.s_addr = inet_addr(hostname);
	}

	/*
	 * 获取main的进程id,用于设置ICMP的标志符
	 */
	pid = getpid();
	printf("PING %s(%s): %d bytes data in ICMP packets.\n",hostname,
					inet_ntoa(dest_addr.sin_addr),datalen);
	signal(SIGINT, statistics);
	signal(SIGALRM, statistics);

	for(;;) {
		send_packet();  /*发送所有ICMP报文*/
		recv_packet();  /*接收所有ICMP报文*/

		if(pgcount && nreceived >= pgcount)
			statistics(SIGALRM);
	}
	//statistics(SIGALRM); /*进行统计*/

	return 0;
}

