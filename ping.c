/*************************************************************************
        > File Name: ping.c
        > Author: fucang_zxx
        > Mail: fucang_zxx@163.com
        > Created Time: 2016年07月18日 星期一 17时52分32秒
 ************************************************************************/
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
/*保存已经发送包的状态值*/
typedef struct pingm_pakcet
{
	struct timeval tv_begin;/*发送的时间*/
	struct timeval tv_end;/*接收到的时间*/
	short seq;/*序列号*/
	int flag;/*1，表示已经发送但没有接收到回应包  0，表示接收到回应包*/
}pingm_pakcet;

static pingm_pakcet pingpacket[128];
static pingm_pakcet *icmp_findpacket(int seq);
static unsigned short icmp_cksum(unsigned char *data,int len);
static struct timeval icmp_tvsub(struct timeval end,struct timeval begin);
static void icmp_statistics(void);
static void icmp_pack(struct icmp *icmph,int seq,struct timeval* tv,int length);
static int icmp_unpack(char *buf,int len);
static void *icmp_recv(void *argv);
static void *icmp_send(void *argv);
static void icmp_sigint(int signo);
static void icmp_usage();

#define K 1024
#define BUFFERSIZE 72
static char send_buff[BUFFERSIZE];
static char recv_buff[2*K];

static struct sockaddr_in dest;/*目的地址*/
static int rawsock = 0;
static pid_t pid = 0;
static int alive = 0;
static short packet_send = 0;/*已经发送的数据包有多少*/
static short packet_recv = 0;

static char dest_str[80];
static struct timeval tv_begin,tv_end,tv_interval;

static void icmp_usage()
{
	printf("ping aaa.bbb.ccc.ddd\n");
}

int main(int argc,char *argv[])
{
	/*用户主机信息*/
	struct hostent *host = NULL;
	struct protoent *protocal = NULL;
	char protoname[] = "icmp";
	unsigned long inaddr = 1;
	int size = 128*K;

	if(argc < 2)
	{
		icmp_usage();
		exit(-1);
	}
	/*获取协议类型ICMP*/
	protocal = getprotobyname(protoname);
	if(protocal == NULL)
	{
		perror("getprotobyname() error\n");
		exit(-1);
	}
	/*复制目的地址字符串*/
	memcpy(dest_str,argv[1], strlen(argv[1])+1 );
	memset(pingpacket,0,sizeof(pingm_pakcet) *128);

	/*socket初始化*/
	rawsock = socket(AF_INET,SOCK_RAW,protocal->p_proto);
	if(rawsock < 0)
	{
		perror("socket error");
		return -1;
	}
	/*为了与其他进程的ping程序区别，加入pid*/
	pid = getuid();
	/*增大接收缓冲区，防止接收的包被覆盖*/
	setsockopt(rawsock,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));
	bzero(&dest,sizeof(dest));
	/*获取目的地址的IP地址*/
	dest.sin_family = AF_INET;
	inaddr = inet_addr(argv[1]);

	if(inaddr == INADDR_NONE)/*判断输入的是不是有效IP地址*/
	{
		host = gethostbyname(argv[1]);
		if(host == NULL)
		{
			perror("gethostbyname error");
			exit(-1);
		}
		memcpy((char *)&dest.sin_addr,host->h_addr,host->h_length);
	}
	else
	{
		memcpy((char *)&dest.sin_addr,&inaddr,sizeof(inaddr));
	}

	/*打印提示*/
	inaddr = dest.sin_addr.s_addr;
	printf("ping %s(%ld.%ld.%ld.%ld) 56(84) bytes of data.\n",dest_str,(inaddr&0x000000FF)>>0,(inaddr&0x0000FF00)>>8,(inaddr&0x00FF0000)>>16,(inaddr&0xFF000000)>>24);

	/*截取信号SIGINT，将icmp_sigint挂接上*/
	signal(SIGINT,icmp_sigint);
	alive =1;

	pthread_t send_id,recv_id;
	int err = pthread_create(&send_id,NULL,icmp_send,NULL);
	if(err < 0)
	{
		perror("pthread_create send error");
		exit(-1);
	}

     err = pthread_create(&recv_id,NULL,icmp_recv,NULL);
	if(err < 0)
	{
		perror("pthread_create recv error");
		exit(-1);
	}

	pthread_join(send_id,NULL);
	pthread_join(recv_id,NULL);

	close(rawsock);
	icmp_statistics();

	return 0;
	
}
/*CRC16校验和计算icmp_cksum
 * 参数：  data:数据   len:数据长度		
 * 返回值： 计算结果，short类型*/

 
static unsigned short icmp_cksum(unsigned char *data,  int len)
{
	int sum = 0;
	int odd = len & 0x01;
	while(len & 0xfffe)
	{
		sum += *(unsigned short*)data;
		data += 2;
		len -= 2;
	}

	if(odd)
	{
		unsigned short tmp = ((*data)<<8)&0xff00;
		sum += tmp;
	}
	sum = (sum>>16) + (sum & 0xffff);
	sum += (sum>>16);
	return ~sum;
}

/*设置ICMP报头*/
static void icmp_pack(struct icmp *icmph,int seq,struct timeval *tv,int length)
{
	unsigned char i = 0;
	/*设置报头*/
	icmph->icmp_type = ICMP_ECHO;
	/*ICMP回显请求*/
	icmph->icmp_code = 0;
	icmph->icmp_cksum = 0;
	icmph->icmp_seq =seq;
	icmph->icmp_id = pid & 0xffff;

	for(i = 0;i < length;++i)
		icmph->icmp_data[i] = i;

	icmph->icmp_cksum = icmp_cksum((unsigned char*)icmph,length);
}
/*解压接收到的包，并打印信息*/
static int icmp_unpack(char *buf,int len)
{
	int iphdrlen;
	struct ip* ip = NULL;
	struct icmp* icmp = NULL;
	int rtt;

	ip = (struct ip*)buf;
	iphdrlen = ip->ip_hl * 4;
	icmp = (struct icmp*)(buf+iphdrlen);

	/*ICMP段的地址*/
	len -= iphdrlen;
	if(len < 8)
	{
		printf("icmp packets\'s length is less than 8\n");
		exit(-1);
	}
	if( (icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid) )
	{
		struct timeval tv_internel,tv_recv,tv_send;
		/*在发送表格中查找已经发送的包，按照seq*/
		pingm_pakcet* packet = icmp_findpacket(icmp->icmp_seq);
		if(packet == NULL)
			return -1;
		packet->flag = 0;

		tv_send = packet->tv_begin;
		/*获取本包的发送时间*/
		gettimeofday(&tv_recv,NULL);
		/*读取此时间，计算时间差*/
		tv_internel = icmp_tvsub(tv_recv,tv_send);
		rtt = tv_internel.tv_sec * 1000 + tv_internel.tv_usec/1000;

		/*打印结果，包含ICMP段长度 源IP地址 包的序列号 TTL  时间差*/
		printf("%d byte from %s:icmp_seq = %s tt1 = %d rtt = %d ms\n",
				len,inet_ntoa(ip->ip_src),icmp->icmp_seq,ip->ip_ttl,rtt);
		packet_recv++;
	}
	else
	{
		return -1;
	}
	return 0;

}
/*计算时间差time_sub
 * 参数: end，接收到的时间	begin，开始发送的时间 
 * 返回值：	使用的时间*/

static struct timeval icmp_tvsub(struct timeval end,struct timeval begin)
{
	struct timeval tv;

	tv.tv_sec = end.tv_sec - begin.tv_sec;
	tv.tv_usec = end.tv_usec - begin.tv_usec;
	/*如果t接收时间的usec值小于发送时的usec值，从usec域借位*/
	if(tv.tv_usec < 0)
	{
		tv.tv_sec--;
		tv.tv_usec += 1000000;
	}
	return tv;
}
/*发送ICMP回显请求包*/
static void* icmp_send(void *argv)
{
	/*保存程序开始发送数据的时间*/
	gettimeofday(&tv_begin,NULL);
	while(alive)
	{
		int size = 0;
		struct timeval tv;
		gettimeofday(&tv,NULL);
		/*当前包的发送时间*/
		/*在发送包状态数组中找一个空闲位置*/
		pingm_pakcet *packet = icmp_findpacket(-1);
		if(packet)
		{
			packet->seq = packet_send;

			packet->flag = 1;
			gettimeofday(&packet->tv_begin,NULL);
		}
		
		icmp_pack((struct icmp*)send_buff,packet_send,&tv,64);
		/*打包数据*/
		/*发送给目的地址*/
		size = sendto(rawsock,send_buff,64,0,(struct sockaddr *)&dest,sizeof(dest) );

		if(size < 0)
		{
			perror("sendto dest error");
			continue;
			packet_send++;

			sleep(1);
		}
	}
}

static void *icmp_recv(void *argv)
{
	/*轮询等待时间*/
	struct timeval tv;
	tv.tv_usec = 200;
	tv.tv_sec = 0;

	fd_set readfd;
	/*当没有信号发出一直接收数据*/
	while(alive)
	{
		int ret = 0;
		FD_ZERO(&readfd);
		FD_SET(rawsock,&readfd);
		ret = select(rawsock+1,&readfd,NULL,NULL,&tv);
		switch(ret)
		{
			case -1:
				break;
			case 0:
				break;
			default:
				{
					int size = recv(rawsock,recv_buff,sizeof(recv_buff),0);
					if(errno == EINTR)
					{
						perror("recvfrom error");
						continue;
					}
					/*解包，并设置相关变量*/
					ret = icmp_unpack(recv_buff,size);
					if(ret == -1)
					{
						continue;
					}

				}
				break;
		}
	}
}
/*查找一个合适的包位置
 * 当seq为-1时，表示查找空包 
 * 其他值表示查找seq对应的包*/
static pingm_pakcet *icmp_findpacket(int seq)
{
	int i = 0;
	/*查找包的位置*/
	pingm_pakcet *found = NULL;
	/*查找空包的位置*/
	if(seq == -1)
	{
		for(i = 0;i < 128;++i)
		{
			if(pingpacket[i].flag == 0)
			{
				found = &pingpacket[i];
				break;
			}
		}
	}
	/*查找对应seq的包*/
	else if(seq >= 0)
	{
		for(i = 0;i < 128;++i)
		{
			if(pingpacket[i].seq == seq)
			{
				found = &pingpacket[i];
				break;
			}
		}
	}
	return found;
}

/*打印全部ICMP发送接收统计结果*/
static void icmp_statistics(void)
{
	long time = (tv_interval.tv_sec * 1000) + (tv_interval.tv_usec/1000);
	/*目的IP地址*/
	printf("---%s ping statistics ---\n",dest_str);

	printf("%d packets transmitted,%d received,%d %c packet loss,time %ld ms\n",packet_send,packet_recv,(packet_send-packet_recv)*100/packet_send,'%',time);

}
/*终端信号处理函数SIGINT*/
static void icmp_sigint(int signo)
{
	alive = 0;
	/*告诉接收和发送线程结束程序*/
	gettimeofday(&tv_end,NULL);
	/*读取程序结束时间*/
	tv_interval = icmp_tvsub(tv_end,tv_begin);
	/**/

	return;
}
