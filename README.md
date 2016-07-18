C语言实现ping功能
ping命令用来查看网络上另一个主机系统的网络连接是否正常。
ping命令的工作原理：向网络上的另一个主机系统发送ICMP报文，如果系统得到了报文，它将把报文一模一样地传回给发送者。
ping命令使用的协议是TCP/IP协议。
ping命令执行后显示出被测试系统主机名和相应IP地址、返回给当前主机的ICMP报文顺序号、TTL生存时间和往返时间RTT
ICMP是为网关和目标主机而提供的一种差错控制机制，使他们在遇到差错时能把错误报告给报文源发方。ICMP协议是IP层的一个协议，但是由于差错报告在发送给报文源发方时可能也要经过若干子网，一次牵扯到路由选择等问题，所以ICMP报文需要通过IP协议来发送。ICMP数据报的数据发送前需要两级封装：首先添加ICMP报头形成ICMP报文，再添加IP报头形成IP数据报。
IP报头格式：由于IP层协议是一种点对点的协议，而非端对端的协议，它提供无连接的数据报服务，没有端口的概念，因此很少使用bind()函数和connect()函数，若有使用也只是用于设置IP地址。发送数据使用sendto()函数，接收数据使用recvfrom()函数。IP报头格式如下：

Linux中的IP报头格式数据结构如下：

其中ping程序中只使用以下数据：
IP报头长度：标识该IP头部有多少个32bit字（4字节）。是上述ip数据结构的ip_hl的变量。
生存时间TTL是数据报到达目的地之前允许经过的路由器跳数。TTL值被发送端设置（常见的值为64）.数据报在转发过程中每经过一个路由，该值就被路由器减1.当TTL减为0时，路由器将丢弃数据报，并向源端发送一个ICMP差错报文。TTL值可以防止数据报陷入路由循环。即指出IP数据报能在网络上停留的最长时间（由发送端设置）。是上述IP数据结构的ip_ttl变量
ICMP报文分为两种，一是错误报告报文，二是查询报文。每个ICMP报头均包含类型、编码和校验和三项内容，长度分别为8位，8位，16位。
ping命令只使用众多ICMP报文中的两种："请求回送'(ICMP_ECHO)和"请求回应'(ICMP_ECHOREPLY)。在Linux中定义如下：
#define ICMP_ECHO   0
#define ICMP_ECHOREPLY   8
这两种ICMP类型报头格式如下：即ping的数据格式

Linux中ICMP数据结构定义如下：
struct icmp
{
  u_int8_t  icmp_type;  //消息的类型
  u_int8_t  icmp_code;  //消息类型的子码
  u_int16_t icmp_cksum;  //校验和
  union
  {
    u_char ih_pptr;     /* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr;   /* gateway address */
    struct ih_idseq     //显示数据报
    {
      u_int16_t icd_id;  //数据报id
      u_int16_t icd_seq;  //数据报的序号
    } ih_idseq;
    u_int32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu
    {
      u_int16_t ipm_void;
      u_int16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv
    {
      u_int8_t irt_num_addrs;
      u_int8_t irt_wpa;
      u_int16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;
#define icmp_pptr   icmp_hun.ih_pptr
#define icmp_gwaddr icmp_hun.ih_gwaddr
#define icmp_id     icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void   icmp_hun.ih_void
#define icmp_pmvoid icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa    icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
  union
  {
    struct
    {
      u_int32_t its_otime;
      u_int32_t its_rtime;
      u_int32_t its_ttime;
    } id_ts;
    struct
    {
      struct ip idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
    struct icmp_ra_addr id_radv;
    u_int32_t   id_mask;
    u_int8_t    id_data[1];
  } icmp_dun;
#define icmp_otime  icmp_dun.id_ts.its_otime
#define icmp_rtime  icmp_dun.id_ts.its_rtime
#define icmp_ttime  icmp_dun.id_ts.its_ttime
#define icmp_ip     icmp_dun.id_ip.idi_ip
#define icmp_radv   icmp_dun.id_radv
#define icmp_mask   icmp_dun.id_mask
#define icmp_data   icmp_dun.id_data
};

使用宏定义令表达更简洁，其中ICMP报头为8字节，数据报长度最大为64K字节。
1.校验和算法：这一算法称为网际校验和算法，把被校验的数据16位进行累加，然后取反码，若数据字节长度为奇数，则数据尾部补一个字节的0以凑成偶数。校验和字段为上述ICMP数据结构的icmp_cksum变量。
2.标识符：用于唯一标识ICMP报文，为上述ICMP数据结构的icmp_id宏所指的变量。
3.顺序号：ping命令的icmp_seq便由这里读出，代表ICMP报文的发送顺序，为上述icmp_seq宏所指的变量
ping命令中需要显示的信息包括icmp_seq和TTL都已有了实现的办法，但还缺rtt往返时间。为了实现这一功能，可利用ICMP数据报携带一个时间戳。使用以下函数生成时间戳：
int gettimeofday(struct timeval *tp, void *tzp)
struct timeval 
{
long tv_sec;
long tv_usec;
};
其中tv_sec为秒数，tv_usec为微秒数。在发送和接受报文时由gettimeofday分别生成两个timeval结构，两者之差即为往返时间，即ICMP报文发送与接收的时间差，而timeval结构由ICMP数据报携带，tzp指针表示时区，一般都不使用，附NULL值。
ping命令当它接送完所有的ICMP报文后，会对所有发送和所有接收的ICMP报文进行统计，从而计算ICMP报文丢失的比率。为达到此目的，定义两个全局变量，接收计数器和发送计数器，用于记录ICMP报文接收和发送数目。
丢失数目 = 发送数目 - 接受数目
丢失比率 = 丢失数目 / 发送数目

