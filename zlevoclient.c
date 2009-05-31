/*
 * =====================================================================================
 *
 *       Filename:  zlevoclient.c
 *
 *    Description:  main source file for ZlevoClient
 *
 *        Version:  0.1
 *        Created:  05/24/2009 05:38:56 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  PT<pentie@gmail.com>
 *        Company:  http://apt-blog.co.cc
 *
 * =====================================================================================
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <net/if.h>

#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include <iconv.h>
#include "md5.h"
#include <arpa/inet.h>

/* ZlevoClient Version */
#define LENOVO_VER "0.7"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define LOCKFILE "/var/run/zlevoclient.pid"

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_eap_header {
    u_char eapol_v;
    u_char eapol_t;
    u_short eapol_length;
    u_char eap_t;
    u_char eap_id;
    u_short eap_length;
    u_char eap_op;
    u_char eap_v_length;
    u_char eap_info_tailer[40];
};

enum EAPType {
    EAPOL_START,
    EAPOL_LOGOFF,
    EAP_REQUEST_IDENTITY,
    EAP_RESPONSE_IDENTITY,
    EAP_REQUEST_IDENTITY_KEEP_ALIVE,
    EAP_RESPONSE_IDENTITY_KEEP_ALIVE,
    EAP_REQUETS_MD5_CHALLENGE,
    EAP_RESPONSE_MD5_CHALLENGE,
    EAP_SUCCESS,
    EAP_FAILURE,
    ERROR
};

enum STATE {
   READY,
   STARTED,
   ID_AUTHED,
   ONLINE
};

void    send_eap_packet(enum EAPType send_type);
void    show_usage();
char*   get_md5_digest(const char* str, size_t len);
void    action_by_eap_type(enum EAPType pType, 
                        const struct sniff_eap_header *header);
void    init_frames();
void    init_info();
void    init_device();
void    init_arguments(int argc, char **argv);
int     set_device_new_ip();
void    fill_password_md5(u_char *attach_key, u_int id);
int     program_running_check();
void*   keep_alive(void *arg);
int     code_convert(char *from_charset, char *to_charset,
             char *inbuf, size_t inlen, char *outbuf, size_t outlen);
void    print_server_info (const u_char *str);
void    daemon_init(void);



static void signal_interrupted (int signo);
static void get_packet(u_char *args, const struct pcap_pkthdr *header, 
                        const u_char *packet);

//u_char local_ip[] = {0x0a, 0x0b, 0x18, 0x2d};
u_char talier_eapol_start[] = {0x00, 0x00, 0x2f, 0xfc, 0x03, 0x00};
u_char talier_eap_md5_resp[] = {0x00, 0x00, 0x2f, 0xfc, 0x00, 0x03, 0x01, 0x01, 0x00};

char        errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
enum STATE  state = READY;                     /* program state */
pcap_t      *handle = NULL;			   /* packet capture handle */

int         background = 0;            /* 后台运行标记  */     
char        *dev = NULL;               /* 连接的设备名 */
char        *username = NULL;          
char        *password = NULL;

int         username_length;
int         password_length;

u_int       local_ip = 0;

u_char      local_mac[ETHER_ADDR_LEN]; /* MAC地址 */

char        *client_ver = NULL;         /* 报文协议版本号 */

u_char      muticast_mac[] =            /* 802.1x的认证服务器多播地址 */
                        {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

u_char      eapol_start[64];            /* EAPOL START报文 */
u_char      eapol_logoff[64];           /* EAPOL LogOff报文 */
u_char      eapol_keepalive[64];
u_char      *eap_response_ident = NULL; /* EAP RESPON/IDENTITY报文 */
u_char      *eap_response_md5ch = NULL; /* EAP RESPON/MD5 报文 */

u_int       live_count = 0;             /* KEEP ALIVE 报文的计数值 */
//pid_t       current_pid = 0;            /* 记录后台进程的pid */

pthread_t   live_keeper_id;
int         exit_flag = 0;
int         debug_on = 0;

// debug function
void 
print_hex(const u_char *array, int count)
{
    int i;
    for(i = 0; i < count; i++){
        printf("%02x ", array[i]);
    }
    printf("\n");
}

int 
code_convert(char *from_charset, char *to_charset,
             char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
    iconv_t cd;
    char **pin = &inbuf;
    char **pout = &outbuf;

    cd = iconv_open(to_charset,from_charset);

    if (cd==0) 
      return -1;
    memset(outbuf,0,outlen);

    if (iconv(cd, pin, &inlen, pout, &outlen)==-1) 
      return -1;
    iconv_close(cd);
    return 0;
}

void 
print_server_info (const u_char *str)
{
    if (!(str[0] == 0x2f && str[1] == 0xfc)) 
        return;

    char info_str [1024] = {0};
    int length = str[2];
    if (code_convert ("gb2312", "utf-8", (char*)str + 3, length, info_str, 200) != 0){
        fprintf (stderr, "@@Error: Server info convert error.\n");
        return;
    }
    fprintf (stdout, "&&Server Info: %s\n", info_str);
}

void
show_usage()
{
    printf( "\n"
            "ZlevoClient %s \n"
            "\t  -- Supllicant for DigiChina Authentication.\n"
            "\n"
            "  Usage:\n"
            "\tRun under root privilege, usually by `sudo', with your \n"
            "\taccount info in arguments:\n\n"
            "\t-u, --username           Your username.\n"
            "\t-p, --password           Your password.\n"
            "\n"
            "  Optional Arguments:\n\n"
            "\t--device              Specify which device to use.\n"
            "\t                      Default is usually eth0.\n\n"

            "\t-b, --background      Program fork to background after authentication.\n\n"
            "\t-l                    Tell the process to Logoff.\n\n"
            "\t--debug               Show debug message.\n\n"
            "\t-h, --help            Show this help.\n\n"
            "\n"
            "  About ZlevoClient:\n\n"
            "\tThis program is a supplicat program compatible for LENOVO ,\n"
            "\t802.1x EAPOL protocol, which was used for  Internet control.\n"

            "\tZlevoClient is a software developed individually, with NO any rela-\n"
            "\tiontship with Lenovo company.\n\n\n"
            
            "\tAnother PT work. Blog: http://apt-blog.co.cc\n"
            "\t\t\t\t\t\t\t\t2009.05.24\n",
            LENOVO_VER);
}

/* calcuate for md5 digest */
char* 
get_md5_digest(const char* str, size_t len)
{
	md5_state_t state;
	md5_byte_t digest[16];
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)str, len);
	md5_finish(&state, digest);

    char *result = malloc(16);
    memcpy(result, digest, 16);
    return result;
}

enum EAPType 
get_eap_type(const struct sniff_eap_header *eap_header) 
{
    switch (eap_header->eap_t){
        case 0x01:
            if (eap_header->eap_op == 0x01)
                    return EAP_REQUEST_IDENTITY;
            if (eap_header->eap_op == 0x04)
                    return EAP_REQUETS_MD5_CHALLENGE;
            break;
        case 0x03:
        //    if (eap_header->eap_id == 0x02)
            return EAP_SUCCESS;
            break;
        case 0x04:
            return EAP_FAILURE;
    }
    fprintf (stderr, "&&IMPORTANT: Unknown Package : eap_t:      %02x\n"
                    "                               eap_id: %02x\n"
                    "                               eap_op:     %02x\n", 
                    eap_header->eap_t, eap_header->eap_id,
                    eap_header->eap_op);
    return ERROR;
}

void 
action_by_eap_type(enum EAPType pType, 
                        const struct sniff_eap_header *header) {
//    printf("PackType: %d\n", pType);
    switch(pType){
        case EAP_SUCCESS:
            state = ONLINE;
            fprintf(stdout, ">>Protocol: EAP_SUCCESS\n");
            fprintf(stdout, "&&Info: Authorized Access to Network. \n");
            if (background){
                background = 0;         /* 防止以后误触发 */
                daemon_init ();  /* fork至后台，主程序退出 */
            }
            if ( !live_keeper_id ) {
                if ( pthread_create(&live_keeper_id, NULL, 
                                            keep_alive, NULL) != 0 ){
                    fprintf(stderr, "@@Fatal ERROR: Init Live keep thread failure.\n");
                    exit (EXIT_FAILURE);
                }
            }
            break;
        case EAP_FAILURE:
            if (state == READY) {
                fprintf(stdout, ">>Protocol: Init Logoff Signal\n");
                return;
            }
            state = READY;
            fprintf(stdout, ">>Protocol: EAP_FAILURE\n");
            if(state == ONLINE){
                fprintf(stdout, "&&Info: SERVER Forced Logoff\n");
            }
            if (state == STARTED){
                fprintf(stdout, "&&Info: Invalid Username or Client info mismatch.\n");
            }
            if (state == ID_AUTHED){
                fprintf(stdout, "&&Info: Invalid Password.\n");
            }
            print_server_info (header->eap_info_tailer);
            pcap_breakloop (handle);
            break;
        case EAP_REQUEST_IDENTITY:
            if (state == STARTED){
                fprintf(stdout, ">>Protocol: REQUEST EAP-Identity\n");
            }
            memset (eap_response_ident + 14 + 5, header->eap_id, 1);
            send_eap_packet(EAP_RESPONSE_IDENTITY);
            break;
        case EAP_REQUETS_MD5_CHALLENGE:
            state = ID_AUTHED;
            fprintf(stdout, ">>Protocol: REQUEST MD5-Challenge(PASSWORD)\n");
            fill_password_md5((u_char*)header->eap_info_tailer, 
                                        header->eap_id);
            send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
            break;
        default:
            return;
    }
}

void 
send_eap_packet(enum EAPType send_type)
{
    u_char *frame_data;
    int     frame_length = 0;
    switch(send_type){
        case EAPOL_START:
            state = STARTED;
            frame_data= eapol_start;
            frame_length = 64;
            fprintf(stdout, ">>Protocol: SEND EAPOL-Start\n");
            break;
        case EAPOL_LOGOFF:
            state = READY;
            frame_data = eapol_logoff;
            frame_length = 64;
            fprintf(stdout, ">>Protocol: SEND EAPOL-Logoff\n");
            break;
        case EAP_RESPONSE_IDENTITY:
            frame_data = eap_response_ident;
            frame_length = 54 + username_length;
            fprintf(stdout, ">>Protocol: SEND EAP-Response/Identity\n");
            break;
        case EAP_RESPONSE_MD5_CHALLENGE:
            frame_data = eap_response_md5ch;
            frame_length = 40 + username_length + 14;
            fprintf(stdout, ">>Protocol: SEND EAP-Response/Md5-Challenge\n");
            break;
        case EAP_RESPONSE_IDENTITY_KEEP_ALIVE:
            frame_data = eapol_keepalive;
            frame_length = 64;
            fprintf(stdout, ">>Protocol: SEND EAPOL Keep Alive\n");
            break;
        default:
            fprintf(stderr,"&&IMPORTANT: Wrong Send Request Type.%02x\n", send_type);
            return;
    }
    if (debug_on){
        printf ("@@DEBUG: Sent Frame Data:\n");
        print_hex (frame_data, frame_length);
    }
    if (pcap_sendpacket(handle, frame_data, frame_length) != 0)
    {
        fprintf(stderr,"&&IMPORTANT: Error Sending the packet: %s\n", pcap_geterr(handle));
        return;
    }
}

/* Callback function for pcap.  */
void
get_packet(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_eap_header *eap_header;

    ethernet = (struct sniff_ethernet*)(packet);
    eap_header = (struct sniff_eap_header *)(packet + SIZE_ETHERNET);

    if (debug_on){
        printf ("@@DEBUG: Packet Caputre Data:\n");
        print_hex (packet, 64);
    }

    enum EAPType p_type = get_eap_type(eap_header);
    action_by_eap_type(p_type, eap_header);

    return;
}

void 
init_frames()
{
    int data_index;

    /*****  EAPOL Header  *******/
    u_char eapol_header[SIZE_ETHERNET];
    data_index = 0;
    u_short eapol_t = htons (0x888e);
    memcpy (eapol_header + data_index, muticast_mac, 6); /* dst addr. muticast */
    data_index += 6;
    memcpy (eapol_header + data_index, local_mac, 6);    /* src addr. local mac */
    data_index += 6;
    memcpy (eapol_header + data_index, &eapol_t, 2);    /*  frame type, 0x888e*/

    /**** EAPol START ****/
    u_char start_data[] = {0x01, 0x01, 0x00, 0x00};
    memset (eapol_start, 0xcc, 64);
    memcpy (eapol_start, eapol_header, 14);
    memcpy (eapol_start + 14, start_data, 4);
    memcpy (eapol_start + 14 + 4, talier_eapol_start, 6);


    /****EAPol LOGOFF ****/
    u_char logoff_data[4] = {0x01, 0x02, 0x00, 0x00};
    memset (eapol_logoff, 0xcc, 64);
    memcpy (eapol_logoff, eapol_header, 14);
    memcpy (eapol_logoff + 14, logoff_data, 4);
    memcpy (eapol_logoff + 14 + 4, talier_eapol_start, 4);

    /****EAPol Keep alive ****/
    u_char keep_data[4] = {0x01, 0xfc, 0x00, 0x0c};
    memset (eapol_keepalive, 0xcc, 64);
    memcpy (eapol_keepalive, eapol_header, 14);
    memcpy (eapol_keepalive + 14, keep_data, 4);
    memset (eapol_keepalive + 18, 0, 8);
    memcpy (eapol_keepalive + 26, &local_ip, 4);
    


    /* EAP RESPONSE IDENTITY */
    u_char eap_resp_iden_head[9] = {0x01, 0x00, 
                                    0x00, 5 + username_length,  /* eapol_length */
                                    0x02, 0x00, 
                                    0x00, 5 + username_length,       /* eap_length */
                                    0x01};
    
    eap_response_ident = malloc (54 + username_length);
    memset(eap_response_ident, 0xcc, 54 + username_length);

    data_index = 0;
    memcpy (eap_response_ident + data_index, eapol_header, 14);
    data_index += 14;
    memcpy (eap_response_ident + data_index, eap_resp_iden_head, 9);
    data_index += 9;
    memcpy (eap_response_ident + data_index, username, username_length);

    /** EAP RESPONSE MD5 Challenge **/
    u_char eap_resp_md5_head[10] = {0x01, 0x00, 
                                   0x00, 6 + 16 + username_length, /* eapol-length */
                                   0x02, 
                                   0x00, /* id to be set */
                                   0x00, 6 + 16 + username_length, /* eap-length */
                                   0x04, 0x10};
    eap_response_md5ch = malloc (14 + 4 + 6 + 16 + username_length + 14);
    memset(eap_response_md5ch, 0xcc, 14 + 4 + 6 + 16 + username_length + 14);

    data_index = 0;
    memcpy (eap_response_md5ch + data_index, eapol_header, 14);
    data_index += 14;
    memcpy (eap_response_md5ch + data_index, eap_resp_md5_head, 10);
    data_index += 26;// 剩余16位在收到REQ/MD5报文后由fill_password_md5填充 
    memcpy (eap_response_md5ch + data_index, username, username_length);
    data_index += username_length;
    memcpy (eap_response_md5ch + data_index, &local_ip, 4);
    data_index += 4;
    memcpy (eap_response_md5ch + data_index, talier_eap_md5_resp, 9);
}

void 
fill_password_md5(u_char *attach_key, u_int id)
{
    char *psw_key = malloc(1 + password_length + 16);
    char *md5_challenge_key;
    psw_key[0] = id;
    memcpy (psw_key + 1, password, password_length);
    memcpy (psw_key + 1 + password_length, attach_key, 16);

    if (debug_on){
        printf("@@DEBUG: MD5-Attach-KEY:\n");
        print_hex ((u_char*)psw_key, 1 + password_length + 16);
    }

    md5_challenge_key = get_md5_digest(psw_key, 1 + password_length + 16);

//    printf("@@DEBUG: MD5-Challenge:\n");
//    print_hex (md5_challenge_key, 16);

    memset (eap_response_md5ch + 14 + 5, id, 1);
    memcpy (eap_response_md5ch + 14 + 10, md5_challenge_key, 16);

    free (psw_key);
    free (md5_challenge_key);
}

void init_info()
{
    if(username == NULL || password == NULL){
        fprintf (stderr,"Error: NO Username or Password promoted.\n"
                        "Try zlevoclient --help for usage.\n");
        exit(EXIT_FAILURE);
    }
    username_length = strlen(username);
    password_length = strlen(password);

}

void init_device()
{
    struct bpf_program fp;			/* compiled filter program (expression) */
    char filter_exp[51];/* filter expression [3] */
//	bpf_u_int32 mask;			/* subnet mask */
//	bpf_u_int32 net;			/* ip */

    if(dev == NULL)
	    dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",
			errbuf);
		exit(EXIT_FAILURE);
    }
	
	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

    /* get device basic infomation */
    struct ifreq ifr;
    int sock;
    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    strcpy(ifr.ifr_name, dev);

    //获得网卡Mac
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    local_ip = ((struct  sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;


    /* construct the filter string */
    sprintf(filter_exp, "ether dst %02x:%02x:%02x:%02x:%02x:%02x"
                        " and ether proto 0x888e", 
                        local_mac[0], local_mac[1],
                        local_mac[2], local_mac[3],
                        local_mac[4], local_mac[5]);

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
    pcap_freecode(&fp);
}


static void
signal_interrupted (int signo)
{
    fprintf(stdout,"\n&&Info: USER Interrupted. \n");
    send_eap_packet(EAPOL_LOGOFF);
    pcap_breakloop (handle);
    pcap_close (handle);
    exit (EXIT_FAILURE);
}

void init_arguments(int argc, char **argv)
{
    /* Option struct for progrm run arguments */
    struct option long_options[] =
        {
        {"help",        no_argument,        0,              'h'},
        {"background",  no_argument,        &background,    1},
        {"device",      required_argument,  0,              2},
        {"username",    required_argument,  0,              'u'},
        {"password",    required_argument,  0,              'p'},
        {"debug",       no_argument,        &debug_on,      'd'},
        {0, 0, 0, 0}
        };

    int c;
    while (1) {

        /* getopt_long stores the option index here. */
        int option_index = 0;
        c = getopt_long (argc, argv, "u:p:hbl",
                        long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
            case 0:
               break;
            case 'b':
                background = 1;
                break;
            case 2:
                dev = optarg;
                break;
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'h':
                show_usage();
                exit(EXIT_SUCCESS);
                break;
            case 'l':
                exit_flag = 1;
                break;
            case '?':
                if (optopt == 'u' || optopt == 'p'|| optopt == 'g'|| optopt == 'd')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                exit(EXIT_FAILURE);
                break;
            default:
                fprintf (stderr,"Unknown option character `\\x%x'.\n", c);
                exit(EXIT_FAILURE);
        }
    }    
}

void* keep_alive(void *arg)
{
    while (1) {
        send_eap_packet (EAP_RESPONSE_IDENTITY_KEEP_ALIVE);
        sleep (60);
    }
}

void
daemon_init(void)
{
	pid_t	pid;
    int ins_pid;

	if ( (pid = fork()) < 0)
	    perror ("Fork");
	else if (pid != 0) {
        fprintf(stdout, "&&Info: ZLevoClient Forked background with PID: [%d]\n\n", pid);
		exit(0);
    }
	setsid();		/* become session leader */
	chdir("/");		/* change working directory */
	umask(0);		/* clear our file mode creation mask */

    sleep (1);      /* wait for the parent exit completely */

    if ( (ins_pid = program_running_check ()) ) {
        fprintf(stderr,"@@Fatal ERROR: Another instance "
                            "running with PID %d\n", ins_pid);
        exit(EXIT_FAILURE);
    }
}


int 
program_running_check()
{
    int fd;
    char buf[16];
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;

    fd = open (LOCKFILE, O_RDWR | O_CREAT , LOCKMODE);

    if (fd < 0){
        perror ("Lockfile");
        exit(1);
    }

    if (fcntl(fd, F_SETLK, &fl) < 0){
        if(errno == EACCES || errno == EAGAIN){
            read (fd, buf, 16);
            close(fd);

            int inst_pid = atoi (buf);
            if (exit_flag) {
                if ( kill (inst_pid, SIGINT) == -1 ) {
                                perror("kill");
                                exit(EXIT_FAILURE);
                }
                fprintf (stdout, "&&Info: Kill Signal Sent to PID %d.\n", inst_pid);
                exit (EXIT_FAILURE);
            }
            return inst_pid;
        }
        perror("Lockfile");
        exit(1);
    }

    ftruncate(fd, 0);    
    sprintf(buf, "%ld", (long)getpid());
    write(fd, buf, strlen(buf) + 1);
    return 0;
}


int main(int argc, char **argv)
{
    int ins_pid;

    init_arguments (argc, argv);

    if ( (ins_pid = program_running_check ()) ) {
        fprintf(stderr,"@@ERROR: ZLevoClient Already "
                            "Running with PID %d\n", ins_pid);
        exit(EXIT_FAILURE);
    }

    init_info();
    init_device();
    init_frames ();

    signal (SIGINT, signal_interrupted);
    signal (SIGTERM, signal_interrupted);    

    printf("######## Lenovo Client ver. %s #########\n", LENOVO_VER);
    printf("Device:     %s\n", dev);
    printf("MAC:        ");
    print_hex(local_mac, 6);
    printf("IP:         %s\n", inet_ntoa(*(struct in_addr*)&local_ip));
    printf("########################################\n");

//    send_eap_packet (EAPOL_LOGOFF);
    send_eap_packet (EAPOL_START);

	pcap_loop (handle, -1, get_packet, NULL);   /* main loop */

    send_eap_packet (EAPOL_LOGOFF);

	pcap_close (handle);
    free (eap_response_ident);
    free (eap_response_md5ch);
    return EXIT_SUCCESS;
}

