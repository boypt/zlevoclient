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

#include <netinet/in.h>
#include <net/if.h>

#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>

#include "md5.h"


/* ZlevoClient Version */
#define LENOVO_VER "0.3"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
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
    u_char eap_ask_id;
    u_short eap_length;
    u_char eap_op;
    u_char eap_v_length;
    u_char eap_md5_challenge[16];
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


static void signal_interrupted (int signo);
static void get_packet(u_char *args, const struct pcap_pkthdr *header, 
                        const u_char *packet);
void* keep_alive(void *arg);


u_char version_segment[] = {0x0a, 0x0b, 0x18, 0x2d};
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
        //    if (eap_header->eap_ask_id == 0x02)
            return EAP_SUCCESS;
            break;
        case 0x04:
            return EAP_FAILURE;
    }
    fprintf (stderr, "&&IMPORTANT: Unknown Package : eap_t:      %02x\n"
                    "                               eap_ask_id: %02x\n"
                    "                               eap_op:     %02x\n", 
                    eap_header->eap_t, eap_header->eap_ask_id,
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
            fprintf(stdout, "##Protocol: EAP_SUCCESS\n");
            fprintf(stdout, "&&Info: Authorized Access to Network. \n");
            if (background){
                background = 0;         /* 防止以后误触发 */
                pid_t pID = fork();     /* fork至后台，主程序退出 */
                if (pID != 0) {
                    fprintf(stdout, "&&Info: ZlevoClient Forked background with PID: [%d]\n\n", pID);
                    exit(0);
                }
            }
            if (live_keeper_id) {
                fprintf(stdout, "@@Fatal ERROR: thread creation.\n");
                exit (EXIT_FAILURE);
            }
            if ( pthread_create(&live_keeper_id, NULL, 
                                    keep_alive, NULL) != 0 ){
                fprintf(stdout, "@@Fatal ERROR: Init Live keep thread failure.\n");
                exit (EXIT_FAILURE);
            }
//            current_pid = getpid();     /* 取得当前进程PID */
            break;
        case EAP_FAILURE:
            if (state == READY) {
                fprintf(stdout, "##Protocol: Init Logoff Signal\n");
                return;
            }
            state = READY;
            fprintf(stdout, "##Protocol: EAP_FAILURE\n");
            if(state == ONLINE){
                fprintf(stdout, "&&Info: SERVER Forced Logoff\n");
            }
            if (state == STARTED){
                fprintf(stdout, "&&Info: Invalid Username or Client info mismatch.\n");
            }
            if (state == ID_AUTHED){
                fprintf(stdout, "&&Info: Invalid Password.\n");
            }
            pcap_breakloop (handle);
            break;
        case EAP_REQUEST_IDENTITY:
            if (state == STARTED){
                fprintf(stdout, "##Protocol: REQUEST EAP-Identity\n");
            }
            send_eap_packet(EAP_RESPONSE_IDENTITY);
            break;
        case EAP_REQUETS_MD5_CHALLENGE:
            state = ID_AUTHED;
            fprintf(stdout, "##Protocol: REQUEST MD5-Challenge(PASSWORD)\n");
            fill_password_md5((u_char*)header->eap_md5_challenge, 
                                        header->eap_ask_id);
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
            fprintf(stdout, "##Protocol: SEND EAPOL-Start\n");
            break;
        case EAPOL_LOGOFF:
            state = READY;
            frame_data = eapol_logoff;
            frame_length = 64;
            fprintf(stdout, "##Protocol: SEND EAPOL-Logoff\n");
            break;
        case EAP_RESPONSE_IDENTITY:
            frame_data = eap_response_ident;
            frame_length = 54 + username_length;
            fprintf(stdout, "##Protocol: SEND EAP-Response/Identity\n");
            break;
        case EAP_RESPONSE_MD5_CHALLENGE:
            frame_data = eap_response_md5ch;
            frame_length = 40 + username_length + 14;
            fprintf(stdout, "##Protocol: SEND EAP-Response/Md5-Challenge\n");
            break;
        case EAP_RESPONSE_IDENTITY_KEEP_ALIVE:
            frame_data = eapol_keepalive;
            frame_length = 64;
            fprintf(stdout, "##Protocol: SEND EAPOL Keep Alive\n");
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

    enum EAPType p_type = get_eap_type(eap_header);
    action_by_eap_type(p_type, eap_header);

    if (debug_on){
        printf ("@@DEBUG: Packet Caputre Data:\n");
        print_hex (packet, 64);
    }

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

    u_char keep_data[4] = {0x01, 0xfc, 0x00, 0x0c};
    memset (eapol_keepalive, 0xcc, 64);
    memcpy (eapol_keepalive, eapol_header, 14);
    memcpy (eapol_keepalive + 14, keep_data, 4);
    memset (eapol_keepalive + 18, 0, 8);
    memcpy (eapol_keepalive + 26, version_segment, 4);
    


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
    memcpy (eap_response_md5ch + data_index, version_segment, 4);
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

void program_unique_check(const char* program)
{
    FILE    *fd;
    pid_t   id = 0;
    char    command[50] = {0};
    char    pid_num[20] = {0};
    const char* program_name;

    program_name = strrchr (program, '/');
    if (program_name)
        ++program_name;
    else
        program_name = program;

    strcat (command, "ps -Ao pid,comm|grep ");
    strcat (command, program_name);

    if ( (fd = popen(command, "r")) == NULL ) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    fgets(pid_num, 20, fd);

    id = atoi(pid_num);

    if (exit_flag){
        if ( getpid() == id ){
            fprintf (stderr, "@@Error: No `%s' Running.\n", program_name);
            exit(EXIT_FAILURE);
        }
        if ( kill (id, SIGINT) == -1 ) {
			perror("kill");
			exit(EXIT_FAILURE);
        }
        fprintf (stdout, "&&Info: Exit Signal Sent.\n");
        exit(EXIT_SUCCESS);
    }
    if ( getpid() != id ){
        fprintf (stderr, "@@Error: There's another `%s' running with PID %d\n",
                program_name, id);
        exit(EXIT_FAILURE);
    }
    pclose(fd);
}

int main(int argc, char **argv)
{
    init_arguments (argc, argv);
    program_unique_check (argv[0]);

    init_info();
    init_device();
    init_frames ();

    signal (SIGINT, signal_interrupted);
    signal (SIGTERM, signal_interrupted);    

    printf("######## Lenovo Client ver. %s #########\n", LENOVO_VER);
    printf("Device:     %s\n", dev);
    printf("MAC:        ");
    print_hex(local_mac, 6);
    printf("########################################\n");

//    send_eap_packet (EAPOL_LOGOFF);
    send_eap_packet (EAPOL_START);

	pcap_loop (handle, -1, get_packet, NULL);   /* main loop */
	pcap_close (handle);
    free (eap_response_ident);
    free (eap_response_md5ch);
    return EXIT_SUCCESS;
}

