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

#include <assert.h>

#include	"commondef.h"
#include	"eap_protocol.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <ctype.h>
#include <errno.h>

//#include <sys/ioctl.h>
//#include <sys/stat.h>
//
//#include <netinet/in.h>
//#include <net/if.h>
//
//#include <pthread.h>
//#include <signal.h>
//#include <getopt.h>
//#include <unistd.h>
//#include <fcntl.h>
//
//#include <iconv.h>
#include "md5.h"
//#include <arpa/inet.h>

/* ZlevoClient Version */
#define LENOVO_VER "0.8"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define LOCKFILE "/var/run/zlevoclient.pid"

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)



//enum EAPType {
//    EAPOL_START,
//    EAPOL_LOGOFF,
//    EAP_REQUEST_IDENTITY,
//    EAP_RESPONSE_IDENTITY,
//    EAP_REQUEST_IDENTITY_KEEP_ALIVE,
//    EAP_RESPONSE_IDENTITY_KEEP_ALIVE,
//    EAP_REQUETS_MD5_CHALLENGE,
//    EAP_RESPONSE_MD5_CHALLENGE,
//    EAP_SUCCESS,
//    EAP_FAILURE,
//    ERROR
//};
//
//enum STATE {
//   READY,
//   STARTED,
//   ID_AUTHED,
//   ONLINE
//};

void    send_eap_packet(enum EAPType send_type);
void    show_usage();
char*   get_md5_digest(const char* str, size_t len);
//void    action_by_eap_type(enum EAPType pType, 
//                        const struct sniff_eap_header *header);
void    init_frames();
void    init_info();
void    init_device();
void    init_arguments(int argc, char **argv);
int     set_device_new_ip();
void    fill_password_md5(u_char *attach_key, u_int id);
int     program_running_check();
//void*   keep_alive(void *arg);
//int     code_convert(char *from_charset, char *to_charset,
//             char *inbuf, size_t inlen, char *outbuf, size_t outlen);
void    print_server_info (const u_char *str);
void    daemon_init(void);
//
//static void signal_interrupted (int signo);
void get_packet(u_char *args, const struct pcap_pkthdr *header, 
                        const u_char *packet);



/* #####   GLOBLE VAR DEFINITIONS   ######################### */
/*-----------------------------------------------------------------------------
 *  程序的主控制变量
 *-----------------------------------------------------------------------------*/
int         lockfile;
char        errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
enum STATE  state = READY;                     /* program state */
pcap_t      *handle = NULL;			   /* packet capture handle */
//pthread_t   live_keeper_id;
u_char      muticast_mac[] =            /* 802.1x的认证服务器多播地址 */
                        {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};


/* #####   GLOBLE VAR DEFINITIONS   ###################
 *-----------------------------------------------------------------------------
 *  用户信息的赋值变量，由init_argument函数初始化
 *-----------------------------------------------------------------------------*/
int         background = 0;            /* 后台运行标记  */     
char        *dev = NULL;               /* 连接的设备名 */
char        username[128];          
char        password[128];
int         exit_flag = 0;
int         debug_on = 0;

/* #####   GLOBLE VAR DEFINITIONS   ######################### 
 *-----------------------------------------------------------------------------
 *  报文相关信息变量，由init_info 、init_device函数初始化。
 *-----------------------------------------------------------------------------*/
size_t         username_length;
size_t         password_length;
u_int       local_ip = 0;
u_char      local_mac[ETHER_ADDR_LEN]; /* MAC地址 */
char        devname[512];

/* #####   TYPE DEFINITIONS   ######################### */
/*-----------------------------------------------------------------------------
 *  报文缓冲区，由init_frame函数初始化。
 *-----------------------------------------------------------------------------*/
u_char      eapol_start[64];            /* EAPOL START报文 */
u_char      eapol_logoff[64];           /* EAPOL LogOff报文 */
u_char      eapol_keepalive[64];
u_char      *eap_response_ident = NULL; /* EAP RESPON/IDENTITY报文 */
u_char      *eap_response_md5ch = NULL; /* EAP RESPON/MD5 报文 */

//u_int       live_count = 0;             /* KEEP ALIVE 报文的计数值 */
//pid_t       current_pid = 0;            /* 记录后台进程的pid */

// debug function
void 
print_hex(const uint8_t *array, int count)
{
    int i;
    for(i = 0; i < count; i++){
        if ( !(i % 16))
            printf ("\n");
        printf("%02x ", array[i]);
    }
    printf("\n");
}
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_md5_digest
 *  Description:  calcuate for md5 digest
 * =====================================================================================
 */
char* 
get_md5_digest(const char* str, size_t len)
{
    static md5_byte_t digest[16];
	md5_state_t state;
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)str, len);
	md5_finish(&state, digest);

    return (char*)digest;
}


enum EAPType 
get_eap_type(const struct eap_header *eap_header) 
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

//void 
//action_by_eap_type(enum EAPType pType, 
//                        const struct sniff_eap_header *header) {
////    printf("PackType: %d\n", pType);
//    switch(pType){
//        case EAP_SUCCESS:
//            state = ONLINE;
//            fprintf(stdout, ">>Protocol: EAP_SUCCESS\n");
//            fprintf(stdout, "&&Info: Authorized Access to Network. \n");
////            if (background){
////                background = 0;         /* 防止以后误触发 */
////                daemon_init ();  /* fork至后台，主程序退出 */
////            }
////            if ( !live_keeper_id ) {
////                if ( pthread_create(&live_keeper_id, NULL, 
////                                            keep_alive, NULL) != 0 ){
////                    fprintf(stderr, "@@Fatal ERROR: Init Live keep thread failure.\n");
////                    exit (EXIT_FAILURE);
////                }
////            }
//            break;
//        case EAP_FAILURE:
//            if (state == READY) {
//                fprintf(stdout, ">>Protocol: Init Logoff Signal\n");
//                return;
//            }
//            state = READY;
//            fprintf(stdout, ">>Protocol: EAP_FAILURE\n");
////            if(state == ONLINE){
////                fprintf(stdout, "&&Info: SERVER Forced Logoff\n");
////            }
////            if (state == STARTED){
////                fprintf(stdout, "&&Info: Invalid Username or Client info mismatch.\n");
////            }
////            if (state == ID_AUTHED){
////                fprintf(stdout, "&&Info: Invalid Password.\n");
////            }
//            print_server_info (header->eap_info_tailer);
//            pcap_breakloop (handle);
//            break;
//        case EAP_REQUEST_IDENTITY:
////            if (state == STARTED){
////                fprintf(stdout, ">>Protocol: REQUEST EAP-Identity\n");
////            }
//            memset (eap_response_ident + 14 + 5, header->eap_id, 1);
//            send_eap_packet(EAP_RESPONSE_IDENTITY);
//            break;
//        case EAP_REQUETS_MD5_CHALLENGE:
////            state = ID_AUTHED;
//            fprintf(stdout, ">>Protocol: REQUEST MD5-Challenge(PASSWORD)\n");
//            fill_password_md5((u_char*)header->eap_info_tailer, 
//                                        header->eap_id);
//            send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
//            break;
//        default:
//            return;
//    }
//}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  action_by_eap_type
 *  Description:  根据eap报文的类型完成相关的应答
 * =====================================================================================
 */
void 
action_by_eap_type(enum EAPType pType, 
                        const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet) {
//    printf("PackType: %d\n", pType);
    switch(pType){
        case EAP_SUCCESS:
            action_eapol_success (eap_head, packetinfo, packet);
            break;
        case EAP_FAILURE:
            action_eapol_failre (eap_head, packetinfo, packet);
            break;
        case EAP_REQUEST_IDENTITY:
            action_eap_req_idnty (eap_head, packetinfo, packet);
            break;
        case EAP_REQUETS_MD5_CHALLENGE:
            action_eap_req_md5_chg (eap_head, packetinfo, packet);
            break;
        default:
            return;
    }
}

//void 
//send_eap_packet(enum EAPType send_type)
//{
//    u_char *frame_data;
//    int     frame_length = 0;
//    switch(send_type){
//        case EAPOL_START:
////            state = STARTED;
//            frame_data= eapol_start;
//            frame_length = 64;
//            fprintf(stdout, ">>Protocol: SEND EAPOL-Start\n");
//            break;
//        case EAPOL_LOGOFF:
//            state = READY;
//            frame_data = eapol_logoff;
//            frame_length = 64;
//            fprintf(stdout, ">>Protocol: SEND EAPOL-Logoff\n");
//            break;
//        case EAP_RESPONSE_IDENTITY:
//            frame_data = eap_response_ident;
//            frame_length = 54 + username_length;
//            fprintf(stdout, ">>Protocol: SEND EAP-Response/Identity\n");
//            break;
//        case EAP_RESPONSE_MD5_CHALLENGE:
//            frame_data = eap_response_md5ch;
//            frame_length = 40 + username_length + 14;
//            fprintf(stdout, ">>Protocol: SEND EAP-Response/Md5-Challenge\n");
//            break;
//        case EAP_RESPONSE_IDENTITY_KEEP_ALIVE:
//            frame_data = eapol_keepalive;
//            frame_length = 64;
//            fprintf(stdout, ">>Protocol: SEND EAPOL Keep Alive\n");
//            break;
//        default:
//            fprintf(stderr,"&&IMPORTANT: Wrong Send Request Type.%02x\n", send_type);
//            return;
//    }
//    if (debug_on){
//        printf ("@@DEBUG: Sent Frame Data:\n");
//        print_hex (frame_data, frame_length);
//    }
//    if (pcap_sendpacket(handle, frame_data, frame_length) != 0)
//    {
//        fprintf(stderr,"&&IMPORTANT: Error Sending the packet: %s\n", pcap_geterr(handle));
//        return;
//    }
//}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_packet
 *  Description:  pcap的回呼函数，当收到EAPOL报文时自动被调用
 * =====================================================================================
 */
void
get_packet(uint8_t *args, const struct pcap_pkthdr *pcaket_header, 
    const uint8_t *packet)
{
	/* declare pointers to packet headers */
	const struct ether_header *ethernet;  /* The ethernet header [1] */
    const struct eap_header *eap_header;
    enum EAPType p_type;

    ethernet = (struct ether_header*)(packet);
    eap_header = (struct eap_header*)(packet + SIZE_ETHERNET);

    p_type = get_eap_type(eap_header);
    if (p_type != ERROR)
        action_by_eap_type(p_type, eap_header, pcaket_header, packet);
    return;
}

void 
init_frames()
{
    const u_char talier_eapol_start[] = {0x00, 0x00, 0x2f, 0xfc, 0x03, 0x00};
    const u_char talier_eap_md5_resp[] = {0x00, 0x00, 0x2f, 0xfc, 0x00, 0x03, 0x01, 0x01, 0x00};

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

    print_hex(eapol_start, sizeof(eapol_start));
    /****EAPol LOGOFF ****/
    u_char logoff_data[4] = {0x01, 0x02, 0x00, 0x00};
    memset (eapol_logoff, 0xcc, 64);
    memcpy (eapol_logoff, eapol_header, 14);
    memcpy (eapol_logoff + 14, logoff_data, 4);
    memcpy (eapol_logoff + 14 + 4, talier_eapol_start, 4);

    print_hex(eapol_logoff, sizeof(eapol_logoff));
    /****EAPol Keep alive ****/
    u_char keep_data[4] = {0x01, 0xfc, 0x00, 0x0c};
    memset (eapol_keepalive, 0xcc, 64);
    memcpy (eapol_keepalive, eapol_header, 14);
    memcpy (eapol_keepalive + 14, keep_data, 4);
    memset (eapol_keepalive + 18, 0, 8);
    memcpy (eapol_keepalive + 26, &local_ip, 4);
    
    print_hex(eapol_keepalive, sizeof(eapol_keepalive));

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

    print_hex(eap_response_ident, sizeof(eap_response_ident));

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

    print_hex(eap_response_md5ch, sizeof(eap_response_md5ch));
}

void 
fill_password_md5(u_char *attach_key, u_int id)
{
    char *psw_key = malloc(1 + password_length + 16);
    char *md5;
    psw_key[0] = id;
    memcpy (psw_key + 1, password, password_length);
    memcpy (psw_key + 1 + password_length, attach_key, 16);

    if (debug_on){
        printf("@@DEBUG: MD5-Attach-KEY:\n");
        print_hex ((u_char*)psw_key, 1 + password_length + 16);
    }

    md5 = get_md5_digest(psw_key, 1 + password_length + 16);

    memset (eap_response_md5ch + 14 + 5, id, 1);
    memcpy (eap_response_md5ch + 14 + 10, md5, 16);

    free (psw_key);
}

//void init_info()
//{
//    if(username == NULL || password == NULL){
//        fprintf (stderr,"Error: NO Username or Password promoted.\n"
//                        "Try zlevoclient --help for usage.\n");
//        exit(EXIT_FAILURE);
//    }
//    username_length = strlen(username);
//    password_length = strlen(password);
//
//}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_device
 *  Description:  初始化设备。主要是找到打开网卡、获取网卡MAC、IP，
 *  同时设置pcap的初始化工作句柄。
 * =====================================================================================
 */
void init_device()
{
    struct          bpf_program fp;			/* compiled filter program (expression) */
    char            filter_exp[51];         /* filter expression [3] */
    pcap_if_t       *alldevs;
	pcap_if_t 		*d;
//	extern HANDLE    hwndComboList;
    extern int      combo_index;
	
	/* NIC device  */
	assert(pcap_findalldevs(&alldevs, errbuf) != -1);

	int sel_index = combo_index;
	for(d = alldevs; sel_index-- && d; d = d->next);
//	while (sel_index--) 
//		d = d->next;
	pcap_addr_t *a;
	for(a = d->addresses; a ; a=a->next) {
		if (a->addr->sa_family == AF_INET) {
			strcpy (devname, d->name);
			local_ip = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
//			local_mask = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;
			break;
		}
	}
	pcap_freealldevs(alldevs);

//    debug_msgbox ("%s", devname);
	
	/* Mac */
	IP_ADAPTER_INFO AdapterInfo[16];			// Allocate information for up to 16 NICs
	PIP_ADAPTER_INFO pAdapterInfo;
	DWORD dwBufLen = sizeof(AdapterInfo);		// Save the memory size of buffer

	DWORD dwStatus = GetAdaptersInfo(			// Call GetAdapterInfo
		AdapterInfo,							// [out] buffer to receive data
		&dwBufLen);								// [in] size of receive data buffer

	if(dwStatus != ERROR_SUCCESS){			// Verify return value is valid, no buffer overflow
        thread_error_exit("Invalid Device.[GET Mac Addr]");
    }

	for (pAdapterInfo = AdapterInfo; pAdapterInfo; pAdapterInfo = pAdapterInfo->Next) {
		if (strstr (devname, pAdapterInfo->AdapterName) != NULL) {
		    memcpy(local_mac, pAdapterInfo->Address, ETHER_ADDR_LEN);
			break;
		}
	}
    if (!pAdapterInfo)
        thread_error_exit("No MAC Addr Found on the Selected Device.");
	
	/* open capture device */
	handle = pcap_open_live(devname, SNAP_LEN, 1, 1000, errbuf);

    if (handle == NULL)
        thread_error_exit("Invalid Device.[Open Live]");
//	assert (handle != NULL);

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB)
        thread_error_exit("Invalid Device.[Ethernet]");

    /* construct the filter string */
    sprintf(filter_exp, "ether dst %02x:%02x:%02x:%02x:%02x:%02x"
                        " and ether proto 0x888e", 
                        local_mac[0], local_mac[1],
                        local_mac[2], local_mac[3],
                        local_mac[4], local_mac[5]);

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) 
        thread_error_exit("Invalid Device.[Filter Compile.]");

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1)
        thread_error_exit("Invalid Device.[Setting Filter.]");

    pcap_freecode(&fp); 
}


//void* keep_alive(void *arg)
//{
//    while (1) {
//        send_eap_packet (EAP_RESPONSE_IDENTITY_KEEP_ALIVE);
//        sleep (60);
//    }
//    return (void*)0;
//}


//int main(int argc, char **argv)
//{   
//    init_info();
//
// //   ----------------------
//    init_device();
//    init_frames ();
//
//    signal (SIGINT, signal_interrupted);
//    signal (SIGTERM, signal_interrupted);    
//
//    printf("######## Lenovo Client ver. %s #########\n", LENOVO_VER);
//    printf("Device:     %s\n", devname);
//    printf("MAC:        %02x:%02x:%02x:%02x:%02x:%02x\n",
//                        local_mac[0],local_mac[1],local_mac[2],
//                        local_mac[3],local_mac[4],local_mac[5]);
//    printf("IP:         %s\n", inet_ntoa(*(struct in_addr*)&local_ip));
//    printf("########################################\n");
//
////    send_eap_packet (EAPOL_LOGOFF);
//    send_eap_packet (EAPOL_START);
//
//	pcap_loop (handle, -1, get_packet, NULL);   /* main loop */
//
//    send_eap_packet (EAPOL_LOGOFF);
//
//	pcap_close (handle);
//    free (eap_response_ident);
//    free (eap_response_md5ch);
//    return EXIT_SUCCESS;
//}
//
