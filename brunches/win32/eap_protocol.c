/*
 * =====================================================================================
 *
 *       Filename:  eap_protocol.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  07/07/2009 02:55:00 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BOYPT (PT), pentie@gmail.com
 *        Company:  http://apt-blog.co.cc
 *
 * =====================================================================================
 */
#include 	<assert.h>
#include	"eap_protocol.h"
//#include	"zruijie.h"
//#include	"blog.h"
#include	"md5.h"

static char*   
get_md5_digest(const char* str, size_t len);
static void 
fill_password_md5(uint8_t attach_key[], uint8_t eap_id);
DWORD WINAPI keep_alive();
DWORD WINAPI wait_exit();

/* #####   TYPE DEFINITIONS   ######################### */
/*-----------------------------------------------------------------------------
 *  报文缓冲区，由init_frame函数初始化。
 *-----------------------------------------------------------------------------*/
//uint8_t             eapol_start[1000];            /* EAPOL START报文 */
//uint8_t             eapol_logoff[1000];           /* EAPOL LogOff报文 */
//uint8_t             eap_response_ident[1000]; /* EAP RESPON/IDENTITY报文 */
//uint8_t             eap_response_md5ch[1000]; /* EAP RESPON/MD5 报文 */
//uint8_t             eap_life_keeping[45];
extern enum STATE   state;

extern pcap_t       *handle;

void
action_eapol_success(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
    extern HANDLE       hLIFE_KEEP_THREAD;

    state = ONLINE;

    /* 打开保持线程 */
    hLIFE_KEEP_THREAD = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)keep_alive, 0, 0, 0);
    edit_info_append("-->ONLINE\n");        
}

void
action_eapol_failre(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
//	extern HANDLE		hEXIT_WAITER;
	extern HANDLE		hLIFE_KEEP_THREAD;

    print_server_info (packet);

    state = READY;

    DWORD code = 0;
    GetExitCodeThread (hLIFE_KEEP_THREAD, &code);
    if (code == STILL_ACTIVE) {
        TerminateThread (hLIFE_KEEP_THREAD, 0);
        WaitForSingleObject (hLIFE_KEEP_THREAD, 1000);
    }
    pcap_breakloop (handle);
    edit_info_append("-->FAILURE\n");        

}

void
action_eap_req_idnty(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
	state = CONNECTING;
    eap_response_ident[0x13] = eap_head->eap_id;
    send_eap_packet(EAP_RESPONSE_IDENTITY);
    edit_info_append("-->SENT IDN-RES\n");
}

void
action_eap_req_md5_chg(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
	state = CONNECTING;
    fill_password_md5((uint8_t*)eap_head->eap_md5_challenge, eap_head->eap_id);
    eap_response_md5ch[0x13] = eap_head->eap_id;
    send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
    edit_info_append("-->SENT PSW-RES\n");    
}

DWORD WINAPI keep_alive()
{
    while (1) {
        send_eap_packet (EAP_RESPONSE_IDENTITY_KEEP_ALIVE);
        Sleep (60000);
    }
	return 0;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  send_eap_packet
 *  Description:  根据eap类型发送相应数据包
 * =====================================================================================
 */
void 
send_eap_packet(enum EAPType send_type)
{
    uint8_t         *frame_data;
    int             frame_length = 0;
    extern size_t username_length;

    switch(send_type){
        case EAPOL_START:
            frame_data= eapol_start;
            frame_length = sizeof(eapol_start);
            break;
        case EAPOL_LOGOFF:
            frame_data = eapol_logoff;
            frame_length = sizeof(eapol_logoff);
            break;
        case EAP_RESPONSE_IDENTITY:
            frame_data = eap_response_ident;
            frame_length = 54 + username_length;
            break;
        case EAP_RESPONSE_MD5_CHALLENGE:
            frame_data = eap_response_md5ch;
            frame_length = 14 + 4 + 6 + 16 + username_length + 14;
            break;
        case EAP_RESPONSE_IDENTITY_KEEP_ALIVE:
            frame_data = eapol_keepalive;
            frame_length = sizeof(eapol_keepalive);
            break;
        default:
            return;
    }
    pcap_sendpacket(handle, frame_data, frame_length);
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fill_password_md5
 *  Description:  给RESPONSE_MD5_Challenge报文填充相应的MD5值。
 *  只会在接受到REQUEST_MD5_Challenge报文之后才进行，因为需要
 *  其中的Key
 * =====================================================================================
 */
void 
fill_password_md5(uint8_t attach_key[], uint8_t eap_id)
{
    extern char password[];
    extern int  password_length;
    char *psw_key; 
    char *md5;

    psw_key = malloc(1 + password_length + 16);
    psw_key[0] = eap_id;
    memcpy (psw_key + 1, password, password_length);
    memcpy (psw_key + 1 + password_length, attach_key, 16);

    md5 = get_md5_digest(psw_key, 1 + password_length + 16);
    memcpy (eap_response_md5ch + 14 + 10, md5, 16);
//    memset (eap_response_md5ch + 14 + 5, eap_id, 1);
    free (psw_key);
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




/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  print_server_info
 *  Description:  提取中文信息并打印输出
 * =====================================================================================
 */

void 
print_server_info (const uint8_t *packet)
{

    if (0x2ffc == ntohs(*(uint16_t*)(packet + 0x18))) {
        char info_str [1024] = {0};
        uint8_t length = *(uint8_t*)(packet + 0x1a);
        strncpy (info_str, (const char*)(packet + 0x1b), length);
        edit_info_append (info_str);
    }

}


