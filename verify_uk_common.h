
#ifndef  VERIFY_UK_COMMON_H_INC
#define  VERIFY_UK_COMMON_H_INC

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <assert.h>

#include "libpq-fe.h"

#include <glog/logging.h>
#include "../config_h_c/config.h"
#include "./openssl/openssl_sign_encrypt_rsa.h"

#define CONFIGFILENAME "../cfg_files/global.cfg"


/* for the common packet header */
#define COMPANY_ID_POSITION 0
#define COMPANY_ID_LENGTH 2

#define SERVICE_ID_POSITION 2
#define SERVICE_ID_LENGTH 2

#define INNER_FLAG_POSITION 4
#define INNER_FLAG_LENGTH 2
#define INVOICE_FLAG "01"

#define TERMINAL_ID_POSITION 6
#define TERMINAL_ID_LENGTH 8

#define WORKER_ID_POSITION 14
#define WORKER_ID_LENGTH 4

#define CONTRACT_ID_POSITION 18
#define CONTRACT_ID_LENGTH 30

#define PHONE_NUMBER_POSITION 48
#define PHONE_NUMBER_LENGTH 30

#define MONEY_POSITION 78
#define MONEY_LENGTH 10

#define INNER_SUCCESS_FLAG_POSITION 88
#define INNER_SUCCESS_FLAG_LENGTH 2

#define ERROR_MEMO_POSITION 90
#define ERROR_MEMO_LENGTH 30

#define INFO_NUMBER_LENGTH 10
#define INFO_FORWARD_PKT_LENGTH 10
#define INFO_BACKWARD_PKT_LENGTH 10

#define COMMON_PACKET_HEADER_LENGTH (COMPANY_ID_LENGTH+SERVICE_ID_LENGTH+INNER_FLAG_LENGTH+TERMINAL_ID_LENGTH+WORKER_ID_LENGTH+CONTRACT_ID_LENGTH+PHONE_NUMBER_LENGTH+MONEY_LENGTH+INNER_SUCCESS_FLAG_LENGTH+ERROR_MEMO_LENGTH)

//define verified-packet header
#define VERIFY_PKT_MSG_TYPE_POSITION 0
#define VERIFY_PKT_MSG_TYPE_LENGTH 2

#define VERIFY_PKT_TERMINAL_ID_POSITION 2
#define VERIFY_PKT_TERMINAL_ID_LENGTH 8

#define VERIFY_PKT_WORKER_ID_POSITION 10
#define VERIFY_PKT_WORKER_ID_LENGTH 4

#define VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION 14
#define VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH 1

#define VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION 15
#define VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH 45

#define VERIFY_PKT_PAYLOAD_LEN_POSITION 60
#define VERIFY_PKT_PAYLOAD_LEN_LENGTH 4

#define VERIFY_PKT_HEADER_LENGTH (VERIFY_PKT_MSG_TYPE_LENGTH+VERIFY_PKT_TERMINAL_ID_LENGTH+VERIFY_PKT_WORKER_ID_LENGTH+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH+VERIFY_PKT_PAYLOAD_LEN_LENGTH)


#define MAX_QUERY_LENGTH 100000
#define MAX_TEMP_SIZE   40000


#define PROCESS_SHARE_ID 108 

#define BACKLOG 1024
#define MAX_PROCESS_NUMBRER 1024

#define DELAY_MONITOR_TIME 2

#define PROCESS_LIEF_TIME_INC_MULTIPLY_FACTOR 2

#define VERIFY_PROCESS_DEADLINE 240
#define MAX_SIZE_BUFFER_RECV 400000
#define MAXPACKETSIZE 400000
#define COMM_LENGTH 256


enum VERIFY_ERROR_CODE{
	ERROR_DECRYPT = -1,
	ERROR_VALIDATE_SIGN = -2,
	ERROR_LINK_PROXY = -3,
	ERROR_INCOMPLETE_PKT = -4,
	ERROR_NO_TERMINAL_RSA_PUBKEY = -5,
	ERROR_NO_SRV_RSA_PRIKEY = -6	
};


#ifdef DEBUG
# define DBG(format, args...) printf(format, ##args)
#else
# define DBG(format, args...)
#endif

#define OUTPUT_OK do{printf("[\033[32mOK\033[0m]\n");fflush(NULL);}while(0);
#define OUTPUT_ERROR do{ printf("[\033[31mERROR\033[0m] %s:%d,%s()\n",__FILE__, __LINE__, __FUNCTION__);LOG(ERROR)<<__FUNCTION__;fflush(NULL);}while(0);

//Fesponse code for downlink to terminals.
enum ResponseCodeFromVerifySrv{RSP_SUCCESS=0,
	RSP_UN_CRYPT_ERROR=1, 
	RSP_UN_SIGN=2,
	RSP_PROXY_LINK_DOWN=3,
	RSP_OTHER_UNKNOW_ERROR=9
};

struct CommonPacketHeader {
    char company_id[COMPANY_ID_LENGTH+1];
    char service_id[SERVICE_ID_LENGTH+1];
    char inner_flag[INNER_FLAG_LENGTH+1];
    char terminal_id[TERMINAL_ID_LENGTH+1];
    char worker_id[WORKER_ID_LENGTH+1];
    char contract_id[CONTRACT_ID_LENGTH+1];
    char phone_number[PHONE_NUMBER_LENGTH+1];
    char money[MONEY_LENGTH+1];
    char inner_success_flag[INNER_SUCCESS_FLAG_LENGTH+1];
    char error_memo[ERROR_MEMO_LENGTH+1];
};


struct VerifyPacketHeader{
	char msg_type[VERIFY_PKT_MSG_TYPE_LENGTH+1];
	char terminal_id[VERIFY_PKT_TERMINAL_ID_LENGTH+1];
	char worker_id[VERIFY_PKT_WORKER_ID_LENGTH+1];
	char rsp_memo_type[VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH+1];
	char rsp_memo_txt[VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH+1];
	int payload_len;
};


enum ProcessType {NORMAL_PROCESS=0,VERIFY_PROCESS};

struct ChildProcessStatus {
    pid_t pid;
    int life_time;
    int deadline;
    enum ProcessType type;
    int process_step;
};

struct ShareMemProcess {
    struct ChildProcessStatus process_table[MAX_PROCESS_NUMBRER];
};


#endif   /* ----- #ifndef VERIFY_UK_COMMON_H_INC  ----- */

