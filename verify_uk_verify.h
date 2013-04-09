
#ifndef  VERIFY_UK_VERIFY_H_INC
#define  VERIFY_UK_VERIFY_H_INC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "verify_uk_common.h"
#include "parse_pkt_common_header.h"
#include "verify_uk_monitor_process.h"
#include "libpq-fe.h"
#include "verify_uk_comm_proxy.h"


#include "./openssl/openssl_sign_encrypt_rsa.h"

int Do_verify_procedures(int connection_sd,char *packet,int packet_size);

int Prepare_error_response_packet(char *pkt, int error_code);
int Parse_verify_pkt_header(char* pkt, int pkt_len, VerifyPacketHeader *pkt_header);

int Get_terminal_pub_key_from_db(RSA **key, VerifyPacketHeader *pkt_header);
int Get_server_private_key_from_db(RSA **server_private_key);

int Get_terminal_pub_key_from_file(RSA **terminal_pub_key, VerifyPacketHeader *pkt_hdr);
int Get_server_private_key_from_file(RSA **server_private_key, char *file_name);

int Transform_server_private_key_from_file_into_db(char* file_name);
int Transform_terminal_public_key_from_file_into_db(char* file_name);

PGconn *Connect_db_server(char *user_name, char *password,char *db_name,char *ip_addr);


int Record_pkt_regular_table( char *pkt, int pkt_size,PGconn *conn_db, char* backward_pkt);

int Get_pkt_record_flag(char *forward_pkt_text);
int Save_trans_pkt_into_backup_db(struct CommonPacketHeader *common_pkt_header, char *cipher_forward_pkt, int cipher_forward_pkt_len, char* cipher_backward_pkt, int cipher_backward_pkt_len);



#endif   /* ----- #ifndef VERIFY_UK_VERIFY_H_INC  ----- */
