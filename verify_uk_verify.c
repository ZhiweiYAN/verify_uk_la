/*
 * =====================================================================================
 *
 *       Filename:  Verify_procedures.c
 *
 *    Description:  record the payment packet into the database
 *
 *        Version:  1.0
 *        Created:  12/14/2012 10:17:07 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zhi-wei YAN (Jerod YAN), jerod.yan@gmail.com
 *        Company:  DrumTm
 *
 * =====================================================================================
 */
#include "verify_uk_verify.h"


int Do_verify_procedures(int connection_sd, char *packet, int packet_size)
{
	int ret = 0;

    char send_terminal[MAXPACKETSIZE];	
	//char send_proxy[MAXPACKETSIZE];
	int pre_pkt_len =0 ;
	
    ssize_t count = 0;

	unsigned char *cipher_text = NULL;
	unsigned int   cipher_text_len = 0;
	unsigned char *to_proxy_plain_text = NULL;
	unsigned int   to_proxy_plain_text_len = 0;

	VerifyPacketHeader veri_pkt_hdr;
	RSA terminal_pub_key;
	RSA server_private_key;
	
    bzero(send_terminal, MAXPACKETSIZE);

	//get verifing-packet header and parse the verifing-packet header
	bzero(&veri_pkt_hdr, sizeof(VerifyPacketHeader));
	ret = Parse_verify_pkt_header(packet, packet_size, &veri_pkt_hdr);
	if(-1 == ret){
		LOG(ERROR)<<"Parse verify pkt header, error.";
		OUTPUT_ERROR;
		ret = PrepareErrorResPacket(send_terminal, ERROR_INCOMPLETE_PKT);
		goto Do_verify_procedures_END;
		}

	//get the public key of terminal
	ret = Get_terminal_pub_key(&terminal_pub_key, &veri_pkt_hdr);
	if (-1==ret){
		LOG(ERROR)<<"pub_key_of_the_terminal_id, found nothing on server side, error.";
		OUTPUT_ERROR;
		ret = PrepareErrorResPacket(send_terminal, ERROR_NO_TERMINAL_RSA_PUBKEY);
		goto Do_verify_procedures_END;
		}

	//get the private key of verify server
	ret = Get_server_private_key(&server_private_key);
	if (-1==ret){
		LOG(ERROR)<<"while finding private key of server, nothing on server side, error.";
		OUTPUT_ERROR;
		ret = PrepareErrorResPacket(send_terminal, ERROR_NO_SRV_RSA_PRIKEY);		
		goto Do_verify_procedures_END;
		}
	
	cipher_text = (unsigned char *)packet + VERIFY_PKT_HEADER_LENGTH;
	cipher_text_len = (unsigned int) (veri_pkt_hdr.payload_len);
	to_proxy_plain_text = NULL;
	to_proxy_plain_text_len = 0;
	
	//De-encrypt and Validate signature
	pre_pkt_len = VERIFY_PKT_HEADER_LENGTH-VERIFY_PKT_PAYLOAD_LEN_LENGTH-VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH;
	memcpy(send_terminal, packet, pre_pkt_len);
	
	ret = decrypt_and_validate_sign(&server_private_key, &terminal_pub_key, 
			cipher_text, cipher_text_len, 
			&to_proxy_plain_text, &to_proxy_plain_text_len);

	
	if(1>to_proxy_plain_text_len || 1!=ret){
		if(ERROR_DECRYPT==ret){
			LOG(ERROR)<<"while decrypting cipher text, error.";
			OUTPUT_ERROR;
			PrepareErrorResPacket(send_terminal, ERROR_DECRYPT);
			goto Do_verify_procedures_END;
			}
		
		if(ERROR_VALIDATE_SIGN==ret){
			LOG(ERROR)<<"while validating the signatures, error.";
			OUTPUT_ERROR;
			PrepareErrorResPacket(send_terminal, ERROR_VALIDATE_SIGN);
			goto Do_verify_procedures_END;
			}
		
	}

	//connect to proxy server as random mode.

	//connect to proxy server

	//send plain text pkt to proxy server

	//waiting for backward pkt from proxy server
	
	//add signature and en-crypt the backward pkt






Do_verify_procedures_END:
    count = send( connection_sd, send_terminal, strlen(send_terminal), 0 );
    DBG("\n%s |%s|\n","send to Teminal",send_terminal);

    if (0>count) {
        OUTPUT_ERROR;
    }

    return 1;
}


int PrepareErrorResPacket(char *pkt, int error_code)
{
	int ret = 0;

	// all default values for the following fields are spaces.
	memset(pkt, 20, VERIFY_PKT_HEADER_LENGTH);

	switch (error_code){
		case ERROR_DECRYPT:
			strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "1", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
			strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION, 
				"while de-crypting cipher pkt with srv_rsa_private_key, error!",
				VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
			break;
		case ERROR_VALIDATE_SIGN:
			strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "2", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
			strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION, 
				"while validating terminal pkt with ukey rsa_pub_key, error!",
				VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
			break;
		case ERROR_LINK_PROXY:
			strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "3", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
			strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION, 
				"while connecting proxy link, error!",
				VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
			break;
		case ERROR_INCOMPLETE_PKT:
				strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "4", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
				strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION, 
					"while parse pkt header, error!",
					VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
				break;
		case ERROR_NO_TERMINAL_RSA_PUBKEY:
			strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "5", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
			strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION, 
				"while finding terminal ukey rsa_pub_key, error!",
				VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
			break;
		case ERROR_NO_SRV_RSA_PRIKEY:
			strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "6", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
			strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION, 
				"while finding server ukey rsa_private_key, error!",
				VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
			break;
		default:
			break;
		}
	
	memset(pkt+VERIFY_PKT_PAYLOAD_LEN_POSITION, 0, VERIFY_PKT_PAYLOAD_LEN_LENGTH);

	return ret;

	
}


int Parse_verify_pkt_header(char* pkt, int pkt_len, VerifyPacketHeader *pkt_header)
{
	if(NULL==pkt){
		LOG(ERROR)<<"NULL==pkt pointer";
		return -1;
		}

	if(NULL==pkt_header){
		LOG(ERROR)<<"NULL==pkt_header pointer";
		return -1;
		}

	if(pkt_len<VERIFY_PKT_HEADER_LENGTH){
		LOG(ERROR)<<"VERIFY_PKT_HEADER_LENGTH, too short, " <<pkt_len<< " less than " << VERIFY_PKT_HEADER_LENGTH;
		return -1;
		}

	bzero(pkt_header, sizeof(VerifyPacketHeader));
	
	memcpy(pkt_header->msg_type, pkt+VERIFY_PKT_MSG_TYPE_POSITION, VERIFY_PKT_MSG_TYPE_LENGTH);
	memcpy(pkt_header->terminal_id, pkt+VERIFY_PKT_TERMINAL_ID_POSITION, VERIFY_PKT_TERMINAL_ID_LENGTH);
	memcpy(pkt_header->worker_id, pkt+VERIFY_PKT_WORKER_ID_POSITION, VERIFY_PKT_WORKER_ID_LENGTH);
	memcpy(pkt_header->rsp_memo_type, pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION);
	memcpy(pkt_header->rsp_memo_txt, pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION, VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
	memcpy(&(pkt_header->payload_len), pkt+VERIFY_PKT_PAYLOAD_LEN_POSITION, VERIFY_PKT_PAYLOAD_LEN_LENGTH);

	return 1;
	
}


int Get_terminal_pub_key(RSA *key, VerifyPacketHeader *pkt_header)
{
	
    PGconn* conn_db = NULL;

	if(NULL==key){
		LOG(ERROR)<<"NULL==key,input parameters, failed.";
		OUTPUT_ERROR;
		return -1;
		}
	if(NULL==pkt_header){
		LOG(ERROR)<<"NULL==pkt_header, input parameters, failed.";
		OUTPUT_ERROR;
		return -1;
		}

	
	//SQL string is created
    char query_string[MAX_QUERY_LENGTH];
	//char private_key_verify_server[MAX_TEMP_SIZE];	

    bzero(query_string,MAX_QUERY_LENGTH);

	conn_db = Connect_db_server(global_par.system_par.verify_database_user[0],
                                global_par.system_par.verify_database_password[0],
                                global_par.system_par.verify_database_name,
                                global_par.system_par.verify_ip_addr_array[0]);


    if (NULL==conn_db) {
        OUTPUT_ERROR;
        return -1;
    }

    /* Free the DB resource */
    PQfinish((PGconn*)(conn_db));
    conn_db = NULL;

	return 1;
		
}

int Get_server_private_key(RSA *server_private_key)
{

	return 1;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Record_pkt_regular_table
 *  Description:  record the payment packets
 * =====================================================================================
 */
int Record_pkt_regular_table( char *pkt, int pkt_size,
                              PGconn *conn_db,
                              char* backward_pkt)
{
    return 1;
}


int Get_back_pkt_for_business_srv(char *pkt,int pkt_size, char* backward_pkt)
{
    
    return 1;
}


PGconn *Connect_db_server(char *user_name, char *password,char *db_name,char *ip_addr)
{
    PGconn  *conn;
    char conn_string[COMM_LENGTH];

    /* Check input parameters */
    if (NULL==ip_addr||NULL==user_name||NULL==password||NULL==db_name) {
        OUTPUT_ERROR;
        return NULL;
    }

    bzero(conn_string,COMM_LENGTH);
    sprintf(conn_string,"user=%s password=%s dbname=%s hostaddr=%s",user_name,password,db_name,ip_addr);
    DBG("Connect to DB: |%s|\n",conn_string);
	LOG(INFO)<<"Connect to DB:" << conn_string;
	
    /* Connect the database */
    conn = PQconnectdb(conn_string);

    if (PQstatus(conn) != CONNECTION_OK) {
		LOG(ERROR)<<"Connect to DB, failed." << "detail: " <<conn_string;
        OUTPUT_ERROR;
        return NULL;
    }

    return conn;
}


