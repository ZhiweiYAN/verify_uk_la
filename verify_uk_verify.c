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
    int send_terminal_len = 0;

    char *send_terminal_cipher_text = NULL;
    int send_terminal_cipher_text_len = 0;

    int pre_pkt_len =0 ;

    ssize_t count = 0;

    unsigned char *cipher_text = NULL;
    unsigned int   cipher_text_len = 0;

    unsigned char *to_proxy_plain_text = NULL;
    unsigned int   to_proxy_plain_text_len = 0;

    unsigned char * from_proxy_plain_text = NULL;
    unsigned int 	from_proxy_plain_text_len = 0;

    VerifyPacketHeader veri_pkt_hdr;
    RSA *terminal_pub_key = NULL;
    RSA *server_private_key = NULL;

    bzero(send_terminal, MAXPACKETSIZE);

    sleep(45);

    //get verifing-packet header and parse the verifing-packet header
    bzero(&veri_pkt_hdr, sizeof(VerifyPacketHeader));
    ret = Parse_verify_pkt_header(packet, packet_size, &veri_pkt_hdr);
    if(-1 == ret) {
        LOG(ERROR)<<"Parse verify pkt header, error.";
        OUTPUT_ERROR;
        ret = PrepareErrorResPacket(send_terminal, ERROR_INCOMPLETE_PKT);
        send_terminal_len = strlen(send_terminal);
        goto Do_verify_procedures_END;
    }

    //get the public key of terminal
//    ret = Get_terminal_pub_key(&terminal_pub_key, &veri_pkt_hdr);
    ret = Get_terminal_pub_key_from_file(&terminal_pub_key);
    if (-1==ret) {
        LOG(ERROR)<<"pub_key_of_the_terminal_id, while finding on server side, error.";
        OUTPUT_ERROR;
        ret = PrepareErrorResPacket(send_terminal, ERROR_NO_TERMINAL_RSA_PUBKEY);
        send_terminal_len = strlen(send_terminal);
        goto Do_verify_procedures_END;
    }

    //get the private key of verify server
//    ret = Get_server_private_key(&server_private_key);
    ret = Get_server_private_key_from_file(&server_private_key);
    if (-1==ret) {
        LOG(ERROR)<<"while finding private key of server, nothing on server side, error.";
        OUTPUT_ERROR;
        ret = PrepareErrorResPacket(send_terminal, ERROR_NO_SRV_RSA_PRIKEY);
        send_terminal_len = strlen(send_terminal);
        goto Do_verify_procedures_END;
    }

    cipher_text = (unsigned char *)packet + VERIFY_PKT_HEADER_LENGTH;
    cipher_text_len = (unsigned int) (veri_pkt_hdr.payload_len);
    to_proxy_plain_text = NULL;
    to_proxy_plain_text_len = 0;

    //De-encrypt and Validate signature
    pre_pkt_len = VERIFY_PKT_MSG_TYPE_LENGTH + VERIFY_PKT_TERMINAL_ID_LENGTH + VERIFY_PKT_WORKER_ID_LENGTH;
    memcpy(send_terminal, packet, pre_pkt_len);

    //malloc? free?
    ret = decrypt_and_validate_sign(server_private_key, terminal_pub_key,
                                    cipher_text, cipher_text_len,
                                    &to_proxy_plain_text, &to_proxy_plain_text_len);


    if(1!=ret) {
        if(ERROR_DECRYPT==ret) {
            LOG(ERROR)<<"while decrypting cipher text, error.";
            OUTPUT_ERROR;
            PrepareErrorResPacket(send_terminal, ERROR_DECRYPT);
            send_terminal_len = strlen(send_terminal);
            goto Do_verify_procedures_END;
        }

        if(ERROR_VALIDATE_SIGN==ret) {
            LOG(ERROR)<<"while validating the signatures, error.";
            OUTPUT_ERROR;
            PrepareErrorResPacket(send_terminal, ERROR_VALIDATE_SIGN);

            send_terminal_len = strlen(send_terminal);
            goto Do_verify_procedures_END;
        } else {
            LOG(ERROR)<<"while decrypting cipher text and validating the signatures, error.";
            OUTPUT_ERROR;
            PrepareErrorResPacket(send_terminal, ERROR_VALIDATE_SIGN);
            send_terminal_len = strlen(send_terminal);
            goto Do_verify_procedures_END;
        }
    }

    from_proxy_plain_text = (unsigned char *)malloc(MAX_SIZE_BUFFER_RECV+1);
    if(NULL==from_proxy_plain_text) {
        LOG(ERROR)<<"memory malloc, failed.";
        OUTPUT_ERROR;
        PrepareErrorResPacket(send_terminal, ERROR_MEMORY_LACK);
        send_terminal_len = strlen(send_terminal);
        goto Do_verify_procedures_END;
    }

    bzero(from_proxy_plain_text, MAX_SIZE_BUFFER_RECV+1);

    //connect to proxy server as random mode, send plain text pkt to proxy server and wait for backward pkt from proxy server
   	//ret = SendRecv_message_to_proxy((char *)to_proxy_plain_text, to_proxy_plain_text_len,
    //                                (char *)from_proxy_plain_text, (int *)&from_proxy_plain_text_len);

	memset(from_proxy_plain_text, 'X', 70);
	from_proxy_plain_text_len = 70;

    //add signature and en-crypt the backward pkt
    if(1==ret) {

        bzero(send_terminal, MAXPACKETSIZE);
        ret = Sign_and_encrypt_plain_text(terminal_pub_key, server_private_key,
                                          (unsigned char *) from_proxy_plain_text,
                                          (unsigned int) from_proxy_plain_text_len,
                                          (unsigned char * *) &send_terminal_cipher_text,
                                          (unsigned int *) &send_terminal_cipher_text_len);
        if(1==ret) {
            memset(send_terminal, ' ', VERIFY_PKT_HEADER_LENGTH);
            memcpy(send_terminal, packet, VERIFY_PKT_MSG_TYPE_LENGTH+VERIFY_PKT_TERMINAL_ID_LENGTH+VERIFY_PKT_WORKER_ID_LENGTH);
            strncpy(send_terminal+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "0", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
            strncpy(send_terminal+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                    "SUCCESS",VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
            memcpy(send_terminal+VERIFY_PKT_PAYLOAD_LEN_POSITION,
                   &send_terminal_cipher_text_len,
                   VERIFY_PKT_PAYLOAD_LEN_LENGTH);
            memcpy(send_terminal+VERIFY_PKT_HEADER_LENGTH,
                   send_terminal_cipher_text, send_terminal_cipher_text_len);
            send_terminal_len = VERIFY_PKT_HEADER_LENGTH + send_terminal_cipher_text_len;

        }

    } else {
        LOG(ERROR)<<"proxy link down.";
        OUTPUT_ERROR;
        PrepareErrorResPacket(send_terminal, ERROR_LINK_PROXY);
        send_terminal_len = strlen(send_terminal);
        goto Do_verify_procedures_END;
    }

    RSA_free(terminal_pub_key);
    RSA_free(server_private_key);



Do_verify_procedures_END:
    count = send( connection_sd, send_terminal, send_terminal_len, 0 );
    DBG("\n%s %s|%s|\n","send to terminal","bytes", send_terminal);

    if (0>count) {
        OUTPUT_ERROR;
    }

    if(NULL!=send_terminal_cipher_text) {
        free(send_terminal_cipher_text);
        send_terminal_cipher_text = NULL;
        send_terminal_cipher_text_len = 0;
    }

    if(NULL!=from_proxy_plain_text) {
        free(from_proxy_plain_text);
        from_proxy_plain_text = NULL;
        from_proxy_plain_text_len =0;
    }

    if(NULL!=to_proxy_plain_text) {
        free(to_proxy_plain_text);
        to_proxy_plain_text=NULL;
    }

    return 1;
}


int PrepareErrorResPacket(char *pkt, int error_code)
{
    int ret = 0;

    // all default values for the following fields are spaces.
    memset(pkt, ' ', VERIFY_PKT_HEADER_LENGTH);


    //Attation plz: the length of msg memo must be less than 45 characters.
    switch (error_code) {
    case ERROR_DECRYPT:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "1", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "decrypt cipher with srv_private_key, error!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_VALIDATE_SIGN:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "2", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "validate term_pkt with ukey_pub_key, error!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_LINK_PROXY:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "3", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "connect to proxy srv, link down!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_INCOMPLETE_PKT:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "4", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "parse verify_pkt header, incomplete!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_NO_TERMINAL_RSA_PUBKEY:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "5", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "find terminal ukey_pub_key, nothing!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_NO_SRV_RSA_PRIKEY:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "6", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "while finding server ukey rsa_private_key, error!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_MEMORY_LACK:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "7", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "server memory, not enough!",
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
    if(NULL==pkt) {
        LOG(ERROR)<<"NULL==pkt pointer";
        return -1;
    }

    if(NULL==pkt_header) {
        LOG(ERROR)<<"NULL==pkt_header pointer";
        return -1;
    }

    if(pkt_len<VERIFY_PKT_HEADER_LENGTH) {
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

    DBG("Pay load bytes: %d, pkt_len: %d, VERIFY_PKT_HEADER_LENGTH: %d", pkt_header->payload_len, pkt_len, VERIFY_PKT_HEADER_LENGTH);
    if(pkt_header->payload_len==pkt_len-VERIFY_PKT_HEADER_LENGTH) {
        return 1;
    } else {
        return -1;
    }

}

int Get_terminal_pub_key_from_file(RSA **terminal_pub_key)
{
    int ret = 0;

    RSA * pub_key = NULL;

    ret =  Generate_pub_key_from_files((char*)PUB_KEY_BARE_BIN_FILE_NAME, &pub_key);
    if(-1==ret) {
        *terminal_pub_key = NULL;
        return -1;
    } else {
        *terminal_pub_key = pub_key;
        return 1;
    }


}


int Get_terminal_pub_key(RSA *key, VerifyPacketHeader *pkt_header)
{

    int ret = 0;
    PGconn* conn_db = NULL;
    char * results_string = NULL;
    int  results_string_len = 0;


    PGresult *res = NULL;

    char *pub_key_bin_buffer = NULL;

    if(NULL==key) {
        LOG(ERROR)<<"NULL==key,input parameters, failed.";
        OUTPUT_ERROR;
        return -1;
    }
    if(NULL==pkt_header) {
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

    //generate query string
    sprintf(query_string, "SELECT pub_key from t_terminal_ukey_pubkey where terminal_id=\'%s\';",
            (char*)(pkt_header->terminal_id) );

//    sprintf(query_string, "SELECT pub_key from t_terminal_ukey_pubkey where terminal_id=\'%s\'";",
    //          (char*)(pkt_header->terminal_id), (char*)(pkt_header->worker_id ));
    /* Send the query to primary database */
    res = PQexec(conn_db, query_string);
    DBG("\n%s |%s|\n","Query: SQL string", query_string);
    LOG(INFO)<<"Query: SQL string: "<<query_string;

    /* Did the record action fail in the primary database? */
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        OUTPUT_ERROR;
        perror(query_string);
        perror(PQerrorMessage(conn_db));

        LOG(INFO)<<query_string;
        LOG(INFO)<<PQerrorMessage(conn_db);

    }

    /* If there are more than one records, return the first one */
    if (PQntuples(res)>=1) {

        /* Only return first tuple*/
        results_string = PQgetvalue(res,0,0);
        results_string_len = PQgetlength(res, 0, 0);

        DBG("\n%s |%s|\n", "RSA Get_terminal_pub_key:", results_string);
        LOG(INFO)<<"RSA Get_terminal_pub_key:"<<results_string;

        pub_key_bin_buffer = unbase64((unsigned char*)results_string, strlen( results_string ));

//		results_string = base64(pub_key_bin_buffer, const unsigned char * input,int length)

        if(NULL!=pub_key_bin_buffer) {
            key = Convert_der_to_rsa_for_pub_key((unsigned char*)pub_key_bin_buffer, PUB_KEY_DER_LEN);
            if(NULL==key) {
                DBG("DER TO RSA, Error");
                LOG(ERROR)<<"Terminal pubkey DER TO RSA, Error.";
                ret = -1;
            }
        }
    }

    if(NULL!=pub_key_bin_buffer) {
        free(pub_key_bin_buffer);
        pub_key_bin_buffer = NULL;
    }


    PQclear(res);
    res = NULL;


    /* Free the DB resource */
    PQfinish((PGconn*)(conn_db));
    conn_db = NULL;

    return ret;

}

int Get_server_private_key(RSA *server_private_key)
{
    int ret = 0;
    return ret;
}

int Get_server_private_key_from_file(RSA **server_private_key)
{
    int ret = 0;
    RSA *key = NULL;

    ret = Get_private_key_from_file(&key, (char *)"./openssl/yao_lagate.pem");
    if(1==ret) {
        *server_private_key = key;
        return 1;
    } else {
        *server_private_key = NULL;
        return -1;
    }

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


