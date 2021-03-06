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

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Do_verify_procedures
 *  Description:  Verify the incoming packet from terminals, transfer the unencrypted
 *                plain packet to proxy servers if the packet is verified successfully.
 * =====================================================================================
 */
int Do_verify_procedures(int connection_sd, char *packet, int packet_size)
{
    int ret = 0;

    char buf_send_terminal[MAX_SIZE_BUFFER_SEND];
    int buf_send_terminal_len = 0;

    char *send_terminal_cipher_text = NULL;
    int send_terminal_cipher_text_len = 0;

    int pre_pkt_len =0 ;

    ssize_t count = 0;

    unsigned char *cipher_text = NULL;
    unsigned int   cipher_text_len = 0;

    unsigned char *to_proxy_plain_text = NULL;
    unsigned int   to_proxy_plain_text_len = 0;

    unsigned char *from_proxy_plain_text = NULL;
    unsigned int from_proxy_plain_text_len = 0;

    VerifyPacketHeader veri_pkt_hdr;
    struct CommonPacketHeader *common_pkt_header = NULL;

    RSA *terminal_pub_key = NULL;
    RSA *server_private_key = NULL;


    if(NULL==packet || 0>=packet_size) {
        LOG_ERROR("The pointer of pkt from terminals is NULL.\n");
        return -1;
    }

    // the variable buf_send_terminal is static array.
    bzero(buf_send_terminal, MAX_SIZE_BUFFER_SEND);

    common_pkt_header = (struct CommonPacketHeader *)malloc(sizeof(struct CommonPacketHeader));
    if (NULL == common_pkt_header) {
        LOG_ERROR("malloc memory of common_pkt_header, failed\n");
        return -1;
    } else {
        bzero(common_pkt_header,sizeof(struct CommonPacketHeader));
    }


    //sleep to debug option for multi-process
    //sleep(45);

    //get verifying-packet header and parse the verifying-packet header
    bzero(&veri_pkt_hdr, sizeof(VerifyPacketHeader));
    memset(buf_send_terminal,' ', VERIFY_PKT_HEADER_LENGTH+COMMON_PACKET_HEADER_LENGTH);
    ret = Parse_verify_pkt_header(packet, packet_size, &veri_pkt_hdr);
    if(-1 == ret) {
        OUTPUT_ERROR;
        LOG_ERROR("Failed to parse verify packet header: terminal_id=%s, worker_id=%s.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
        ret = Prepare_error_response_packet(buf_send_terminal, ERROR_INCOMPLETE_PKT);
        buf_send_terminal_len = strlen(buf_send_terminal);
        goto Do_verify_procedures_END;
    } else {
        DBG("Success to parse verify packet header: terminal_id=%s, worker_id=%s.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
    }


    //get the public key of terminal
    ret = Get_terminal_pub_key_from_db(&terminal_pub_key, &veri_pkt_hdr);
    //ret = Get_terminal_pub_key_from_file(&terminal_pub_key, &veri_pkt_hdr);
    if (-1==ret) {
        OUTPUT_ERROR;
        LOG_ERROR("Failed to get terminal %s:%s public rsa-key.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
        ret = Prepare_error_response_packet(buf_send_terminal, ERROR_NO_TERMINAL_RSA_PUBKEY);
        buf_send_terminal_len = strlen(buf_send_terminal);
        goto Do_verify_procedures_END;
    } else {
        DBG("Success to get terminal %s:%s public rsa-key.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);

    }

    //get the private key of verify server
    ret = Get_server_private_key_from_db(&server_private_key);
    //ret = Get_server_private_key_from_file(&server_private_key, (char *)SERVER_PRIVATE_KEY_PEM_FILE);
    if (-1==ret) {
        OUTPUT_ERROR;
        LOG_ERROR("Failed to get server rsa key pair.\n");
        ret = Prepare_error_response_packet(buf_send_terminal, ERROR_NO_SRV_RSA_PRIKEY);
        buf_send_terminal_len = strlen(buf_send_terminal);
        goto Do_verify_procedures_END;
    } else {
        DBG("Success to get server rsa key pair.\n");
    }

    cipher_text = (unsigned char *)packet + VERIFY_PKT_HEADER_LENGTH;
    cipher_text_len = packet_size - VERIFY_PKT_HEADER_LENGTH;
    to_proxy_plain_text = NULL;
    to_proxy_plain_text_len = 0;

    pre_pkt_len = VERIFY_PKT_MSG_TYPE_LENGTH + VERIFY_PKT_TERMINAL_ID_LENGTH + VERIFY_PKT_WORKER_ID_LENGTH;
    memcpy(buf_send_terminal, packet, pre_pkt_len);

    //malloc? free?
    //The memory for the variable 'to_proxy_plain_text' will be allocated in the
    //function decrypt_and_validate_sign().
    //De-encrypt and Validate signature
    ret = decrypt_and_validate_sign(server_private_key, terminal_pub_key,
                                    cipher_text, cipher_text_len,
                                    &to_proxy_plain_text, &to_proxy_plain_text_len);


    //here, we use 'if' clause instead of 'switch' because there are 'goto' clauses.
    if(1!=ret) {
        if(ERROR_DECRYPT==ret) {
            OUTPUT_ERROR;
            LOG_ERROR("while decrypting cipher text from %s %s, error.\n",veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
            Prepare_error_response_packet(buf_send_terminal, ERROR_DECRYPT);
            buf_send_terminal_len = strlen(buf_send_terminal);
            goto Do_verify_procedures_END;
        }
        if(ERROR_VALIDATE_SIGN==ret) {
            OUTPUT_ERROR;
            LOG_ERROR("while validating the signatures from %s %s, error.\n",veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
            Prepare_error_response_packet(buf_send_terminal, ERROR_VALIDATE_SIGN);
            buf_send_terminal_len = strlen(buf_send_terminal);
            goto Do_verify_procedures_END;
        } else {
            OUTPUT_ERROR;
            LOG_ERROR("while decrypting cipher text and validating the signatures from %s %s, error.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
            Prepare_error_response_packet(buf_send_terminal, ERROR_VALIDATE_SIGN);
            buf_send_terminal_len = strlen(buf_send_terminal);
            goto Do_verify_procedures_END;
        }
    }

    DBG("Send to proxy packet %d bytes: |%s|.\n", to_proxy_plain_text_len, to_proxy_plain_text);

    //Prepare the memory for the packet from the server proxy.
    from_proxy_plain_text = (unsigned char *)malloc(MAX_SIZE_BUFFER_RECV);
    if(NULL==from_proxy_plain_text) {
        OUTPUT_ERROR;
        LOG(ERROR)<<"memory malloc for the variable from_proxy_plain_text, failed.";
        Prepare_error_response_packet(buf_send_terminal, ERROR_MEMORY_LACK);
        buf_send_terminal_len = strlen(buf_send_terminal);
        goto Do_verify_procedures_END;
    } else {
        bzero(from_proxy_plain_text, MAX_SIZE_BUFFER_RECV);
    }

    //connect to proxy server as random mode, send plain text pkt to proxy server
    //and wait for backward pkt from proxy server.
    from_proxy_plain_text_len = 0;
    ret = SendRecv_message_to_proxy((char *)to_proxy_plain_text, to_proxy_plain_text_len,
                               (char *)from_proxy_plain_text, (int *)&from_proxy_plain_text_len);

    //begin debug
    //ret = 1;
    //from_proxy_plain_text_len = 16;
    //memcpy(from_proxy_plain_text, "1234567890ABCDEF", from_proxy_plain_text_len);
    //end debug

    //add signature and en-crypt the backward pkt
    if(1==ret && 0< from_proxy_plain_text_len) {

        bzero(buf_send_terminal, MAX_SIZE_BUFFER_SEND);
        send_terminal_cipher_text_len = 0;
        //the variable 'send_terminal_cipher_text' memory is allocated in the function 'Sign_and_encrypt_plain_text'.
        ret = Sign_and_encrypt_plain_text(terminal_pub_key, server_private_key,
                                          (unsigned char *) from_proxy_plain_text,
                                          (unsigned int) from_proxy_plain_text_len,
                                          (unsigned char * *) &send_terminal_cipher_text,
                                          (unsigned int *) &send_terminal_cipher_text_len);

        //if we can add signature and encrypt the backward packet successfully.
        //memset(buf_send_terminal, 0, buf_send_terminal_len);
        if(1==ret && 0<send_terminal_cipher_text_len) {
            memset(buf_send_terminal, '0', VERIFY_PKT_HEADER_LENGTH);
            memcpy(buf_send_terminal, packet, VERIFY_PKT_MSG_TYPE_LENGTH+VERIFY_PKT_TERMINAL_ID_LENGTH+VERIFY_PKT_WORKER_ID_LENGTH);
            memset(buf_send_terminal+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, '0', VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
            strncpy(buf_send_terminal+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                    "SUCCESS",VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);

            char cipher_text_len_str[VERIFY_PKT_PAYLOAD_LEN_LENGTH+1];
            snprintf(cipher_text_len_str, VERIFY_PKT_PAYLOAD_LEN_LENGTH, "%06d", send_terminal_cipher_text_len);
            memcpy(buf_send_terminal+VERIFY_PKT_PAYLOAD_LEN_POSITION,
                   cipher_text_len_str,
                   VERIFY_PKT_PAYLOAD_LEN_LENGTH);
            memcpy(buf_send_terminal+VERIFY_PKT_HEADER_LENGTH,
                   send_terminal_cipher_text, send_terminal_cipher_text_len);
            buf_send_terminal_len = VERIFY_PKT_HEADER_LENGTH + send_terminal_cipher_text_len;
        }
    } else {

        //if there are errors when we send pkts to the proxy server.
        OUTPUT_ERROR;
        LOG_ERROR("The link with proxy server seems down. \nThe packet from proxy server = |%s|", from_proxy_plain_text);
        //LOG(ERROR)<<"The link with proxy server seems down.";
        Prepare_error_response_packet(buf_send_terminal, ERROR_LINK_PROXY);
        buf_send_terminal_len = strlen(buf_send_terminal);
        //if link down, we also record the trans, Not goto Do_verify_procedures_END;
    }


    if(1 == Get_pkt_record_flag((char *)to_proxy_plain_text)) {

        /* Get the common packet header */
        // we judge whether the packet from proxy server is accepted or not.
        if(0< from_proxy_plain_text_len) {
            ret = Get_common_header((char *)from_proxy_plain_text, common_pkt_header);
            DBG("Common pkt header from downlink packet  %s, %s\n", common_pkt_header->company_id, common_pkt_header->service_id);
        } else {
            ret = Get_common_header((char *)to_proxy_plain_text, common_pkt_header);
            DBG("Common pkt header from uplink packet %s, %s\n", common_pkt_header->company_id, common_pkt_header->service_id);
        }


        ret = Save_trans_pkt_into_backup_db(common_pkt_header, packet, packet_size, buf_send_terminal, buf_send_terminal_len);

    }

    //label for return.
Do_verify_procedures_END:
    //send the packet to terminal
    count = send(connection_sd, buf_send_terminal, buf_send_terminal_len, 0 );
    DBG("Send to terminal with %d bytes: |%s|\n", count, buf_send_terminal);

    if (0>count) {
        OUTPUT_ERROR;
        LOG_ERROR("Failed to send backward to terminals.\n");
    }

    if(NULL!=terminal_pub_key) {
        RSA_free(terminal_pub_key);
        terminal_pub_key = NULL;
    }
    if(NULL!=server_private_key) {

        RSA_free(server_private_key);
        server_private_key = NULL;
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

    if(NULL!=common_pkt_header) {
        free(common_pkt_header);
        common_pkt_header = NULL;
    }


    return 1;
}



int Save_trans_pkt_into_backup_db(struct CommonPacketHeader *common_pkt_header, char *cipher_forward_pkt, int cipher_forward_pkt_len, char* cipher_backward_pkt, int cipher_backward_pkt_len)
{

    int ret = 0;


    PGconn* conn_db = NULL;
    PGresult *res = NULL;

    char *uplink_pkt_ascii = NULL;
    char *downlink_pkt_ascii = NULL;

    int i =0;
    time_t t = 0;
    int verify_srv_num = 0;
    VerifyPacketHeader veri_pkt_hdr;



//SQL string is created
    char query_string[MAX_QUERY_LENGTH];
    bzero(query_string,MAX_QUERY_LENGTH);


    //get verifying-packet header and parse the verifying-packet header
    bzero(&veri_pkt_hdr, sizeof(VerifyPacketHeader));
    ret = Parse_verify_pkt_header(cipher_forward_pkt, cipher_forward_pkt_len, &veri_pkt_hdr);
    if(-1 == ret) {
        OUTPUT_ERROR;
        LOG_ERROR("Failed to parse verify packet header: terminal_id=%s, worker_id=%s.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
        return -1;
    } else {
        DBG("Success to parse verify packet header: terminal_id=%s, worker_id=%s.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
    }



//choose the index of a verify server at random
    t = time(NULL);
    srand((unsigned int) t);
    verify_srv_num = global_par.system_par.verify_number;

    if(1==verify_srv_num) {
        i = 0;
    } else {
        i = 0 + (int) ( 1.0 * verify_srv_num * rand() / (RAND_MAX + 1.0));

    }

    conn_db = Connect_db_server(global_par.system_par.verify_database_user[i],
                                global_par.system_par.verify_database_password[i],
                                global_par.system_par.verify_database_name,
                                global_par.system_par.verify_ip_addr_array[i]);
    if (NULL==conn_db) {
        OUTPUT_ERROR;
        return -1;
    }

// we do check the pointer of cipher_xxxx_pkt in Binary2str function
    downlink_pkt_ascii = Binary2str( (unsigned char *) cipher_backward_pkt, cipher_backward_pkt_len);
    uplink_pkt_ascii = Binary2str( (unsigned char *) cipher_forward_pkt, cipher_forward_pkt_len);

    //generate query string
    sprintf(query_string, "INSERT INTO trans_pkt_backup(TERMINAL_ID, WORKER_ID, COMPANY_ID, SERVICE_ID, INNER_FLAG, CONTRACT_ID, PHONE_NUMBER, MONEY, cipher_forward_pkt, cipher_backward_pkt) VALUES (\'%s\', \'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\', trim(\'%s\'), trim(\'%s\') );",
            veri_pkt_hdr.terminal_id,
            veri_pkt_hdr.worker_id,
            common_pkt_header->company_id,
            common_pkt_header->service_id,
            common_pkt_header->inner_flag,
            common_pkt_header->contract_id,
            common_pkt_header->phone_number,
            common_pkt_header->money,
            uplink_pkt_ascii,
            downlink_pkt_ascii);

    /* Send the query to primary database */
    res = PQexec(conn_db, query_string);
    DBG("\n%s |%s|\n","Query: SQL string", query_string);
    //DLOG(INFO)<<"Query: SQL string: "<<query_string;

    /* Did the record action fail in the primary database? */
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        OUTPUT_ERROR;
        perror(query_string);
        perror(PQerrorMessage(conn_db));

        LOG(ERROR)<<query_string;
        LOG(ERROR)<<PQerrorMessage(conn_db);
        ret = -1;

    }

    if(NULL!=downlink_pkt_ascii) {
        free(downlink_pkt_ascii);
        downlink_pkt_ascii = NULL;
    }
    if(NULL!=uplink_pkt_ascii) {
        free(uplink_pkt_ascii);
        uplink_pkt_ascii = NULL;
    }

    return ret;

}

//Similar to Get_import_level() functions.
// 1 means to save it into db, others not.
int Get_pkt_record_flag(char *forward_pkt_text)
{
    int success = 0;
    int com_id = 0;
    int pkt_id = 0;
    int im_level = 0;
    char *e = NULL;

    struct CommonPacketHeader *common_pkt_header = NULL;

    common_pkt_header =(struct CommonPacketHeader *) malloc(sizeof(struct CommonPacketHeader));
    if (NULL == common_pkt_header) {
        LOG_ERROR("malloc error when parsing Common packet header, failed");
        return 0;
    } else {
        bzero(common_pkt_header,sizeof(struct CommonPacketHeader));
    }

    /* Get the forward_pkt_text header */
    DBG("Forward_pkt_text:|%s|.\n", forward_pkt_text);
    success = Get_common_header(forward_pkt_text, common_pkt_header);

    /* Get the company id */
    com_id = strtol(common_pkt_header->company_id,&e,10);

    /*Get the service type*/
    pkt_id = strtol(common_pkt_header->service_id,&e,10);

    /* Get the important level value */
    im_level = global_par.company_par_array[com_id].packet_important_level[pkt_id];
    free(common_pkt_header);

    common_pkt_header = NULL;

    DBG("The importance level of the packet = %d.\n", im_level);

    if(0==im_level) {
        //It is not important packet.
        //we do not record it into db.
        return -1;
    } else {
        return 1;
    }

    /*
    	switch (im_level) {
        case CHARGE_PKT_IMPORTANCE_LEVEL:
            return 1;
            break;
        case REVERSAL_PKT_IMPORTANCE_LEVEL:
            return 1;
            break;
        case QUERY_PKT_IMPORTANCE_LEVEL:
            return 1;
            break;
        default:
            return 1;
            break;
        }
        */

}
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Prepare_error_response_packet
 *  Description:  Generate backward packet according to the error codes.
 * =====================================================================================
 */
int Prepare_error_response_packet(char *pkt, int error_code)
{
    int ret = 0;
    char *common_pkt_erro_code = NULL;
    char *common_pkt_erro_info = NULL;

    // all default values for the following fields are spaces.
    memset(pkt, ' ', VERIFY_PKT_HEADER_LENGTH);

    common_pkt_erro_info = pkt + VERIFY_PKT_HEADER_LENGTH + ERROR_MEMO_POSITION;
    common_pkt_erro_code = pkt + VERIFY_PKT_HEADER_LENGTH + INNER_SUCCESS_FLAG_POSITION;

    //memcpy(common_pkt_erro_code, INNER_ERROR_CODE, INNER_SUCCESS_FLAG_LENGTH);
    //Attation plz: the length of msg memo must be less than 45 characters.
    switch (error_code) {
    case ERROR_DECRYPT:
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION,
               "01", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
               ERROR_DECRYPT_INFO,
               strlen(ERROR_DECRYPT_INFO));
        //memcpy(common_pkt_erro_info, ERROR_DECRYPT_INFO, strlen(ERROR_DECRYPT_INFO));
        break;
    case ERROR_VALIDATE_SIGN:
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION,
               "02", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
               ERROR_VALIDATE_SIGN_INFO,
               strlen(ERROR_VALIDATE_SIGN_INFO));
        //memcpy(common_pkt_erro_info, ERROR_VALIDATE_SIGN_INFO, strlen(ERROR_VALIDATE_SIGN_INFO));
        break;
    case ERROR_LINK_PROXY:
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION,
               "03", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
               ERROR_LINK_PROXY_INFO,
               strlen(ERROR_LINK_PROXY_INFO));
        //memcpy(common_pkt_erro_info, ERROR_LINK_PROXY_INFO, strlen(ERROR_LINK_PROXY_INFO));
        break;
    case ERROR_INCOMPLETE_PKT:
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION,
               "04", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
               ERROR_INCOMPLETE_PKT_INFO,
               strlen(ERROR_INCOMPLETE_PKT_INFO));
        //memcpy(common_pkt_erro_info, ERROR_INCOMPLETE_PKT_INFO, strlen(ERROR_INCOMPLETE_PKT_INFO));
        break;
    case ERROR_NO_TERMINAL_RSA_PUBKEY:
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION,
               "05", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
               ERROR_NO_TERMINAL_RSA_PUBKEY_INFO,
               strlen(ERROR_NO_TERMINAL_RSA_PUBKEY_INFO));
        //memcpy(common_pkt_erro_info, ERROR_NO_TERMINAL_RSA_PUBKEY_INFO, strlen(ERROR_NO_TERMINAL_RSA_PUBKEY_INFO));
        break;
    case ERROR_NO_SRV_RSA_PRIKEY:
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION,
               "06", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
               ERROR_NO_SRV_RSA_PRIKEY_INFO,
               strlen(ERROR_NO_SRV_RSA_PRIKEY_INFO));
        //memcpy(common_pkt_erro_info, ERROR_NO_SRV_RSA_PRIKEY_INFO, strlen(ERROR_NO_SRV_RSA_PRIKEY_INFO));
        break;
    case ERROR_MEMORY_LACK:
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION,
               "07", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        memcpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
               ERROR_MEMORY_LACK_INFO,
               strlen(ERROR_MEMORY_LACK_INFO));
        //memcpy(common_pkt_erro_info, ERROR_MEMORY_LACK_INFO, strlen(ERROR_MEMORY_LACK_INFO));
        break;

    default:
        break;
    }

    memset(pkt+VERIFY_PKT_PAYLOAD_LEN_POSITION, 0, VERIFY_PKT_PAYLOAD_LEN_LENGTH);

    return ret;


}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Parse_verify_pkt_header
 *  Description:  Parse the incoming packet from terminals
 * =====================================================================================
 */
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
        LOG_ERROR("Verify packet header length, too short, %d bytes, less than standard length %d", pkt_len, VERIFY_PKT_HEADER_LENGTH);
        return -1;
    }

    bzero(pkt_header, sizeof(VerifyPacketHeader));

    memcpy(pkt_header->msg_type, pkt+VERIFY_PKT_MSG_TYPE_POSITION, VERIFY_PKT_MSG_TYPE_LENGTH);
    memcpy(pkt_header->terminal_id, pkt+VERIFY_PKT_TERMINAL_ID_POSITION, VERIFY_PKT_TERMINAL_ID_LENGTH);
    memcpy(pkt_header->worker_id, pkt+VERIFY_PKT_WORKER_ID_POSITION, VERIFY_PKT_WORKER_ID_LENGTH);
    memcpy(pkt_header->rsp_memo_type, pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION);
    memcpy(pkt_header->rsp_memo_txt, pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION, VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
    memcpy(pkt_header->payload_len, pkt+VERIFY_PKT_PAYLOAD_LEN_POSITION, VERIFY_PKT_PAYLOAD_LEN_LENGTH);

    DBG("Payload bytes: %s, pkt_len: %d, VERIFY_PKT_HEADER_LENGTH: %d.\n", pkt_header->payload_len, pkt_len, VERIFY_PKT_HEADER_LENGTH);

    //Examine the packet length whether it is valid or not.
    int payload_len = 0;
    payload_len = atoi(pkt_header->payload_len);
    if(payload_len==pkt_len-VERIFY_PKT_HEADER_LENGTH) {

        //Good
        return 1;
    } else {

        //Bad
        LOG_ERROR("Payload bytes: %s, pkt_len: %d, VERIFY_PKT_HEADER_LENGTH: %d.\n", pkt_header->payload_len, pkt_len, VERIFY_PKT_HEADER_LENGTH);
        return -1;
    }

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Get_terminal_pub_key_from_file
 *  Description:  Get terminal public key from PEM file or Binary file
 * =====================================================================================
 */
int Get_terminal_pub_key_from_file(RSA **terminal_pub_key, char* file_name)
{
    int ret = 0;

    RSA * pub_key = NULL;

    ret =  Generate_pub_key_from_file( &pub_key, file_name);
    //ret = Get_public_key_from_file(&pub_key, pem_filename);
    if(-1==ret) {
        *terminal_pub_key = NULL;
        return -1;
    } else {
        *terminal_pub_key = pub_key;
        return 1;
    }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Get_terminal_pub_key_from_db
 *  Description:  Connect to PostgreSQL to query the pubic key of rsa.
 * =====================================================================================
 */
int Get_terminal_pub_key_from_db(RSA **pub_key, VerifyPacketHeader *pkt_header)
{

    int ret = 0;

    int i =0;
    time_t t = 0;
    int verify_srv_num = 0;


    PGconn* conn_db = NULL;
    PGresult *res = NULL;

    char * results_string = NULL;
    int  results_string_len = 0;

    char *pub_key_bin_buffer = NULL;

    if(NULL==pub_key) {
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

    //choose the index of a verify server at random
    t = time(NULL);
    srand((unsigned int) t);
    verify_srv_num = global_par.system_par.verify_number;

    if(1==verify_srv_num) {
        i = 0;
    } else {
        i = 0 + (int) ( 1.0 * verify_srv_num * rand() / (RAND_MAX + 1.0));

    }
    conn_db = Connect_db_server(global_par.system_par.verify_database_user[i],
                                global_par.system_par.verify_database_password[i],
                                global_par.system_par.verify_database_name,
                                global_par.system_par.verify_ip_addr_array[i]);
    if (NULL==conn_db) {
        OUTPUT_ERROR;
        return -1;
    }


    //generate query string
    sprintf(query_string, "SELECT pub_key from %s where terminal_id=\'%s\' AND worker_id=\'%s\' AND enable_flag=1;",
            TERMINAL_PUB_KEY_TABLE_NAME, (char*)(pkt_header->terminal_id), (char*)(pkt_header->worker_id));

    /* Send the query to primary database */
    res = PQexec(conn_db, query_string);
    DBG("\n%s |%s|\n","Query: SQL string", query_string);
    DLOG(INFO)<<"Query: SQL string: "<<query_string;

    /* Did the record action fail in the primary database? */
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        OUTPUT_ERROR;
        perror(query_string);
        perror(PQerrorMessage(conn_db));

        DLOG(INFO)<<query_string;
        DLOG(INFO)<<PQerrorMessage(conn_db);

        ret = -1;
        if(NULL!=res) {
            PQclear(res);
            res = NULL;
        }

    }

    /* If there are more than one records, return the first one */
    if (PQntuples(res)>=1) {

        /* Only use first tuple*/
        results_string = PQgetvalue(res,0,0);
        results_string_len = PQgetlength(res, 0, 0);

        DBG("\nRSA Get terminal pub key with len = %d, |%s|\n", results_string_len, results_string);
        DLOG(INFO)<<"RSA Get_terminal_pub_key:"<<results_string;

		int pub_key_bin_buffer_len = 0;

        pub_key_bin_buffer = str2binary((char*)results_string, results_string_len, &pub_key_bin_buffer_len );

//      pub_key_bin_buffer = unbase64((unsigned char*)results_string, strlen( results_string ));
//		results_string = base64(pub_key_bin_buffer, const unsigned char * input,int length)

        if(NULL!=pub_key_bin_buffer) {
            *pub_key = Convert_der_to_rsa_for_pub_key((unsigned char*)pub_key_bin_buffer, pub_key_bin_buffer_len);
            if(NULL==*pub_key) {
                DBG("Terminal public key DER TO RSA, Error");
                LOG(ERROR)<<"Terminal public key DER TO RSA, Error.";
                ret = -1;
            }
        }
    } else {
        ret = -1;
    }

    if(NULL!=pub_key_bin_buffer) {
        free(pub_key_bin_buffer);
        pub_key_bin_buffer = NULL;
    }

    if(NULL!=res) {
        PQclear(res);
        res = NULL;
    }

    /* Free the DB resource */
    PQfinish((PGconn*)(conn_db));
    conn_db = NULL;

    return ret;

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Get_server_private_key_from_db
 *  Description:
 * =====================================================================================
 */
int Get_server_private_key_from_db(RSA **key)
{

    int ret = 0;

    PGconn* conn_db = NULL;
    PGresult *res = NULL;

    char * results_string = NULL;
    int  results_string_len = 0;

    char *private_key_bin_buffer = NULL;

    int i =0;
    time_t t = 0;
    int verify_srv_num = 0;


    //SQL string is created
    char query_string[MAX_QUERY_LENGTH];
    bzero(query_string,MAX_QUERY_LENGTH);

    //choose the index of a verify server at random
    t = time(NULL);
    srand((unsigned int) t);
    verify_srv_num = global_par.system_par.verify_number;

    if(1==verify_srv_num) {
        i = 0;
    } else {
        i = 0 + (int) ( 1.0 * verify_srv_num * rand() / (RAND_MAX + 1.0));

    }

    conn_db = Connect_db_server(global_par.system_par.verify_database_user[i],
                                global_par.system_par.verify_database_password[i],
                                global_par.system_par.verify_database_name,
                                global_par.system_par.verify_ip_addr_array[i]);
    if (NULL==conn_db) {
        OUTPUT_ERROR;
        return -1;
    }

    //generate query string
    sprintf(query_string, "SELECT rsa_key FROM verify_srv_rsa where enable_flag=1;");

    /* Send the query to primary database */
    res = PQexec(conn_db, query_string);
    DBG("\n%s |%s|\n","Query: SQL string", query_string);
    DLOG(INFO)<<"Query: SQL string: "<<query_string;

    /* Did the record action fail in the primary database? */
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        OUTPUT_ERROR;
        perror(query_string);
        perror(PQerrorMessage(conn_db));

        LOG(ERROR)<<query_string;
        LOG(ERROR)<<PQerrorMessage(conn_db);

    }

    /* If there are more than one records, return the first one */
    if (PQntuples(res)>=1) {

        /* Only return first tuple*/
        results_string = PQgetvalue(res,0,0);
        results_string_len = PQgetlength(res, 0, 0);

        DBG("\nRSA Get_server_pri_key with len=:%d, |%s|\n", results_string_len , results_string);

        //results_string = base64(pub_key_bin_buffer, const unsigned char * input,int length)

        //the memory of 'private_key_bin_buffer' will be allocated in the function 'str2binary'
        int private_key_bin_buffer_len = 0;
        private_key_bin_buffer = str2binary((char*)results_string, results_string_len, &private_key_bin_buffer_len);

        if(NULL!=private_key_bin_buffer) {
            *key = Convert_der_to_rsa_for_private_key((unsigned char*)private_key_bin_buffer, results_string_len*2);
            if(NULL==*key) {
                DBG("Srv Private Key DER TO RSA, Error");
                LOG(ERROR)<<"Srv_pri_key DER TO RSA, Error.";
                ret = -1;
            }
        }
    }

    if(NULL!=private_key_bin_buffer) {
        free(private_key_bin_buffer);
        private_key_bin_buffer = NULL;
    }

    if(NULL!=res) {
        PQclear(res);
        res = NULL;
    }

    /* Free the DB resource */
    PQfinish((PGconn*)(conn_db));
    conn_db = NULL;

    return ret;

}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Get_server_private_key_from_file
 *  Description:
 * =====================================================================================
 */
int Get_server_private_key_from_file(RSA **server_private_key, char* file_name)
{
    int ret = 0;
    RSA *key = NULL;

//    ret = Get_private_key_from_file(&key, (char *)"./openssl/yao_lagate.pem");
    ret = Get_private_key_from_file(&key, file_name);
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



/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Connect_db_server
 *  Description:
 * =====================================================================================
 */
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
    sprintf(conn_string,"user=%s password=%s dbname=%s hostaddr=%s port=6432",user_name,password,db_name,ip_addr);
    DBG("Connect to DB: |%s|\n",conn_string);

    /* Connect the database */
    conn = PQconnectdb(conn_string);
    if (PQstatus(conn) != CONNECTION_OK) {
        LOG(ERROR)<<"Connect to DB, failed." << "detail: " <<conn_string;
        OUTPUT_ERROR;
        return NULL;
    }

    return conn;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Load_server_private_key_from_file_into_db (char* file_name)
 *  Description:
 * =====================================================================================
 */
int Transform_server_private_key_from_file_into_db(char* file_name)
{
    int ret = 0;


    PGconn* conn_db = NULL;
    PGresult *res = NULL;

    int i =0;
    time_t t = 0;
    int verify_srv_num = 0;


//SQL string is created
    char query_string[MAX_QUERY_LENGTH];
    bzero(query_string,MAX_QUERY_LENGTH);

    RSA *server_private_key = NULL;


    unsigned char* srv_rsa_private_key_binary = NULL;
    int srv_rsa_private_key_binary_len = 0;

    char *srv_rsa_private_key_binary_string = NULL;
    int srv_rsa_private_key_binary_string_len = 0;


    //Read rsa from file with base64 format.
    ret = Get_server_private_key_from_file(&server_private_key, file_name);

    if(NULL==server_private_key) {
        LOG(ERROR)<<"Read private key of verify server, failed." << file_name;
        ret = 0;
        goto load_s_p_k_return;
    } else {
        DLOG(INFO)<<"Read private key of verify server, success!";
    }

    //Convert rsa format into der format
    srv_rsa_private_key_binary = Convert_rsa_to_der_for_private_key(server_private_key, &srv_rsa_private_key_binary_len);

    if(NULL!=srv_rsa_private_key_binary && 0!=srv_rsa_private_key_binary_len) {
        DLOG(INFO)<<"Convert rsa to binary, Success!";

        //convert der binary format to ASIICA format.
        srv_rsa_private_key_binary_string = Binary2str(srv_rsa_private_key_binary, srv_rsa_private_key_binary_len);
        if(NULL!=srv_rsa_private_key_binary_string) {
            srv_rsa_private_key_binary_string_len = srv_rsa_private_key_binary_len *2;
            //One Byte -> 2 Numbers
            DLOG(INFO)<<"Private key string length:" << srv_rsa_private_key_binary_string_len
                      <<"ASIIC :" <<srv_rsa_private_key_binary_string;
        } else {
            ret = 0;
            LOG(ERROR)<<"Convert rsa binary to ASIIC string, failed.";
            goto load_s_p_k_return;
        }


    } else {
        LOG(ERROR)<<"Convert rsa to binary, Failed.";
        ret = 0;
        goto load_s_p_k_return;
    }



//choose the index of a verify server at random
    t = time(NULL);
    srand((unsigned int) t);
    verify_srv_num = global_par.system_par.verify_number;

    if(1==verify_srv_num) {
        i = 0;
    } else {
        i = 0 + (int) ( 1.0 * verify_srv_num * rand() / (RAND_MAX + 1.0));

    }

    conn_db = Connect_db_server(global_par.system_par.verify_database_user[i],
                                global_par.system_par.verify_database_password[i],
                                global_par.system_par.verify_database_name,
                                global_par.system_par.verify_ip_addr_array[i]);
    if (NULL==conn_db) {
        OUTPUT_ERROR;
        return -1;
    }

//generate query string
    sprintf(query_string, "INSERT INTO verify_srv_rsa(rsa_key) values (trim(\'%s\'));", srv_rsa_private_key_binary_string);

    /* Send the query to primary database */
    res = PQexec(conn_db, query_string);
    DBG("\n%s |%s|\n","Query: SQL string", query_string);
    DLOG(INFO)<<"Query: SQL string: "<<query_string;

    /* Did the record action fail in the primary database? */
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        OUTPUT_ERROR;
        perror(query_string);
        perror(PQerrorMessage(conn_db));

        LOG(ERROR)<<query_string;
        LOG(ERROR)<<PQerrorMessage(conn_db);

    }

load_s_p_k_return:
    if(NULL!=server_private_key) {
        free(server_private_key);
        server_private_key = NULL;
    }

    if(NULL!=srv_rsa_private_key_binary) {
        OPENSSL_free(srv_rsa_private_key_binary);
        srv_rsa_private_key_binary = NULL;
        srv_rsa_private_key_binary_len = 0;
    }

    if(NULL!=srv_rsa_private_key_binary_string) {
        free(srv_rsa_private_key_binary_string);
        srv_rsa_private_key_binary_string = NULL;
        srv_rsa_private_key_binary_string_len = 0;
    }

    return ret;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Load_server_private_key_from_file_into_db (char* file_name)
 *  Description:
 * =====================================================================================
 */
int Transform_terminal_public_key_from_file_into_db(char* file_name)
{
    int ret = 0;


    PGconn* conn_db = NULL;
    PGresult *res = NULL;

    int i =0;
    time_t t = 0;
    int verify_srv_num = 0;


    //SQL string is created
    char query_string[MAX_QUERY_LENGTH];
    bzero(query_string,MAX_QUERY_LENGTH);

    RSA *terminal_public_key = NULL;


    unsigned char* terminal_rsa_public_key_binary = NULL;
    int terminal_rsa_public_key_binary_len = 0;

    char *terminal_rsa_public_key_binary_string = NULL;
    int terminal_rsa_public_key_binary_string_len = 0;


    //Read rsa from file with base64 format.
    ret = Get_terminal_pub_key_from_file(&terminal_public_key, file_name);

    if(NULL==terminal_public_key) {
        LOG(ERROR)<<"Read private key of verify server, failed." << file_name;
        ret = 0;
        goto load_s_p_k_return;
    } else {
        DLOG(INFO)<<"Read private key of verify server, success!";
    }

    //Convert rsa format into der format
    terminal_rsa_public_key_binary = Convert_rsa_to_der_for_pub_key(terminal_public_key, &terminal_rsa_public_key_binary_len);

    if(NULL!=terminal_rsa_public_key_binary && 0!=terminal_rsa_public_key_binary_len) {
        DLOG(INFO)<<"Convert rsa to binary, Success!";

        //convert der binary format to ASIICA format.
        terminal_rsa_public_key_binary_string = Binary2str(terminal_rsa_public_key_binary, terminal_rsa_public_key_binary_len);
        if(NULL!=terminal_rsa_public_key_binary_string) {
            terminal_rsa_public_key_binary_string_len = terminal_rsa_public_key_binary_len *2;
            //One Byte -> 2 Numbers
            DLOG(INFO)<<"Pulic key string length:" << terminal_rsa_public_key_binary_string_len
                      <<"ASIIC :" <<terminal_rsa_public_key_binary_string;
        } else {
            ret = 0;
            LOG(ERROR)<<"Convert rsa binary to ASIIC string, failed.";
            goto load_s_p_k_return;
        }


    } else {
        LOG(ERROR)<<"Convert rsa to binary, Failed.";
        ret = 0;
        goto load_s_p_k_return;
    }



    //choose the index of a verify server at random
    t = time(NULL);
    srand((unsigned int) t);
    verify_srv_num = global_par.system_par.verify_number;

    if(1==verify_srv_num) {
        i = 0;
    } else {
        i = 0 + (int) ( 1.0 * verify_srv_num * rand() / (RAND_MAX + 1.0));

    }

    conn_db = Connect_db_server(global_par.system_par.verify_database_user[i],
                                global_par.system_par.verify_database_password[i],
                                global_par.system_par.verify_database_name,
                                global_par.system_par.verify_ip_addr_array[i]);
    if (NULL==conn_db) {
        OUTPUT_ERROR;
        return -1;
    }

    //generate query string
    sprintf(query_string, "INSERT INTO t_terminal_ukey_pubkey(pub_key) values (trim(\'%s\'));", terminal_rsa_public_key_binary_string);

    /* Send the query to primary database */
    res = PQexec(conn_db, query_string);
    DBG("\n%s |%s|\n","Query: SQL string", query_string);
    DLOG(INFO)<<"Query: SQL string: "<<query_string;

    /* Did the record action fail in the primary database? */
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        OUTPUT_ERROR;
        perror(query_string);
        perror(PQerrorMessage(conn_db));

        LOG(ERROR)<<query_string;
        LOG(ERROR)<<PQerrorMessage(conn_db);

    }

load_s_p_k_return:
    if(NULL!=terminal_public_key) {
        free(terminal_public_key);
        terminal_public_key = NULL;
    }

    if(NULL!=terminal_rsa_public_key_binary) {
        OPENSSL_free(terminal_rsa_public_key_binary);
        terminal_rsa_public_key_binary = NULL;
        terminal_rsa_public_key_binary_len = 0;
    }

    if(NULL!=terminal_rsa_public_key_binary_string) {
        free(terminal_rsa_public_key_binary_string);
        terminal_rsa_public_key_binary_string = NULL;
        terminal_rsa_public_key_binary_string_len = 0;
    }

    return ret;
}


