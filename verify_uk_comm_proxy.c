/*
 * =====================================================================================
 *
 *       Filename:  verify_uk_comm_proxy.c
 *
 *    Description:  functions with communication, such as socket programming.
 *
 *        Version:  1.0
 *        Created:  1/28/2013 1:26:50 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zhi-wei YAN (Jerod YAN), jerod.yan@gmail.com
 *        Company:  DrumTm
 *
 * =====================================================================================
 */

#include "verify_uk_comm_proxy.h"

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  SendRecv_message_to_proxy
 *  Description:  Connect to the proxy server IP randomly
 *                and send plain text packet to it and recv its response packet.
 * =====================================================================================
 */
int SendRecv_message_to_proxy(char *msg_to_proxy,
                              int msg_to_proxy_length,
                              char*msg_from_proxy,
                              int *msg_from_proxy_len)
{
    int success = 0;
    int count = 0;

    int i = 0;
    int proxy_sd;/*socket for proxy*/
    struct sockaddr_in proxy_sa;/* information for proxy*/

    int proxy_srv_num = 0;
    char proxy_address_array[MAX_PROXY_NUMBER][16];
    int proxy_data_port = 0;

    time_t t = 0;

    /* Get proxy address and communication with proxy */

    //choose the index of a proxy server at random
    t = time(NULL);
    srand((unsigned int) t);
    proxy_srv_num = global_par.system_par.proxy_number;

    if(1==proxy_srv_num) {
        i = 0;
    } else {
        i = 0 + (int) ( 1.0 * proxy_srv_num * rand() / (RAND_MAX + 1.0));

    }

    //read the proxy server IPs and data port from the global configuration
    success = Read_proxy_parameters((char*)(proxy_address_array),&proxy_data_port);
    if ((proxy_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        OUTPUT_ERROR;
        LOG(ERROR)<<"socket initialization in SendRecv_message_to_proxy, failed.";
        return -1;
    }

    /*set information for proxy*/
    bzero(&proxy_sa, sizeof(proxy_sa));
    proxy_sa.sin_family = AF_INET;
    proxy_sa.sin_port = htons(proxy_data_port);
    proxy_sa.sin_addr.s_addr = inet_addr(proxy_address_array[i]);

    /*connect to proxy*/
    success = connect(proxy_sd, (struct sockaddr*)&proxy_sa, sizeof(proxy_sa));
    if(success < 0) {
        OUTPUT_ERROR;
        LOG(ERROR)<<"Failed to connect proxy server " << proxy_address_array[i] <<":"<<proxy_data_port;
        DBG("Failed to connect proxy server %s:%d.\n", proxy_address_array[i], proxy_data_port);
        close(proxy_sd);
        return -1;
    } else {
        DBG("Success to connect to the proxy server %s:%d.\n", proxy_address_array[i], proxy_data_port);
        DLOG(INFO)<<"successfully connect to proxy server" << proxy_address_array[i] <<":" <<proxy_data_port;
    }

    /* Send the message */
    count = send(proxy_sd, msg_to_proxy, msg_to_proxy_length, 0);
    if (count < 0) {
        OUTPUT_ERROR;
        DBG("Failed to send to proxy %s with %d bytes: |%s|.\n", proxy_address_array[i],count, msg_to_proxy);
        LOG(ERROR)<<"failed to send msg_to_proxy to proxy server: "<< proxy_address_array[i] << msg_to_proxy;
        close(proxy_sd);
        return -1;
    } else {
        DBG("Success to send to proxy %s with %d bytes: |%s|.\n", proxy_address_array[i],count, msg_to_proxy);
    }

    /* Recv a message */
    count=recv(proxy_sd, msg_from_proxy, MAX_SIZE_BUFFER_RECV, 0);
    if (count < 0) {
        OUTPUT_ERROR;
        DBG("Failed to recv packet from proxy server %s.\n", proxy_address_array[i]);
        LOG(ERROR)<<"Failed to recv packet from proxy server "<< proxy_address_array[i];
        *msg_from_proxy_len = 0;
        close(proxy_sd);
        return -1;
    } else {
        DBG("Success to receive from proxy %s with %d bytes: |%s|.\n", proxy_address_array[i],count, msg_from_proxy);
        *msg_from_proxy_len = count;
    }

    close(proxy_sd);
    return 1;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Read_proxy_parameters
 *  Description:  Read the configuration of proxy servers, including IP and data port
 * =====================================================================================
 */
int Read_proxy_parameters(char *proxy_addr_array,int *proxy_data_port)
{
    *proxy_data_port = global_par.system_par.proxy_data_port;
    memcpy(proxy_addr_array,global_par.system_par.proxy_ip_addr_array,MAX_PROXY_NUMBER*16);
    return 1;
}
