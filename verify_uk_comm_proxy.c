/* *************************************************
 * File name:
 * 		verify_uk_comm_proxy.cc
 * Description:
 * 		The program is run at the verify server.
 * Author:
 * 		Zhiwei Yan, jerod.yan@gmail.com
 * Date:
 * 		2012-12-14
 * *************************************************/
#include "verify_uk_comm_proxy.h"
/* *************************************************
* Function Name:
* 		int SendRecv_message_to_proxy(char *msg_to_proxy, int msg_to_proxy_length)
* *************************************************/
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

    //choose the idx of a proxy server at random
    t = time(NULL);
    srand((unsigned int) t);
    proxy_srv_num = global_par.system_par.proxy_number;

    if(1==proxy_srv_num) {
        i = 0;
    } else {
        i = 0 + (int) ( 1.0 * proxy_srv_num * rand() / (RAND_MAX + 1.0));

    }

    //read the proxy server ips and data port from the global configration
    success = Read_proxy_parameters((char*)(proxy_address_array),&proxy_data_port);
    if ((proxy_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("error:@verify_db_comm_proxy.cc:Send_message_to_proxy() socket ");
        LOG(ERROR)<<"socket initialization in SendRecv_message_to_proxy, failed.";
        return -1;
    }

    /*set information for proxy*/
    bzero(&proxy_sa, sizeof(proxy_sa));
    proxy_sa.sin_family = AF_INET;
    proxy_sa.sin_port = htons(proxy_data_port);
    proxy_sa.sin_addr.s_addr = inet_addr(global_par.system_par.proxy_ip_addr_array[i]);

    /*connect to proxy*/
    if (connect(proxy_sd, (struct sockaddr*)&proxy_sa, sizeof(proxy_sa)) < 0) {
        perror("error:@verify_db_comm_proxy.cc:Send_message_to_proxy()02");
        LOG(ERROR)<<"failed to connect proxy server "
                  << global_par.system_par.proxy_ip_addr_array[i]
                  <<":"<<proxy_data_port;
        close(proxy_sd);
        return -1;
    }

    LOG(INFO)<<"successfully connect to proxy server" << global_par.system_par.proxy_ip_addr_array[i]
             <<":" <<proxy_data_port;

    /* Send the message */
    count = send(proxy_sd, msg_to_proxy, msg_to_proxy_length, 0);
    if (count < 0) {
        perror("error:@verify_db_comm_proxy.cc:Send_message_to_proxy()03");
        LOG(ERROR)<<"failed to send msg_to_proxy to proxy server: "<< msg_to_proxy;
        close(proxy_sd);
        return -1;
    } else {
        DBG("Send to proxy %d bytes: |%s|\n", count, msg_to_proxy);
    }

    /* Recv a message */
    count=recv(proxy_sd, msg_from_proxy, MAX_SIZE_BUFFER_RECV, 0);
    if (count < 0) {
        perror("error:@verify_db_comm_proxy.cc:Send_message_to_proxy()04");
        *msg_from_proxy_len = 0;
        close(proxy_sd);
        return -1;
    } else {
        DBG("Recv from proxy %d bytes: |%s|\n", count, msg_from_proxy);
        *msg_from_proxy_len = count;
        LOG(INFO)<<"successfully recv msg from proxy server:" << msg_from_proxy;
    }

    close(proxy_sd);
    return 1;
}

/* *************************************************
* Function Name:
* 		int Read_proxy_parameters(char *proxy_addr,int *proxy_data_port)
* Input:
* 		NONE;
* Ouput:
* 		1 ---> success
* 		-1 ---> failure
*		char *proxy_addr
*       int *proxy_data_port
* *************************************************/
int Read_proxy_parameters(char *proxy_addr_array,int *proxy_data_port)
{
    *proxy_data_port = global_par.system_par.proxy_data_port;
    memcpy(proxy_addr_array,global_par.system_par.proxy_ip_addr_array,MAX_PROXY_NUMBER*16);
    return 1;
}
