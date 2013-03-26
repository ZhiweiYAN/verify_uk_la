/*
 * =====================================================================================
 *
 *       Filename:  verify_uk_init.c
 *
 *    Description:  initialize the server, all things:including opening socket port for listening, process monitor.
 *
 *        Version:  1.0
 *        Created:  1/19/2013 10:31:41 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zhi-wei YAN (Jerod YAN), jerod.yan@gmail.com
 *        Company:  DrumTm
 *
 * =====================================================================================
 */

#include "verify_uk_start.h"

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Init_verify_uk_server
 *  Description:  Initialize all things
 * =====================================================================================
 */
int Init_verify_uk_server(void)
{
    int ret = 0;

    /* for socket connections */
    int welcome_sd_trans = 0;	/* socket for normal transaction packets from clients */
    struct sockaddr_in sa_trans;

    /* pid for the daemon process management */
    pid_t pid_daemon_trans = 0;

    /* Read parameters from the configuration files. */
    ret  = Setup_config_parameters();
    DLOG(INFO)<<"Reading parameters from the configure file:";
    printf("Reading parameters from the configure file : ");
    if (-1 == ret ) {
        LOG(ERROR)<<"[!Failed]";
        OUTPUT_ERROR;
        return -1;
    } else {
        DLOG(INFO)<<"[Success!]";
        OUTPUT_OK;
    }

    //debug
    //RSA *key = NULL;
    //ret = Transform_server_private_key_from_file_into_db((char *)SERVER_PRIVATE_KEY_PEM_FILE);
    //ret = Get_server_private_key_from_db( &key);
    //return 0;

    //debug end

    //We decide to read the private key from the PGSQL-Database when we receive a packet.
//    DLOG(INFO)<<"Read the public key and private key of its server";
//    printf("\nRead the public key and private key of its server:");
//    ret = Init_server_key_pair();
//    if (-1 == ret ) {
//        LOG(ERROR)<<"[!Failed]";
//        OUTPUT_ERROR;
//        return -1;
//    } else {
//        DLOG(INFO)<<"[Success!]";
//        OUTPUT_OK;
//    }

    /* Initialize PROCESS MANAGER semaphore and One block memory for process*/
    ret  = Init_process_manager_share_memory(PROCESS_SHARE_ID);
    DLOG(INFO)<<"Initialize the PROCESS MANAGEMENT share memory and semaphore:";
    printf("Initialize the PROCESS MANAGEMENT share memory and semaphore:");
    if (-1 == ret ) {
        LOG(ERROR)<<"[!Failed]";
        OUTPUT_ERROR;
        return -1;
    } else {
        DLOG(INFO)<<"[Success!]";
        OUTPUT_OK;
    }

    /* Initialize the  communication socket and port with terminals from outside */
    /* server socket 1 */
    bzero(&sa_trans,sizeof(struct sockaddr_in));
    ret  = Init_verify_data_socket(global_par.system_par.verify_data_port, &welcome_sd_trans, &sa_trans);
    printf("Initialize the data communication with terminals with PORT %d:", global_par.system_par.verify_data_port);
    DLOG(INFO)<<"Initialize the data communication with terminals :";
    if (-1 == ret ) {
        LOG(ERROR)<<"[!Failed]";
        OUTPUT_ERROR;
        return -1;
    } else {
        DLOG(INFO)<<"[Success!]";
        OUTPUT_OK;
    }

    /* Initialize the monitor process*/
    ret  = Start_monitor_process();
    printf("Start the server monitor process:");
    DLOG(INFO)<<"Start the server monitor process:";
    if (-1 == ret ) {
        OUTPUT_ERROR;
        LOG(ERROR)<<"[!Failed]";
        return -1;
    } else {
        DLOG(INFO)<<"[Success!]";
        OUTPUT_OK;
    }

    /* Initialize the time counter process - clock*/
    ret  = Start_life_time_counter_process();
    printf("Start the server time counter:");
    DLOG(INFO)<<"Start the server time counter:";
    if (-1 == ret ) {
        OUTPUT_ERROR;
        LOG(ERROR)<<"[!Failed]";
        return -1;
    } else {
        DLOG(INFO)<<"[Success!]";
        OUTPUT_OK;
    }

    if ((pid_daemon_trans = fork()) < 0) {
        LOG(ERROR)<<"[pid_daemon_trans, fork(), !Failed]";
        OUTPUT_ERROR;
        return -1;
    } else if (0 == pid_daemon_trans) {
        ret  = Daemon_db_verify_uk_server(welcome_sd_trans,&sa_trans);
        if (-1== ret) {
            LOG(ERROR)<<"[Daemon__trans_server, !Failed]";
            exit(0);
        };
    }

    return 1;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Daemon_db_verify_uk_server
 *  Description:  Start daemon process of verify server
 * =====================================================================================
 */
int Daemon_db_verify_uk_server(int welcome_sd,struct sockaddr_in *sa)
{
    int ret  = 0;

    pid_t pid = 0;

    int connection_sd = 0;
    socklen_t len = 0;
    int count = 0;

    char *buf_recv = NULL;
    char *packet = NULL;

    len = sizeof (struct sockaddr);

    assert(0<welcome_sd);
    assert(NULL!=sa);

    /* Enter the Daemon */
    while (1) {

        printf("\r\033[32mThe Verify UK Daemon Process is waiting for connections .... \033[0m\n");

        if (( connection_sd = accept(welcome_sd,(struct sockaddr*)sa,&len))<0) {
            LOG(ERROR)<< "Error happens when socket function <accept> is running. We will close the socket at once and delay 2 ms and restart.";
            OUTPUT_ERROR;
            close(connection_sd);
            sleep(2);
            continue;
        }


        char peeraddrstr[MAX_TEMP_SIZE];
        struct sockaddr_in peer;
        socklen_t len;
        bzero(peeraddrstr,MAX_TEMP_SIZE);
        ret = getpeername(connection_sd, (struct sockaddr *)&peer, &len);
        if (ret < 0) {
            close(connection_sd);
            sleep(2);
            continue;
        }

        sprintf(peeraddrstr, "%s", inet_ntoa(peer.sin_addr));
        printf("\r\033[36mA connection from %s has arrived.\033[0m\n", peeraddrstr);

        //	create a independent process to monitor the process table.
        if ((pid = fork()) < 0) {
            LOG(ERROR)<<"1st fork() verify server, failed";
            OUTPUT_ERROR;
            close(connection_sd);
            return -1;
        } else if (0 == pid) {

            //enter into the child process, child name=alice, mother=obama
            /* Close the listening socket description */
            close(welcome_sd);

            if ((pid = fork()) < 0) {
                LOG(ERROR)<<"2nd fork() verify server, failed";
                OUTPUT_ERROR;
                return -1;
            } else if (pid > 0)
                exit(0); /* the child "alice" return to her mother "obama" */


            //enter into the grandchild, child name=jose, mother=alice

            /* In the grandchild process */
            /* Allocate memory for receiving data */

            ret  = Insert_pid_process_table(getpid(),VERIFY_PROCESS_DEADLINE,VERIFY_PROCESS);
            buf_recv = (char*)malloc(sizeof(char)*MAX_SIZE_BUFFER_RECV);
            if (NULL==buf_recv) {
                LOG(ERROR)<<"malloc buf_recv, failed.";
                OUTPUT_ERROR;
                goto END;
            } else {
                bzero(buf_recv,MAX_SIZE_BUFFER_RECV);
            }

            /* Terminal:Receiving data from terminals*/
            count = recv(connection_sd,buf_recv,MAX_SIZE_BUFFER_RECV,0);
            //DLOG(INFO)<<"Verify UK: Recv data from Terminal.";
            //DLOG(INFO)<<"Data Len:"<<count<<"\nData String:|"<<buf_recv<<"|";
            DBG("Verify UK: Recv (%d bytes) data from Terminal:|%s|.\n",count, buf_recv);

            /* Prepare the actual memory for the packet */
            packet = (char *)malloc(sizeof(char)*(count+1));
            if (NULL == packet) {
                OUTPUT_ERROR;
                LOG(ERROR)<<"malloc packet, failed.";
                goto END;
            } else {
                bzero(packet,count+1);
                memcpy(packet,buf_recv,count);
            }

            /* Deal with the packet in the following function, there is a function
            to send the result to the business machines. */
            ret  = Do_verify_procedures(connection_sd, packet, count);

END:
            close(connection_sd);
            ret  = Remove_pid_process_table(getpid());

            free(buf_recv);
            buf_recv = NULL;
            free(packet);
            packet = NULL;

            exit(0);
        }

        /* Close the connection socket description in the parent obama  process*/
        close(connection_sd);

        /* In the parent process */
        if (waitpid(pid,NULL,0)!=pid) {
            OUTPUT_ERROR;
        }
        continue;
    }
    return 1;
}

