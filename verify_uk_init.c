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

#include "verify_uk_init.h"

/*
* Initiailize all things, 
*
*/
int Init_verify_uk_server(void)
{
	int ret = 0;

	/* for socket conncetions */
	int welcome_sd_trans = 0;	/* socket for normal transaction packets from clients */

	int welcome_sd_update_server_pub_key = 0; /*socket for updating server public key*/


	/* pid for the daemon process management */
	pid_t pid_daemon_trans = 0;

	LOG(INFO)<<"================ Initialization Step I =====================";
	printf("\n================ Initialization Step I =====================\n");

    LOG(INFO)<<"Read the public key and private key of its server";
    printf("\nRead the public key and private key of its server:");
    //ret = Init_server_key_pair();
    if (-1 == ret ) {
        LOG(ERROR)<<"[!Failed]";
        OUTPUT_ERROR;
        return -1;
    } else {
        LOG(INFO)<<"[Success!]";
        OUTPUT_OK;
    }
    


	
	
}
