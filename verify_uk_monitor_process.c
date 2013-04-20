/*
 * =====================================================================================
 *
 *       Filename:  verify_uk_monitor_process.c
 *
 *    Description: 	To avoid the process being blocked, there is a monitor process
 * 					to kill those ones whose life time is too long.
 *        Version:  1.0
 *        Created:  12/13/2012 9:18:31 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zhi-wei YAN (Jerod YAN), jerod.yan@gmail.com
 *        Company:  DrumTm
 *
 * =====================================================================================
 */

#include "verify_uk_monitor_process.h"
/* *************************************************
 * Function Name:
 * 		int Insert_pid_process_table(pid_t pid,int deadline,enum ProcessType type)
 * Input:
 * 		pid_t pid;
 * 		int deadline;
 * 		processType type;
 * Ouput:
 * 		1 ---> success
 * 		-1 ---> failure
 * *************************************************/
int Insert_pid_process_table(pid_t pid,int deadline,enum ProcessType type, char* ip_str)
{
    void * mem_ptr = NULL;
    int success = 0;
    int semid = 0;
    semid = GetExistedSemphore(PROCESS_SHARE_ID);
    success = AcquireAccessRight(semid);
    mem_ptr = MappingShareMemOwnSpace(PROCESS_SHARE_ID);

    /*  insert the pid of the process into the table */
    success = Register_process_into_process_table(((struct ShareMemProcess *)mem_ptr)->process_table,MAX_PROCESS_NUMBRER,pid,deadline,type, ip_str);

    /* Free memory control handler */
    success = UnmappingShareMem((void*)mem_ptr);
    success = ReleaseAccessRight(semid);

    return success;
}


/* *************************************************
 * Function Name:
 * 		int int Remove_pid_process_table(pid_t pid)
 * Input:
 * 		pid_t pid;
 * Ouput:
 * 		1 ---> success
 * 		-1 ---> failure
 * *************************************************/
int Remove_pid_process_table(pid_t pid)
{
    void * mem_ptr = NULL;
    int success = 0;
    int semid = 0;
    semid = GetExistedSemphore(PROCESS_SHARE_ID);
    success = AcquireAccessRight(semid);
    mem_ptr = MappingShareMemOwnSpace(PROCESS_SHARE_ID);

    /*  remove the pid of the process into the table */
    success = Unregister_process_from_process_table(((struct ShareMemProcess *)mem_ptr)->process_table,MAX_PROCESS_NUMBRER,pid);

    /* Free memory control handler */
    success = UnmappingShareMem((void*)mem_ptr);
    success = ReleaseAccessRight(semid);

    return success;
}

/* *************************************************
 * Function Name:
 * 		int Set_process_life_time(pid_t pid,int life_time)
 * Input:
 * 		pid_t pid;
 * 		int life_time;
 * Ouput:
 * 		1 ---> success
 * 		-1 ---> failure
 * *************************************************/
int Set_process_life_time(pid_t pid, int life_time)
{
    struct ShareMemProcess * mem_ptr = NULL;
    struct ChildProcessStatus *process_ptr = NULL;
    int success = 0;
    int i = 0;
    int semid = 0;
    semid = GetExistedSemphore(PROCESS_SHARE_ID);
    success = AcquireAccessRight(semid);
    mem_ptr = (struct ShareMemProcess *)MappingShareMemOwnSpace(PROCESS_SHARE_ID);
    process_ptr = (struct ChildProcessStatus * )(mem_ptr->process_table);

    /*  set the life time of the process table */
    /* Place the pid into the table */
    for (i=0; i<MAX_PROCESS_NUMBRER; i++) {
        if (pid==(process_ptr+i)->pid) {
            (process_ptr+i)->life_time = life_time;
            break;
        }
    }
    /* Free memory control handler */
    success = UnmappingShareMem((void*)mem_ptr);
    success = ReleaseAccessRight(semid);

    return success;
}

/* *************************************************
 * Function Name:
 * 		int Register_process_into_process_table(struct ChildProcessStatus *ptr, int prcs_num,pid_t pid,int deadline, enum ProcessType type)
 * Input:
 * 		struct ChildProcessStatus *ptr ---> table of life time of processes
 * 		int prcs_num ---> the sum of all child processes
 * Output:
 * 		1 ---> success;
 * 		-1 ---> failure
 * *************************************************/
int Register_process_into_process_table(struct ChildProcessStatus *ptr, int prcs_num,pid_t pid,int deadline,enum ProcessType type, char *ip_str)
{
    int i = 0;
    int j = 0;

    int available_slot_sum = 0;
    /* Check the input parameters */
    if (NULL==ptr||0>prcs_num||0>deadline) {
        perror("error@monitor_process.cc:Add_process_into_time_table():NULL==ptr");
        return -1;
    }

    /* Place the pid into the table */
    for (i=0; i<prcs_num; i++) {
        if (0==(ptr+i)->pid) {
            (ptr+i)->pid = pid;
            (ptr+i)->life_time = 0;
            (ptr+i)->recv_timer_stop = 0; //default
            (ptr+i)->recv_delay_time = 0;
            (ptr+i)->deadline = deadline;
            (ptr+i)->type = type;
            (ptr+i)->process_step = 0;
			memcpy((ptr+i)->ip_str, ip_str, IP_STRING_LEN);
            //if(RECORD_PROCESS==type||SYNC_PROCESS==type)
            //printf("\r\033[33mRegister PID %d is OK in slot %d\033[0m. \n",pid,i);
            break;
            fflush(NULL);
        }
    }
    for (j=0; j<prcs_num; j++) {
        if(0==(ptr+j)->pid) {
            available_slot_sum ++;
        }
    }
    printf("\r\033[33mRegister PID %d into slot %d, ava_slot_ratio = %d/%d \033[0m. \n",pid,i, available_slot_sum, prcs_num);
    return 1;
}

int Unregister_process_from_process_table(struct ChildProcessStatus *ptr, int prcs_num,pid_t pid)
{
    int i = 0;
    int j = 0;

    int available_slot_sum = 0;
    int process_life_time = 0;
    /* Check the input parameters */
    if (NULL==ptr||0>prcs_num) {
        perror("error@monitor_process.cc:Add_process_into_time_table():NULL==ptr");
        return -1;
    }

    /* Remove the pid into the table */
    for (i=0; i<prcs_num; i++) {
        if (pid==(ptr+i)->pid) {
            (ptr+i)->pid = 0;
            process_life_time = (ptr+i)->life_time;
            (ptr+i)->life_time = 0;
            (ptr+i)->recv_delay_time =0;
            (ptr+i)->recv_timer_stop = 1;
            (ptr+i)->deadline = 0;
            (ptr+i)->type = NORMAL_PROCESS;
            (ptr+i)->process_step = 0;
			memset((ptr+i)->ip_str, 0, IP_STRING_LEN);
            //printf("\r\033[36mUnRegister PID %d is OK from slot %d.\033[0m. \n",pid,i);
            break;
            fflush(NULL);
        }
    }

    for (j=0; j<prcs_num; j++) {
        if(0==(ptr+j)->pid) {
            available_slot_sum ++;
        }
    }
    printf("\r\033[36mUnRegister PID %d from slot %d, life_time = %d, ava_slot_ratio = %d/%d \033[0m. \n",pid,i, process_life_time, available_slot_sum, prcs_num);

    return 1;
}

/* *************************************************
 * Function Name:
 * 		int Increase_process_life_time(struct ChildProcessStatus *ptr, int prcs_num)
 * Input:
 * 		struct ChildProcessStatus *ptr ---> the pointer of the process table
 * 		int prcs_num ---> the sum of the process
 * Ouput:
 * 		1 ---> success
 * 		-1 ---> failure
 * *************************************************/
int Increase_process_life_time(struct ChildProcessStatus *ptr, int prcs_num)
{
    int i = 0;
    /* Check the input parameters */
    if (NULL==ptr||0>=prcs_num) {
        perror("error@mointor_process.cc:Increase_process_life_time():NULL==ptr");
        return -1;
    }

    for (i=0; i<prcs_num; i++) {
        if (0!= (ptr+i)->pid) {
            ((ptr+i)->life_time)++;
            if(0==(ptr+i)->recv_timer_stop) {
                ((ptr+i)->recv_delay_time)++;
            }
        }
    }
    return 1;
}

/* *************************************************
 * Function Name:
 * 		int Kill_invalid_process(struct ChildProcessStatus *ptr, int prcs_num, int deadline)
 * Input:
 * 		struct ChildProcessStatus *ptr ---> all the child process in the table
 * 		int prcs_num   --->  the sum of all child processes
 * Output:
 * 		1 ---> success;
 * 		-1 ---> failure
 * *************************************************/
int Kill_invalid_process(struct ChildProcessStatus *ptr, int prcs_num)
{
    int i = 0;
    int success = 0;

    /* Check the input parameters */
    if (NULL==ptr||0>=prcs_num) {
        perror("error@mointor_process.cc:Kill_invalid_process():NULL==ptr");
        return -1;
    }

    /* Kill all process that exceed their deadlines. */
    for (i=0; i<prcs_num; i++) {
        /* if the process belongs to the BEART HEART process */
        if ((1<(ptr+i)->pid&&(ptr+i)->deadline<(ptr+i)->life_time)) {
            switch ((ptr+i)->type) {
            case VERIFY_PROCESS:
                success = kill((ptr+i)->pid,SIGKILL);
                waitpid(-1,NULL,WNOHANG);
                if (0==success) {
                    LOG_WARNING("Kill pid %d trigered by %s, reach to deadline (%d sec). OK.\n",(ptr+i)->pid,(ptr+i)->ip_str, (ptr+i)->deadline);
                    //LOG(ERROR)<<"VERIFY_PROCESS "<<(ptr+i)->pid <<", was killed due to lifetime: "<<(ptr+i)->deadline;
                    //Increase_half_lifetime_record_process(ptr, prcs_num);
                } else {
                    LOG_ERROR("Kill pid %d trigered by %s, reach to deadline (%d sec). Failed.\n",(ptr+i)->pid,(ptr+i)->ip_str, (ptr+i)->deadline);
					//perror("VERIFY_PROCESS was killed, but kill operation faild");
                    //printf("\n\033[35mThe VERIFY_PROCESS %d  should be killed. But killing operation failed.\033[0m\n",(ptr+i)->pid);
                }
                (ptr+i)->pid = 0;
                (ptr+i)->life_time = 0;
                (ptr+i)->deadline = 0;
                (ptr+i)->recv_timer_stop =1;
                (ptr+i)->recv_delay_time = 0;
                (ptr+i)->type = NORMAL_PROCESS;
                (ptr+i)->process_step = 0;
				memset((ptr+i)->ip_str, 0, IP_STRING_LEN);
                success = Unregister_process_from_process_table(ptr, prcs_num, (ptr+i)->pid);
                break;
            default:
                break;
            }
            fflush(NULL);
            google::FlushLogFiles(google::ERROR);
            google::FlushLogFiles(google::INFO);
            usleep(100);
        }
        if ((1<(ptr+i)->pid && 0==(ptr+i)->recv_timer_stop && MIN_TIME_SPAN_ACCEPT_RECV< (ptr+i)->recv_delay_time)) {
            switch ((ptr+i)->type) {
            case VERIFY_PROCESS:
                success = kill((ptr+i)->pid,SIGKILL);
                waitpid(-1,NULL,WNOHANG);
                if (0==success) {
                    LOG_WARNING("Kill pid %d trigered by %s, invalid connection (%d sec). OK.\n",(ptr+i)->pid,(ptr+i)->ip_str, (ptr+i)->recv_delay_time);
                    //LOG(ERROR)<<"VERIFY_PROCESS "<<(ptr+i)->pid <<", was killed due to lifetime: "<<(ptr+i)->deadline;
                    //Increase_half_lifetime_record_process(ptr, prcs_num);
                } else {
                    LOG_ERROR("Kill pid %d trigered by %s, invalid connection (%d sec). Failed.\n",(ptr+i)->pid,(ptr+i)->ip_str, (ptr+i)->recv_delay_time);
                    //perror("VERIFY_PROCESS was killed, but kill operation faild");
                    //printf("\n\033[35mThe VERIFY_PROCESS %d  should be killed. But killing operation failed.\033[0m\n",(ptr+i)->pid);
                }
                (ptr+i)->pid = 0;
                (ptr+i)->life_time = 0;
                (ptr+i)->deadline = 0;
                (ptr+i)->recv_timer_stop =1;
                (ptr+i)->recv_delay_time = 0;
                (ptr+i)->type = NORMAL_PROCESS;
                (ptr+i)->process_step = 0;
                success = Unregister_process_from_process_table(ptr, prcs_num, (ptr+i)->pid);
                break;
            default:
                break;
            }
            fflush(NULL);
            google::FlushLogFiles(google::ERROR);
            google::FlushLogFiles(google::WARNING);
            google::FlushLogFiles(google::INFO);
            usleep(100);
        }
    }

    return 1;
}





/* *************************************************
 * Function Name:
 * 		int Increase_half_lifetime_record_process(struct ChildProcessStatus *ptr, int prcs_num, int deadline)
 *      set the lifetime of Record_process in queue to 0
 * Input:
 * 		struct ChildProcessStatus *ptr ---> all the child process in the table
 * 		int prcs_num   --->  the sum of all child processes
 * 		int deadline ---> the max life time
 * Output:
 * 		1 ---> success;
 * 		-1 ---> failure
 * *************************************************/
int Increase_half_lifetime_record_process(struct ChildProcessStatus *ptr, int prcs_num)
{
    int i = 0;
    /* Check the input parameters */
    if (NULL==ptr||0>=prcs_num) {
        perror("error@mointor_process.cc:Zero_Lifetime_Record_Process():NULL==ptr");
        return -1;
    }

    /* ZERO all RECORD or CAS process to be handled in the queue */
    for (i=0; i<prcs_num; i++) {
        if ((VERIFY_PROCESS== (ptr+i)->type)) {
            (ptr+i)->life_time = (int)((ptr+i)->life_time / PROCESS_LIEF_TIME_INC_MULTIPLY_FACTOR);
        }
    }
    return 1;
}

void Print_current_date_time(void)
{
    time_t t;
    t = time(NULL);
    printf(" %24.24s\r",ctime(&t));

}

int Count_available_process_slot(void)
{
    int j = 0;

    struct ShareMemProcess * mem_ptr = NULL;
    struct ChildProcessStatus *process_ptr = NULL;

    int success = 0;
    int semid = 0;

    int available_slot_sum = 0;

    semid = GetExistedSemphore(PROCESS_SHARE_ID);
    success = AcquireAccessRight(semid);
    mem_ptr = (struct ShareMemProcess *)MappingShareMemOwnSpace(PROCESS_SHARE_ID);
    process_ptr = (struct ChildProcessStatus * )(mem_ptr->process_table);

    /*  set the life time of the process table */
    /* Place the pid into the table */

    for (j=0; j<MAX_PROCESS_NUMBRER; j++) {
        if(0==(process_ptr+j)->pid) {
            available_slot_sum ++;
        }
    }

    /* Free memory control handler */
    success = UnmappingShareMem((void*)mem_ptr);
    success = ReleaseAccessRight(semid);


    return available_slot_sum;
}

int Stop_recv_timer(pid_t pid)
{
    int j = 0;

    struct ShareMemProcess * mem_ptr = NULL;
    struct ChildProcessStatus *process_ptr = NULL;

    int ret = 0;
    int semid = 0;

    semid = GetExistedSemphore(PROCESS_SHARE_ID);
    ret = AcquireAccessRight(semid);
    mem_ptr = (struct ShareMemProcess *)MappingShareMemOwnSpace(PROCESS_SHARE_ID);
    process_ptr = (struct ChildProcessStatus * )(mem_ptr->process_table);

    /*  set the life time of the process table */
    /* Place the pid into the table */

    for (j=0; j<MAX_PROCESS_NUMBRER; j++) {
        if(pid==(process_ptr+j)->pid) {
            //if(MIN_TIME_SPAN_ACCEPT_RECV>(process_ptr+j)->recv_delay_time) {
                (process_ptr+j)->recv_timer_stop = 1;
                break;
            //}
        }
    }

    /* Free memory control handler */
    ret = UnmappingShareMem((void*)mem_ptr);
    ret = ReleaseAccessRight(semid);


    return 1;

}

