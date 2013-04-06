/* *************************************************
 * File name:
 * 		monitor_process.h
 * Description:
 * 		To avoid the process being blocked, there is a monitor process
 * 		to kill those ones whose life time is too long.
 * Author:
 * 		Yan Zhiwei, jerod.yan@gmail.com  (Drum Team)
 * Date:
 *		2012-12-13
 * *************************************************/
#ifndef MONITOR_PROCESS_H
#define MONITOR_PROCESS_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "shmsem.h"
#include "verify_uk_common.h"
#include "check.h"

int Insert_pid_process_table(pid_t pid,int deadline,enum ProcessType type);
int Remove_pid_process_table(pid_t pid);
int Register_process_into_process_table(struct ChildProcessStatus *ptr, int prcs_num,pid_t pid,int deadline,enum ProcessType type);
int Unregister_process_from_process_table(struct ChildProcessStatus *ptr, int prcs_num,pid_t pid);
int Increase_process_life_time(struct ChildProcessStatus *ptr, int prcs_num);
int Kill_invalid_process(struct ChildProcessStatus *ptr, int prcs_num);

int Set_process_life_time(pid_t pid, int life_time);

int Increase_half_lifetime_record_process(struct ChildProcessStatus *ptr, int prcs_num);

void Print_current_date_time(void);
int Count_available_process_slot(void);
int Stop_recv_timer(pid_t pid);


#endif
