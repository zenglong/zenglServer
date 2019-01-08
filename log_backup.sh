#!/bin/bash
if [ $# -ne 2 ]; then
	echo "usage: ./log_backup.sh logfile_name pidfile_name"
	exit 1
else
	logfile_name=$1
	pidfile_name=$2
fi
log_backup_path="log_backup/"
target_log_file=${log_backup_path}${logfile_name}_$(date +"%Y%m%d").log
mv ${logfile_name} ${target_log_file}
kill -USR1 `cat ${pidfile_name}`
