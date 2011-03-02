#!/bin/bash

## How to use
# Variables
# SUDOBG	Run plain commands in background and with sudo, because some cases eval doesn't work well and "sudo command &" is one of these
# COLORS	Colorize warning and error
# VERBOSE	Enable notifyv
# QUIET		Shows only errors when set
# STEP		ask before execute any command after when it set
# BREAK		ask before execute command when it set before exec_cmd and it will be unset when command executed
# DRY_RUN	only echoing commands without executing
# CMD_LOG	Log where to save executed commands (without redirections to logs)
#
# Functions
# All notifies are echoed to $DEBUG_LOG
# notify	General echo
# notifyw	Same than notify, but colorize output when COLORS is set
# notifyd	When QUIET is set, this is still workable. Useful when DRY_RUN is set
# notifye	Colorize errors and execute clean_up function if exist or exit 1
# pretty_log	More informative log messages
# exec_cmd	Execute commands using eval (pipes work too) or plain command in background with sudo when SUDOBG is set
#


#TODO: Test required variables: DEBUG_LOG, DEBUG, COLORS, VERBOSE
if test "${DEBUG_LOG+set}" != set ; then
	DEBUG_LOG=`mktemp`
fi

if test "${CMD_LOG+set}" == set ; then
	if [ ! -f "$CMD_LOG" ]; then
		CMD_LOG=`mktemp`
	else
		#Log is exist
		echo -e "\n\n\n\n #### `date` ####" >> $CMD_LOG
		#rm -Rf $CMD_LOG
	fi
fi




#Add time at the beginning of the lines in log and redirect it to $1 or $DEBUG_LOG
pretty_log () {
	LOGFILE="$DEBUG_LOG"
	EXTRA=""
	if [ -n "$1" ]; then
		LOGFILE=$1
		if [ -n "$2" ]; then
			EXTRA=$2
		fi
	fi

	while read data
	do
		if [ "$DEBUG" ]; then
			echo "[$(date +'%H:%M:%S')]$EXTRA $data"
		fi
		echo "[$(date +'%H:%M:%S')]$EXTRA $data" >> $LOGFILE
		if [ "$LOGFILE" != "$DEBUG_LOG" ]; then
			echo "[$(date +'%H:%M:%S')]$EXTRA $data" >> $DEBUG_LOG
		fi
	done
}

#Normal
notify () {
	if test "${QUIET+set}" != set ; then
		echo "`date +"%H:%M:%S"`: $1"
	fi
	echo -e "\n[`date +"%H:%M:%S"`] -> $1" >> $DEBUG_LOG
}

#Verbose
notifyv () {
	if [ "$VERBOSE" ]; then
		if test "${QUIET+set}" != set ; then
			echo -e "`date +"%H:%M:%S"`:\t - $1"
		fi
	fi
	echo -e "\n[`date +"%H:%M:%S"`] -> $1" >> $DEBUG_LOG
}

#format output for dry run command
notifyd () {
	echo -e "$1"
}

#Warnings
notifyw () {
	if test "${QUIET+set}" != set ; then
		if [ "$COLORS" ]; then
			echo "[01;34m`date +"%H:%M:%S"`: $1[0m"
		else
			echo "`date +"%H:%M:%S"`: $1"
		fi
	fi
	echo -e "\n[`date +"%H:%M:%S"`] -> $1" >> $DEBUG_LOG
}

#Errors
notifye () {
	if [ "$COLORS" ]; then
		echo "[01;31m`date +"%H:%M:%S"`: $1[0m"
	else
		echo "`date +"%H:%M:%S"`: $1"
	fi
	echo -e "\n[`date +"%H:%M:%S"`] -> $1" >> $DEBUG_LOG

	#test is there clean_up function
	if [ "`declare -f clean_up > /dev/null; echo $?`" -eq "0" ]; then
		clean_up
	else
		notifyw "No 'clean_up' function"
		exit 1
	fi
}

exec_cmd () {
	EXECUTECMD=1

	#Stepping
	if [ "${STEP+set}" == set ] || [ "${BREAK+set}" == set ]; then
		if [ "${BREAK+set}" == set ]; then
			echo "Breakpoint $2, execute [Y/n/c] '$1'"
			unset BREAK
		else
			echo "Execute command [Y/n/c] '$1'"
		fi
		read ansver
		if [ "$ansver" == "n" ]; then
			echo "Skip command"
			EXECUTECMD=0
		elif [ "$ansver" == "c" ]; then
			echo "Cancel execution"
			#test is there clean_up function
			if [ "`declare -f clean_up > /dev/null; echo $?`" -eq "0" ]; then
				clean_up
			else
				notifyw "No 'clean_up' function"
				exit 1
			fi
		else
			EXECUTECMD=1
		fi
	fi

	#Execute command
	if [ "$EXECUTECMD" -eq "1" ]; then
		#Test log variable
		if test "${LOG+set}" != set ; then
			if test "${DEBUG_LOG+set}" == set ; then
				LOG=$DEBUG_LOG
			else
				LOG="/dev/null"
			fi
		fi


		#SUDOBG because eval, sudo, and & doesn't work well together
		if test "${SUDOBG+set}" == set ; then
			EXECUTED_CMD="echo $1 | sudo sh &"
			## Echo command to DEBUG_LOG
			echo $EXECUTED_CMD | pretty_log $DEBUG_LOG " Execute: "

			if test "${DRY_RUN+set}" != set ; then
				echo "$1 >> $LOG 2>&1" | sudo sh &
				a="${PIPESTATUS[@]}"
			fi

		else
			EXECUTED_CMD=$1
			## Echo command to DEBUG_LOG
			echo $EXECUTED_CMD | pretty_log $DEBUG_LOG " Execute: "

			if test "${DRY_RUN+set}" != set ; then
				eval "$1 ; typeset -a a=(\${PIPESTATUS[@]}) " >> $LOG 2>&1
			fi
		fi

		## Print command when dry run
		if test "${DRY_RUN+set}" == set ; then
			notifyd "$EXECUTED_CMD"
		fi

		## Echo command to CMD_LOG if set.
		if test "${CMD_LOG+set}" == set ; then
			echo $EXECUTED_CMD  >> $CMD_LOG
		fi

		#unset variables
		unset ONLY_WARNING
		unset LOG
		unset SUDOBG

		#Check return values
		for i in $a
		do
			#echo $i
			if [ "$i" -ne "0" ]; then
				if test "${ONLY_WARNING+set}" == set ; then
					notifyw "Command '$EXECUTED_CMD' returned $i"
				else
					notifye "Command '$EXECUTED_CMD' returned $i"
				fi
			fi
		done
	fi
}
