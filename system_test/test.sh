#!/bin/bash

#All are under this directory
WORK_DIR="$HOME/linuxigd2_test"

#Where build software
BUILD_DIR="$WORK_DIR/builds"

#Where to clone sources
SRC_DIR="$WORK_DIR/src"

#Where to unpack device protection files
DP_SRC="$WORK_DIR/dp_files"

#log files
LOG_DIR="$WORK_DIR/logs"
DEBUG_LOG="$LOG_DIR/debug.txt"
LINUXIGD2_LOG="$LOG_DIR/linux_igd2.txt"
CP_TEST_LOG="$LOG_DIR/cp_test_log.txt"

#chroot for upnpd
LINUXIGD2_CHROOT="$WORK_DIR/linuxigd2_chroot"

#software and libraries
PREFIX="$WORK_DIR/installed_software"

DISTRIB_ID="None"
#check operating system
if [ -n "`which lsb_release`" ]; then
	DISTRIB_ID=`lsb_release -si`
elif [ -f /etc/meego-release ]; then
	#MeeGo
	DISTRIB_ID="MeeGo"
else
	#other
	DISTRIB_ID="None"
fi

#DEBUG=1
COLORS=1
VERBOSE=1


#Include general functions
SCRIPT_DIR=`dirname $0`
source ${SCRIPT_DIR}/general_functions.sh

prepare_host() {
	if [ ! -d $WORK_DIR ]; then
		echo  "'$WORK_DIR' does not exist, please create it with the following command:"
		echo "mkdir $WORK_DIR"
		exit 1
	fi

	#Create directories and log files
	rm -Rf $LOG_DIR
	mkdir -p $LOG_DIR
	exec_cmd "mkdir -p $DP_SRC"
	#exec_cmd "mkdir -p $WORK_DIR/data"
	exec_cmd "mkdir -p $BUILD_DIR"
	exec_cmd "touch $LINUXIGD2_LOG $DEBUG_LOG $CP_TEST_LOG"
	notify "Prepare host"

	#Create directories for chroot
	exec_cmd "mkdir -p $LINUXIGD2_CHROOT/{lib,bin,etc,proc,dev,tmp}"
	exec_cmd "mkdir -p $LINUXIGD2_CHROOT/etc/linuxigd"

	#PREFIX=$WORK_DIR/

	##check all required software in host
	REQUIRED_SOFTWARE="autoconf sudo libtool make"
	MISSING_SOFTWARE=""
	for i in $REQUIRED_SOFTWARE
	do
		if [ -z "`which $i`" ]; then
			MISSING_SOFTWARE="$MISSING_SOFTWARE $i, "
		fi
	done

	if [ -n "$MISSING_SOFTWARE" ]; then
		echo "$MISSING_SOFTWARE are required but not installed software. Install these before continue."
		exit 1
	fi


	# Test sudo
	sudo ls > /dev/null

	if [ -n "`pgrep upnpd`" ]; then
		notifyw "there is already upnpd running with pid `pgrep upnpd`, I will kill it"
		exec_cmd "sudo pkill upnpd"
		sleep 5
	fi

	#Check is there is HOST_CONFIGURED file or similar and intall required software if not
	if [ ! -f "$WORK_DIR/.HOST_CONFIGURED" ]; then
		notify "Need root access to install required software"
		if [ "$DISTRIB_ID" == "Debian" ]; then
			notify "We are in Debian"
			exec_cmd "sudo aptitude -y install libssl-dev git ldtp python-ldtp libgcrypt11 libgcrypt11-dev libgnutls26 libgnutls-dev libgnutls-dev gtk-doc-tools libsoup2.4-1 libsoup2.4-dev libsoup2.4-doc uuid-dev libgtk2.0-dev libglade2-dev"
			exec_cmd "touch \"$WORK_DIR/.HOST_CONFIGURED\""
		elif [ "$DISTRIB_ID" == "Ubuntu" ]; then
			#Ubuntu 10
			#Test ubuntu versions
			UBUNTU_VERSION=`lsb_release -sr`
			if [ "$UBUNTU_VERSION" == "10.10" ]; then
				notify "We are in Ubuntu 10.10"
				exec_cmd "sudo aptitude -y install libssl-dev git ldtp python-ldtp libgcrypt11 libgcrypt11-dev libgnutls26 libgnutls-dev libgnutls-dev gtk-doc-tools libsoup2.4-1 libsoup2.4-dev libsoup2.4-doc uuid-dev libgtk2.0-dev libglade2-dev"
			elif [ "$UBUNTU_VERSION" == "10.04" ]; then
				notify "We are in Ubuntu 10.04"
				exec_cmd "sudo aptitude -y install libssl-dev git-core ldtp python-ldtp libgcrypt11 libgcrypt11-dev libgnutls26 libgnutls-dev libgnutls-dev gtk-doc-tools libsoup2.4-1 libsoup2.4-dev libsoup2.4-doc uuid-dev libgtk2.0-dev libglade2-dev"
			else # older than 10.04 (not tested)
				notify "We are in unsupported Ubuntu version"
				exit 1
			fi
			exec_cmd "touch \"$WORK_DIR/.HOST_CONFIGURED"\"
		else
			notifyw "Can not configure host"
		fi
	fi
}

get_sources(){
	notify "Get sources"
	if [ ! -d "$SRC_DIR/deviceprotection" ]; then
		notifyv "Clone deviceprotection GIT repo"
		
		exec_cmd "git clone http://git.gitorious.org/igd2-for-linux/deviceprotection.git $SRC_DIR/deviceprotection"
	else
		notifyv "deviceprotection repository already cloned"
	fi
	
	if [ ! -d "$BUILD_DIR/deviceprotection" ]; then
		notifyv "Clone source dir"
		
		#keep $SRC_DIR clean, and copy it into $BUILD_DIR
		exec_cmd "git clone $SRC_DIR/deviceprotection $BUILD_DIR/deviceprotection"
	else
		notifyv "source dir already cloned"
	fi
}

build_and_install_hostapd() {
	notify "Build and install hostapd"
	if [ ! -f $PREFIX/lib/libhostapd.so ]; then
		P=`pwd`

		notifyv "build hostapd"
		exec_cmd "cd $BUILD_DIR/deviceprotection/hostap/hostapd"
		exec_cmd "PREFIX=$PREFIX make"
		exec_cmd "PREFIX=$PREFIX make libhostapd.so"

		notifyv "Install hostapd"
		exec_cmd "PREFIX=$PREFIX make install_hostapd"
		exec_cmd "cd $P"
	else
		notifyv "libhostapd already installed"
	fi
}

build_and_install_wpa_supplicant() {
	notify "Build and install wpa_supplicant"
	if [ ! -f $PREFIX/lib/libwpa_supplicant.so ]; then
		P=`pwd`

		notifyv "Build wpa_supplicant"
		exec_cmd "cd $BUILD_DIR/deviceprotection/hostap/wpa_supplicant"
		exec_cmd "PREFIX=$PREFIX make"
		exec_cmd "PREFIX=$PREFIX make libwpa_supplicant.so"

		notifyv "Install wpa_supplicant"
		exec_cmd "PREFIX=$PREFIX make install_libwpa_supplicant"

		exec_cmd "cd $P"
	else
		notifyv "libwpa_supplicant already installed"
	fi
}

build_libupnp () {
	notify "Build and install libupnp"
	if [ ! -f "$PREFIX/lib/libupnp.so.3.0.5" ]; then
		P=`pwd`
		exec_cmd "cd $BUILD_DIR/deviceprotection/pupnp_branch-1.6.x"

		notifyv "Build libupnp"
		exec_cmd "PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig  autoreconf -v --install"
		exec_cmd "PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig ./configure --prefix=$PREFIX"
		exec_cmd "PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig make"

		notifyv "Install libupnp"
		exec_cmd "PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig make install"

		exec_cmd "cd $P"
	else
		notifyv "libupnp already installed"
	fi
}

build_linuxigd2 () {
	notify "Build linuxigd2"
	P=`pwd`
	exec_cmd "cd $BUILD_DIR/deviceprotection/linuxigd2"

	#Fix Makefile
	notifyv "Change path to LIBUPNP_PREFIX in Makefile"
	exec_cmd "sed \"s#LIBUPNP_PREFIX=/usr/local#LIBUPNP_PREFIX=$PREFIX#g\" Makefile > kissa && cp kissa Makefile"

	notifyv "Build linuxigd2"
	exec_cmd "make 2>&1"
	exec_cmd "cd $P"
}

umount_chroot() {
	CO=0
	while [ -n "`pgrep upnpd`" ];
	do
		CO=`expr $CO + 1`
		if [ "$CO" -gt "10" ]; then
			sudo pkill -9 upnpd
			notifye "Too hard to kill upnpd"
		else
			exec_cmd "sudo pkill upnpd"
		fi
		sleep 2
	done

	while [ -n "`mount | grep $LINUXIGD2_CHROOT/proc`" ]
	do
		notifyv "Unmount proc from chroot"
		exec_cmd "sudo umount $LINUXIGD2_CHROOT/proc"
	done

	while [ -n "`mount | grep $LINUXIGD2_CHROOT/dev`" ]
	do
		notifyv "Umount dev from chroot"
		exec_cmd "sudo umount $LINUXIGD2_CHROOT/dev"
	done
}

chroot_linuxigd2 () {
	#TODO: this is executed always, add check to avoid id
	notify "Create chroot for linuxigd2"
	if [ -f "$BUILD_DIR/deviceprotection/linuxigd2/bin/upnpd" ]; then
		if [ -n "`pgrep upnpd`" ]; then
			notifyw "there is still upnpd running with pid `pgrep upnpd`, I will kill it"
			exec_cmd "sudo pkill upnpd"
		fi

		#Copy libs for chroot
		notifyv "Copy libraries to chroot"

		for i in `LD_LIBRARY_PATH=$PREFIX/lib/ ldd $BUILD_DIR/deviceprotection/linuxigd2/bin/upnpd | awk '{print $3}' | grep ^/`; do exec_cmd "cp $i $LINUXIGD2_CHROOT/lib/."; done
		exec_cmd "cp /lib/libc.so.6 /lib/ld-linux.so.2 $LINUXIGD2_CHROOT/lib/."

		#Copy binaries to chroot
		notifyv "Copy binaries to chroot"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/bin/upnpd $LINUXIGD2_CHROOT/bin"
		exec_cmd "cp /bin/sh $LINUXIGD2_CHROOT/bin/."

		notifyv "Copy upnpd settings to chroot"
		#settings
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/ligd.gif $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/gatedesc.xml $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/ligd.gif $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/gatedesc.xml $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/gateconnSCPD.xml  $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/gateicfgSCPD.xml $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/lanhostconfigSCPD.xml $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/gateEthlcfgSCPD.xml $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/deviceprotectionSCPD.xml $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/dummy.xml $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/accesslevel.xml $LINUXIGD2_CHROOT/etc/linuxigd"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/upnpd.conf $LINUXIGD2_CHROOT/etc"
		exec_cmd "cp $BUILD_DIR/deviceprotection/linuxigd2/configs/upnpd_ACL.xml  $LINUXIGD2_CHROOT/etc"

	else
		notifye "No such file o directory '$BUILD_DIR/deviceprotection/linuxigd2/bin/upnpd'"
	fi
}

run_linuxigd2 () {
	notify "Run upnpd in chroot"
	if [ -f "$LINUXIGD2_CHROOT/bin/upnpd" ]; then
		exec_cmd "sudo ls > /dev/null"
		if [ -n "`pgrep upnpd`" ]; then
			notifyw "upnpd already running, try to kill it"
			exec_cmd "sudo pkill upnpd"
			sleep 5
		fi

		#select configuration
		if [ "$1" == "pin" ]; then
			notifyv "Configure upnpd to PIN method"
			exec_cmd "sed \"s/wps_config_methods = push_button/#wps_config_methods = push_button/g\" $LINUXIGD2_CHROOT/etc/upnpd.conf > kissa && mv kissa $LINUXIGD2_CHROOT/etc/upnpd.conf"
		else
			notifyv "Configure upnpd to PBC method"
			exec_cmd "sed \"s/#wps_config_methods = push_button/wps_config_methods = push_button/g\" $LINUXIGD2_CHROOT/etc/upnpd.conf > kissa && mv kissa $LINUXIGD2_CHROOT/etc/upnpd.conf"
		fi

		#Remove old mount if any
		umount_chroot

		notifyv "Mount /proc to $LINUXIGD2_CHROOT/proc"
		exec_cmd "sudo mount -o bind /proc $LINUXIGD2_CHROOT/proc"

		notifyv "Mount /dev to $LINUXIGD2_CHROOT/dev"
		exec_cmd "sudo mount -o bind /dev $LINUXIGD2_CHROOT/dev"

		notifyv "Run upnpd"
		# SUDOBG=1 because eval, sudo, and & doesn't work well together
		LOG=$LINUXIGD2_LOG SUDOBG=1 exec_cmd "LC_ALL='C' LC_CTYPE='C' LANG='C' chroot $LINUXIGD2_CHROOT upnpd -f eth0 eth0 "

		exec_cmd "sleep 10"

		if [ -n "`pgrep upnpd`" ]; then
			notifyv "Upnpd is up and running"
		else
			notifye "Something went wrong, upnpd is not running"
		fi
	else
		notifyw "No upnpd in chroot"
	fi
}

build_gsources () {
	notify "Build gssdp, gupnp and gupnp-tools"
	P=`pwd`
	if [ ! -f "$PREFIX/lib/libgssdp-1.0.so.1.0.0" ]; then
		notifyv "build gssdp"
		exec_cmd "cd $BUILD_DIR/deviceprotection/gupnp/gssdp"
		exec_cmd "PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig ./autogen.sh --prefix=$PREFIX"
		exec_cmd "make"

		notifyv "Install gssdp"
		exec_cmd "make install"
		exec_cmd "cd $P"
	else
		notifyv "gssdp already installed"
	fi

	if [ ! -f "$PREFIX/lib/libgupnp-1.0.so.2.0.0" ]; then
		notifyv "build gupnp"
		exec_cmd "cd $BUILD_DIR/deviceprotection/gupnp/gupnp"
		exec_cmd "PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig ./autogen.sh --prefix=$PREFIX"
		exec_cmd "PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig make"

		notifyv "Install gupnp"
		exec_cmd "make install"
		exec_cmd "cd $P"
	else
		notifyv "gupnp already installed"
	fi


	if [ ! -f "$PREFIX/bin/gupnp-universal-cp" ]; then
		notifyv "build gupnp-tools"
		exec_cmd "cd $BUILD_DIR/deviceprotection/gupnp/gupnp-tools"
		exec_cmd "PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig ./autogen.sh --prefix=$PREFIX"
		exec_cmd "PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig make"

		notifyv "Install gupnp-tools"
		exec_cmd "make install"
		exec_cmd "cd $P"
	else
		notifyv "gupnp-tools already installed"
	fi
}

pin_test() {
	#with pin method
	notify "Test PIN method"

	#Start upnpd
	notifyv "Start upnpd"
	run_linuxigd2 pin

	#Test gupnp-universal-cp
	if [ -f "$PREFIX/bin/gupnp-universal-cp" ]; then
		EX=1
		LOG=$CP_TEST_LOG exec_cmd "python pin_method_test.py $PREFIX/bin/gupnp-universal-cp"
		EX=${a[0]}
		if [ "$EX" -ne "0" ]; then
			notifyw "PIN test failed with exit value $EX, check $CP_TEST_LOG"
		else
			notifyv "PIN test succeed"
		fi
		notifyv "Kill upnpd"
		exec_cmd "sudo pkill upnpd"
		exec_cmd "sleep 5"
		umount_chroot

	else
		notifye "No such file or directory '$PREFIX/bin/gupnp-universal-cp'"
	fi
}

pbc_test() {
	#with pbc method
	notify "Test PBC method"

	#Start upnpd
	notifyv "Start upnpd"
	run_linuxigd2 pbc

	#Test gupnp-universal-cp
	if [ -f "$PREFIX/bin/gupnp-universal-cp" ]; then
		EX=1
		LOG=$CP_TEST_LOG exec_cmd "python pbc_method_test.py $PREFIX/bin/gupnp-universal-cp"
		EX=${a[0]}
		if [ "$EX" -ne "0" ]; then
			notifyw "PBC test failed with exit value $EX, check $CP_TEST_LOG"

		else
			notifyv "PBC test succeed"
		fi
		notifyv "Kill upnpd"
		exec_cmd "sudo pkill upnpd"
		exec_cmd "sleep 5"
		umount_chroot
	else
		notifye "No such file or directory '$PREFIX/bin/gupnp-universal-cp'"
	fi
}


clean_up () {
	notify "cleanup"
	sudo pkill upnpd
	sleep 3

	umount_chroot

	echo -e "\nTest took $SECONDS seconds\n"

	echo "Log files are:"
	echo $DEBUG_LOG
	echo $LINUXIGD2_LOG
	echo $CP_TEST_LOG
	exit 0
}

trap "clean_up" SIGHUP SIGINT SIGTERM


case "$1" in
all)

	prepare_host
	get_sources

	build_and_install_wpa_supplicant
	build_libupnp
	build_linuxigd2
	chroot_linuxigd2

	build_and_install_hostapd
	build_gsources

	exec_cmd "sleep 5"
	pin_test
	exec_cmd "sleep 5"
	pbc_test

	clean_up
	;;

upnpd_test)
	#Send ramdomly USR1 and USR2 to upnpd and sleep random time (0-5 sconds) between kills
	rm $LINUXIGD2_LOG
	touch $LINUXIGD2_LOG
	run_linuxigd2 pbc

	COUNT=0
	MAX=100
	while [ -n "`pgrep upnpd`" ]
	do
		sleep $((RANDOM%6))
		R=$((RANDOM%2))
		RAN=`expr $R + 1`
		sudo pkill -USR${RAN} upnpd
		echo "Run test $COUNT"
		if [ $MAX -gt $COUNT ]; then
			COUNT=`expr $COUNT + 1`
		else
			sudo pkill upnpd
		fi
	done

	clean_up
	echo "Log file is $LINUXIGD2_LOG"
	;;
*)
	echo usage:
	echo "./`basename $0` all"
	exit 1
	;;
esac
