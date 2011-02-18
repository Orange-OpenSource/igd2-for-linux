#!/bin/bash

WORK_DIR="$HOME/tmp_dp"
SRC_DIR="$WORK_DIR/src"
LOG_DIR="$WORK_DIR/log/"
DEBUGLOG="$LOG_DIR/debug.txt"
LINUXIGD2_LOG="$LOG_DIR/linux_igd2.txt"
LINUXIGD2_CHROOT="$WORK_DIR/linuxigd_chroot"

BRANCH_NAME=gupnp_with_dp
PATCHSET_ID=110211001
#100921001

LIBUPNP_SRC="libupnp-patched-1.6.6.tar.bz2"
LINUXIGD2_SRC="linuxigd2-0.8.tar.gz"

DISTRIB_ID="None"
ROOT_ACCESS="su"
#check operating system
if [ -n "`which lsb_release`" ]; then
	DISTRIB_ID=`lsb_release -si`
	if [ "$DISTRIB_ID" == "Ubuntu" ]; then
		ROOT_ACCESS="sudo"
	fi

elif [ -f /etc/meego-release ]; then
	#MeeGo
	DISTRIB_ID="MeeGo"
else
	#other
	DISTRIB_ID="None"
fi

echo2(){
	echo "`basename $0`: $1"
}

prepare_host() {
	if [ -n "`pgrep upnpd`" ]; then
		echo "there is already upnpd running with pid `pgrep upnpd`, kill it befor continue or press 'y' and give a root password"
		read -t 10 ansver
		if [ "$ansver" == "y" ]; then
			if [ "$ROOT_ACCESS" == "su" ]; then
				su -c "pkill upnpd"
			else
				sudo pkill upnpd
			fi
			sleep 5
		else
			exit 1
		fi

	fi

	echo2 "Prepare host"
	rm -Rf $LOG_DIR
	mkdir -p $WORK_DIR/data
	mkdir -p $LOG_DIR
	touch $LINUXIGD2_LOG

	#for chroot
	mkdir -p $LINUXIGD2_CHROOT/{lib,bin,etc,proc,dev,tmp}
	mkdir -p $LINUXIGD2_CHROOT/etc/linuxigd

	PREFIX=$WORK_DIR/data

	echo2 "Root access required to install softwares"
	if [ "$DISTRIB_ID" == "Debian" ]; then
		echo "Remove before publish and add tldp tldp-python"
		#su -c "aptitude install autoconf libgcrypt11 libgcrypt11-dev libgnutls13 libgnutls-dev libtool libgnutls-dev gtk-doc-tools libsoup2.4-1 libsoup2.4-dev libsoup2.4-doc uuid-dev libgtk2.0-dev libglade2-dev"
	elif [ "$DISTRIB_ID" == "Ubuntu" ]; then
		sudo aptitude install libgcrypt11 libgcrypt11-dev autoconf libtool libgnutls13 libgnutls-dev libgnutls-dev gtk-doc-tools libsoup2.4-1 libsoup2.4-dev libsoup2.4-doc uuid-dev libgtk2.0-dev libglade2-dev
	else
		echo "Can not configure $DISTRIB_ID"
		exit 1
	fi
}

clone_hostap(){
	#Clone hostap
	if [ ! -d "$SRC_DIR/hostap" ]; then
		git clone http://w1.fi/hostap.git $SRC_DIR/hostap
	else
		echo2 "hostapd already cloned"
	fi

	#Clone gssdp
	if [ ! -d "$SRC_DIR/gssdp" ]; then
		git clone http://git.gitorious.org/gupnp/gssdp.git $SRC_DIR/gssdp
	else
		echo2 "gssdp already cloned"
	fi

	#CLone gupnp
	if [ ! -d "$SRC_DIR/gupnp" ]; then
		git clone http://git.gitorious.org/gupnp/gupnp.git $SRC_DIR/gupnp
	else
		echo2 "gupnp already cloned"
	fi

	#Clone gupnp-tools
	if [ ! -d "$SRC_DIR/gupnp-tools" ]; then
		git clone http://git.gitorious.org/gupnp/gupnp-tools.git $SRC_DIR/gupnp-tools
	else
		echo2 "gupnp-tools already cloned"
	fi
}

patch_hostap(){
	if [ ! -d "$SRC_DIR/hostap" ]; then
		echo2 "No '$SRC_DIR/hostap', clone it first"
		exit 1
	elif [ ! -d "$WORK_DIR/hostap" ]; then
		PATCH="`ls hostap_patches_*.tgz | head -1`"
		P=`pwd`
		echo2 "Copy hostap sources"
		git clone $SRC_DIR/hostap $WORK_DIR/hostap  >> $DEBUGLOG 2>&1
		cp $PATCH $WORK_DIR/hostap/.
		cd $WORK_DIR/hostap
		echo2 "Change branch to ${BRANCH_NAME}"
		git checkout -b ${BRANCH_NAME} 6195adda9b4306cda2b06b930c59c95832d026a9  >> $DEBUGLOG 2>&1
		mkdir tmp_patches
		echo2 "Unpack patches"
		tar xzvf $PATCH -C tmp_patches >> $DEBUGLOG 2>&1
		echo2 "Patch hostap"
		git am tmp_patches/*  >> $DEBUGLOG 2>&1

		##
		#Fix libhostapd.pc
		##
		sed "s#prefix=\/usr\/local#prefix=$PREFIX#g" hostapd/libhostapd.pc > kissa && mv kissa hostapd/libhostapd.pc
		sed 's/Cflags: -I${includedir}\/hostapd/Cflags: -I${includedir}/g' hostapd/libhostapd.pc > kissa && mv kissa hostapd/libhostapd.pc
		echo2 "Clean"
		rm -rf tmp_patches  >> $DEBUGLOG 2>&1
		cd $P
	else
		echo2 "hostap already patched"
	fi
}

patch_gsources() {
	P=`pwd`
	#gssdp
	if [ ! -d "$SRC_DIR/gssdp" ]; then
		echo2 "No '$SRC_DIR/gssdp', clone it first"
		exit 1
	elif [ ! -d "$WORK_DIR/gssdp" ]; then
		PATCH="gupnp_gssdp_patches_${PATCHSET_ID}.tgz"
		if [ -f  "$PATCH" ]; then
			echo2 "Copy gssdp sources"
			git clone $SRC_DIR/gssdp $WORK_DIR/gssdp  >> $DEBUGLOG 2>&1
			cp $PATCH $WORK_DIR/gssdp/.
			cd $WORK_DIR/gssdp
			git checkout -b ${BRANCH_NAME} fb8333c67483b5f245ab15bfd42907816d27c6fc >> $DEBUGLOG 2>&1
			mkdir tmp_patches
			echo2 "Unpack patches"
			tar xvzf gupnp_gssdp_patches_${PATCHSET_ID}.tgz -C tmp_patches >> $DEBUGLOG 2>&1
			echo2 "Patch gssdp"
			git am --whitespace=nowarn tmp_patches/* >> $DEBUGLOG 2>&1
			echo2 "Clean"
			rm -rf tmp_patches >> $DEBUGLOG 2>&1
			cd $P
		else
			echo2 "No such file '$PATCH'"
			exit 1
		fi
	else
		echo2 "gssdp already patched"
	fi

	#gupnp
	if [ ! -d "$SRC_DIR/gupnp" ]; then
		echo2 "No '$SRC_DIR/gupnp', clone it first"
		exit 1
	elif [ ! -d "$WORK_DIR/gupnp" ]; then
		PATCH="gupnp_gupnp_patches_${PATCHSET_ID}.tgz"
		if [ -f  $PATCH ]; then
			echo2 "Copy gupnp sources"
			git clone $SRC_DIR/gupnp $WORK_DIR/gupnp  >> $DEBUGLOG 2>&1
			cp $PATCH $WORK_DIR/gupnp/.
			cd $WORK_DIR/gupnp
			git checkout -b ${BRANCH_NAME} 8a67704144db3bd994f23837ff000c65766c3d4d >> $DEBUGLOG 2>&1
			mkdir tmp_patches
			echo2 "Unpack patches"
			tar xvzf gupnp_gupnp_patches_${PATCHSET_ID}.tgz -C tmp_patches >> $DEBUGLOG 2>&1
			echo2 "Patch gupnp"
			git am --whitespace=nowarn tmp_patches/* >> $DEBUGLOG 2>&1
			echo2 "Clean"
			rm -rf tmp_patches >> $DEBUGLOG 2>&1
			cd $P
		else
			echo2 "No such file '$PATCH'"
			exit 1
		fi
	else
		echo2 "gupnp already patched"
	fi

	#gupnp-tools
	if [ ! -d "$SRC_DIR/gupnp-tools" ]; then
		echo2 "No '$SRC_DIR/gupnp-tools', clone it first"
		exit 1
	elif [ ! -d "$WORK_DIR/gupnp-tools" ]; then
		PATCH="gupnp_gupnp-tools_patches_${PATCHSET_ID}.tgz"
		if [ -f  $PATCH ]; then
			echo2 "Copy gupnp-tools sources"
			git clone $SRC_DIR/gupnp-tools $WORK_DIR/gupnp-tools  >> $DEBUGLOG 2>&1
			cp $PATCH $WORK_DIR/gupnp-tools/.
			cd $WORK_DIR/gupnp-tools
			git checkout -b ${BRANCH_NAME} 5bea76c0956ce85fd071bd20e491bd48747964aa >> $DEBUGLOG 2>&1
			mkdir tmp_patches
			echo2 "Unpack patches"
			tar xvzf gupnp_gupnp-tools_patches_${PATCHSET_ID}.tgz -C tmp_patches >> $DEBUGLOG 2>&1
			echo2 "Patch gupnp-tools"
			git am --whitespace=nowarn tmp_patches/* >> $DEBUGLOG 2>&1
			echo2 "Clean"
			rm -rf tmp_patches >> $DEBUGLOG 2>&1
			cd $P
		else
			echo2 "No such file '$PATCH'"
			exit
		fi
	else
		echo2 "gupnp-tools already patched"
	fi
}

build_and_install_hostapd() {
	if [ ! -f $PREFIX/lib/libhostapd.so ]; then
		P=`pwd`
		echo2 "build hostapd"
		cd $WORK_DIR/hostap/hostapd
		PREFIX=$PREFIX make  >> $DEBUGLOG 2>&1
		PREFIX=$PREFIX make libhostapd.so >> $DEBUGLOG 2>&1
		PREFIX=$PREFIX make install_hostapd >> $DEBUGLOG 2>&1
		cd $P
	else
		echo2 "libhostapd already installed"
	fi
}

build_and_install_wpa_supplicant() {
	if [ ! -f $PREFIX/lib/libwpa_supplicant.so ]; then
		P=`pwd`
		echo2 "build wpa_supplicant"
		cd $WORK_DIR/hostap/wpa_supplicant
		PREFIX=$PREFIX make  >> $DEBUGLOG 2>&1
		PREFIX=$PREFIX make libwpa_supplicant.so >> $DEBUGLOG 2>&1
		PREFIX=$PREFIX make install_libwpa_supplicant >> $DEBUGLOG 2>&1
		## Create pc file
		mkdir -p $PREFIX/lib/pkgconfig/
		echo "prefix=$PREFIX
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include
Name: libwpa_supplicant
Description: HostAP for WPA
Version: 0.1.0
Libs: -L\${libdir} -lwpa_supplicant
Cflags: -I\${includedir}" > $PREFIX/lib/pkgconfig/libwpa_supplicant.pc

		cd $P
	else
		echo2 "libwpa_supplicant already installed"
	fi
}

build_libupnp () {
	if [ ! -f "$PREFIX/lib/libupnp.so.3.0.5" ]; then
		if [ -f $LIBUPNP_SRC ]; then
			P=`pwd`
			tar -xjf $LIBUPNP_SRC -C $WORK_DIR/
			cd $WORK_DIR/libupnp-1.6.6
			PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig  autoreconf -v --install >> $DEBUGLOG 2>&1
			PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig ./configure --prefix=$PREFIX >> $DEBUGLOG  2>&1
			PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig make >> $DEBUGLOG  2>&1
			PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig make install >> $DEBUGLOG  2>&1
			cd $P
		else
			echo2 "No such file '$LIBUPNP_SRC'"
		fi
	else
		echo2 "libupnp already installed"
	fi
}

build_linuxigd2 () {
	if [ -f $LINUXIGD2_SRC ]; then
		P=`pwd`
		tar -xzf $LINUXIGD2_SRC -C $WORK_DIR/ 2> /dev/null
		cd $WORK_DIR/linuxigd2-0.8
		#Fix Makefile
		sed "s#LIBUPNP_PREFIX=/usr/local#LIBUPNP_PREFIX=$PREFIX#g" Makefile > kissa && mv kissa Makefile
		make  >> $LINUXIGD2_LOG  2>&1
		cd $P
	fi
}

run_linuxigd2 () {
	if [ -f "$WORK_DIR/linuxigd2-0.8/bin/upnpd" ]; then
		if [ -n "`pgrep upnpd`" ]; then
			echo "there is still upnpd running with pid `pgrep upnpd`, kill it befor continue"
			exit 1
		fi

		#Copy libs for chroot
		echo2 "Copy libraries to chroot"
		for i in `LD_LIBRARY_PATH=$PREFIX/lib/ ldd $WORK_DIR/linuxigd2-0.8/bin/upnpd | awk '{print $3}' | grep ^/`; do echo $i;  cp $i $LINUXIGD2_CHROOT/lib/.; done >> $LINUXIGD2_LOG  2>&1
		echo /lib/libc.so.6 >> $LINUXIGD2_LOG  2>&1
		echo /lib/ld-linux.so.2 >> $LINUXIGD2_LOG  2>&1
		cp  /lib/libc.so.6 /lib/ld-linux.so.2 $LINUXIGD2_CHROOT/lib/.

		#Copy binaries to chroot
		echo2 "Copy binaries to chroot"
		cp $WORK_DIR/linuxigd2-0.8/bin/upnpd $LINUXIGD2_CHROOT/bin
		cp /bin/sh $LINUXIGD2_CHROOT/bin/.

		echo2 "Copy upnpd settings to chroot"
		#settings
		cp $WORK_DIR/linuxigd2-0.8/configs/ligd.gif $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/gatedesc.xml $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/ligd.gif $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/gatedesc.xml $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/gateconnSCPD.xml  $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/gateicfgSCPD.xml $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/lanhostconfigSCPD.xml $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/gateEthlcfgSCPD.xml $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/deviceprotectionSCPD.xml $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/dummy.xml $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/accesslevel.xml $LINUXIGD2_CHROOT/etc/linuxigd
		cp $WORK_DIR/linuxigd2-0.8/configs/upnpd.conf $LINUXIGD2_CHROOT/etc
		cp $WORK_DIR/linuxigd2-0.8/configs/upnpd_ACL.xml  $LINUXIGD2_CHROOT/etc
		sed "s/wps_config_methods = push_button/#wps_config_methods = push_button/g" $LINUXIGD2_CHROOT/etc/upnpd.conf > kissa && mv kissa $LINUXIGD2_CHROOT/etc/upnpd.conf

		# sudo/su commands
		su -c "mount -o bind /proc $LINUXIGD2_CHROOT/proc && mount -o bind /dev $LINUXIGD2_CHROOT/dev && LC_ALL=\"C\" LC_CTYPE=\"C\" LANG=\"C\" chroot $LINUXIGD2_CHROOT upnpd -f eth0 eth0 >> $LINUXIGD2_LOG  2>&1 &"
		PIDI=`pgrep upnpd`
		echo "Run linuxigd2 with pid $PIDI"
	else
		echo2 "No upnpd, build it first"
	fi
}

build_gsources () {
	#PREFIX="$WORK_DIR/data"
	P=`pwd`
	if [ ! -f "$PREFIX/lib/libgssdp-1.0.so.1.0.0" ]; then
		echo2 "build and install gssdp"
		cd $WORK_DIR/gssdp
		PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig ./autogen.sh --prefix=$PREFIX  >> $DEBUGLOG  2>&1
		make  >> $DEBUGLOG  2>&1
		make install  >> $DEBUGLOG  2>&1
	else
		echo2 "gssdp already installed"
	fi

	if [ ! -f "$PREFIX/lib/libgupnp-1.0.so.2.0.0" ]; then
		echo2 "build and install gupnp"
		cd $WORK_DIR/gupnp
		PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig ./autogen.sh --prefix=$PREFIX  >> $DEBUGLOG  2>&1
		PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig make  >> $DEBUGLOG  2>&1
		make install  >> $DEBUGLOG  2>&1
	else
		echo2 "gupnp already installed"
	fi


	if [ ! -f "$PREFIX/bin/gupnp-universal-cp" ]; then
		echo2 "build and install gupnp-tools"
		cd $WORK_DIR/gupnp-tools
		PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig ./autogen.sh --prefix=$PREFIX  >> $DEBUGLOG  2>&1
		PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig make  >> $DEBUGLOG  2>&1
		make install  >> $DEBUGLOG  2>&1
	else
		echo2 "gupnp-tools already installed"
	fi
}

clean_up () {
	echo2 "cleanup"
	#kill upnp
	#umount proc
	#umount dev
	#remove file
	#show log files
}

case "$1" in
all)

	prepare_host
	clone_hostap
	patch_hostap
	patch_gsources

	echo "################### end gupnp-universal-cp ###########################"

	build_and_install_wpa_supplicant
	build_libupnp
	build_linuxigd2

	run_linuxigd2
	echo "###### end of linux igd and start of gupnp-universal-cp ##############"

	build_and_install_hostapd
	build_gsources

	echo "################### end gupnp-universal-cp ###########################"

	##
	#with pin method
	#python pin_method_test.py /home/kari/tmp_dp/data/bin/gupnp-universal-cp

	#with pbc method
	#python pin_method_test.py /home/kari/tmp_dp/data/bin/gupnp-universal-cp


	#$WORK_DIR/data/bin/gupnp-universal-cp >> $DEBUGLOG  2>&1
	;;
*)
	echo usage:
	echo "./`basename $0` all"
	exit 1
	;;
esac
