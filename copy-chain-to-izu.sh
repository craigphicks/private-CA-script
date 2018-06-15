#!/bin/bash
set -x
set -euo pipefail

# if [[ ${#@} -ne 1 ]]; then
#     echo "USAGE $0 <user>@<remote-machine>:<dirpath>"
#     exit 1
# fi

read filepath < <(./ca_builder.sh ca-chain-filepath 2>/dev/null) 
filedir=`dirname "${filepath}"`
filebase=`basename "${filepath}"`
#echo "filepath=$filepath"
#echo "filedir=$filedir"
#echo "filebase=$filebase"

tmpdir="$(mktemp -d copy-chain-to-remote.d.XXXXXXXXXXXX)"
trap "rm -rf ${tmpdir}" EXIT

cdir="${tmpdir}/copy-${filebase}.dir"
mkdir $cdir
cat <<EOF_ > ${cdir}/copy-${filebase}.sh
#!/bin/bash
[[ -d ${filedir} ]] || mkdir -p ${filedir}
cp ./${filebase} ${filedir}
chmod 444 ${filedir}/${filebase}
echo ${filedir}
ls -la ${filedir}
EOF_
chmod +x ${cdir}/copy-${filebase}.sh
cp ${filepath} ${cdir}
#ls -al ${cdir}
#echo "---- start content ----"
#cat ${cdir}/copy-${filebase}.sh
#echo "---- end content ----"
scp -r ${cdir} ichiban@izu:~/upload-dest

