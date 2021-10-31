#!/bin/sh
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "Usage: $(basename $0) <<bapcap file path>> <<output file name>>"
    exit 1
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}"tmp.XXXXXXXX)

unzip $1 -d $tmpdir
chmod -R 777 $tmpdir
cd $tmpdir

xmlstarlet ed --inplace \
-N x=http://schemas.microsoft.com/sqlserver/dac/Serialization/2012/02 \
--delete "//x:Element[@Type='SqlMasterKey']" \
--delete "//x:Element[@Type='SqlRoleMembership']" \
--delete "//x:Element[@Type='SqlPermissionStatement']" \
--delete "//x:Element[@Type='SqlUser']" \
model.xml

SHA256HASH=$(shasum -a 256 model.xml | awk '{ print $1 }')

xmlstarlet ed --inplace \
-N x=http://schemas.microsoft.com/sqlserver/dac/Serialization/2012/02 \
-u "//x:DacOrigin/x:Checksums/x:Checksum[@Uri='/model.xml']" \
-v $SHA256HASH \
origin.xml

zip -r -X $(basename $2) .
cd $(dirname $0)
cp $tmpdir/$(basename $2) $2
rm -rf $tmpdir

echo "Done"