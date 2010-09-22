#!/bin/sh

if [ ! -f `which git` ]; then
  exit 0
elif [ ! -d .git ]; then
  exit 0
fi

date=`LC_ALL=C date "+%a, %d %b %Y %H:%M:%S %z"`

REVISION="$(git rev-list HEAD -n 1 | head -c 7)";
LOCALID="$(git rev-list HEAD | wc -l)";

ver="${LOCALID}.${REVISION}";

rm -f debian/changelog
rm -Rf debian/tcpflow
cat debian/changelog.in | sed -e "s|@@DATE@@|$date|g" | sed -e "s|@@VER@@|$ver|g" > debian/changelog
dpkg-buildpackage -rfakeroot -us -uc -i\.git -I.git
