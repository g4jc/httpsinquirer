#!/bin/bash
VERSION="0.93"
sed -i "/<em:version>/c\        <em:version>$VERSION</em:version>" install.rdf

if [ ! -d "$DIRECTORY" ]; then
	mkdir pkg
fi
cd pkg
7z a -tzip -mx9 -mm=Deflate -mfb=258 -mmt=8 -mpass=15 -mtc=on "httpsinquirer-$VERSION.xpi" ../* -x@../.ignore
cd ..
echo "Generated "httpsinquirer-$VERSION.xpi" placed in pkg/"
sha512sum pkg/*
echo "Done!"
