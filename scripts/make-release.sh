#!/bin/bash

MOKEY_DIR='./.mokey-release'
VERSION=`grep Version main.go | egrep -o '[0-9]\.[0-9]\.[0-9]'`
REL_DIR=${MOKEY_DIR}/mokey-${VERSION}

rm -Rf ${MOKEY_DIR}
mkdir -p ${REL_DIR}/{cert,private}

cp ./mokey ${REL_DIR}/ 
cp ./mokey.yaml.sample ${REL_DIR}/ 
cp ./README.rst ${REL_DIR}/ 
cp ./AUTHORS.rst ${REL_DIR}/ 
cp ./LICENSE ${REL_DIR}/ 
cp -R ./templates ${REL_DIR}/ 
cp -R ./static ${REL_DIR}/ 
cp -R ./ddl ${REL_DIR}/ 

tar -C $MOKEY_DIR -cvzf mokey-${VERSION}.tar.gz mokey-${VERSION}
rm -Rf ${MOKEY_DIR}
