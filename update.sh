#!/usr/bin/env bash
# Script to update the local RPKI cache

cd $(dirname $0)

mkdir -p ./data
./rcynic/rcynic -c ./rcynic/rcynic.conf
./manage.py migrate
./parse.py -l warning -f ./data/rcynic.xml -r ./data |& tee -a > data/parse.log
