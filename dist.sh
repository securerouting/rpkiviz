#!/usr/bin/env bash
make distclean
tar -C .. -acv --exclude-from=exclude -f ../rpkiviz.tar.xz rpkiviz/
