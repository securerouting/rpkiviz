all: build

build:
	python setup.py build
	cp build/lib.*/rpki/POW/_POW.so ../rpki/POW/

#install:
#	python setup.py install --record installed

#uninstall:
#	for f in `cat installed`; do rm $$f; done

clean:
	rm -rf build


distclean: clean
	rm -f autoconf.py autoconf.pyc
