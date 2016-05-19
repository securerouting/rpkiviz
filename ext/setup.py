from distutils.core import setup, Extension

import autoconf

setup(
    name='rpki',
    version='0.0',
    description='rpki.net python lib',
    #packages=["rpki", "rpki.POW"],
    ext_modules=[Extension('rpki.POW._POW',
                          sources=['POW.c'],
                          include_dirs=["./h"] + autoconf.include_dirs,
                          extra_link_args=["-Wl,-Bsymbolic"] + autoconf.extra_link_args,
                          libraries=autoconf.libraries,
                         )]
     )
