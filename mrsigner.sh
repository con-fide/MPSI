#/bin/sh

# Where is OpenSSL 1.1.x?

OPENSSL_LIBDIR=/usr/local/lib
if [ "$OPENSSL_LIBDIR" != "" ]
then
        if [ "$LD_LIBRARY_PATH" = "" ]
        then
                export LD_LIBRARY_PATH=$OPENSSL_LIBDIR
        else
                export LD_LIBRARY_PATH=$OPENSSL_LIBDIR:$LD_LIBRARY_PATH
        fi
fi

exec ./mrsigner "$@"

