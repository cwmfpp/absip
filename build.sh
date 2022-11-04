tar zcvf libosip2-5.1.0.tar.gz libosip2-5.1.0 && rm libosip2-5.1.0 -rf && tar xvf libosip2-5.1.0.tar.gz && rm libosip2-5.1.0.tar.gz
cd libosip2-5.1.0/ && ./configure --prefix=`pwd`/../_install && make && make install-strip
cd -
tar zcvf libexosip2-5.1.0.tar.gz libexosip2-5.1.0 && rm libexosip2-5.1.0/ -rf && tar xvf libexosip2-5.1.0.tar.gz && rm libexosip2-5.1.0.tar.gz -rf
cd libexosip2-5.1.0/ && ./configure --prefix=`pwd`/temp --disable-openssl --enable-shared --includedir=`pwd`/../_install/include libdir=`pwd`/../_install/lib && make && make install-strip
cd -
