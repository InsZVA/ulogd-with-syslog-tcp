```
yum install automake autoconf libtool mysql-devel -y

git clone https://github.com/InsZVA/ulogd-with-syslog-tcp
cd ulogd-with-syslog-tcp
./autogen.sh

#Install libnfnetlink
git clone git://git.netfilter.org/libnfnetlink
cd libnfnetlink
./autogen.sh
./configure
make && make install
cd ..

#pkg config path
echo "export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/">>/etc/profile
source /etc/profile

#Install libmnl
git clone git://git.netfilter.org/libmnl
cd libmnl
./autogen.sh
./configure
make && make install
cd ..

#Install libnetfilter_log
git clone git://git.netfilter.org/libnetfilter_log
cd libnetfilter_log
./autogen.sh
./configure
make && make install
cd ..

#Install libnetfilter_conntrack
git clone git://git.netfilter.org/libnetfilter_conntrack
cd libnetfilter_conntrack
./autogen.sh
./configure
make && make install
cd ..

#Install libnetfilter_acct
git clone git://git.netfilter.org/libnetfilter_acct
autoreconf -fi
make && make install
cd ..

./configure
make && make install
```