pkgname=cjail
pkgver=0
pkgrel=0
pkgdesc="cgroups-based jail tools"
arch=(i686 x86_64)
license=('GPL')
install=
source=(Makefile cjail.c mkcjail cjail-init.c)
md5sums=('d06a4f0a595cfa3f5e6c266be30ec75e'
         'f35e9efcd79266233833c82a88b711bb'
         'c3980d2d401c85525c7af96ec79e9112'
         'f308c9b6564eb83550cfb3f4b6d2f00c')
    
build() {
  cd "$srcdir"
  make
}

package() {
  cd "$srcdir"
  install -Dm4755 cjail "$pkgdir"/usr/sbin/cjail
  install -Dm744 mkcjail "$pkgdir"/usr/bin/mkcjail
  install -Dm755 cjail-init "$pkgdir"/usr/lib/cjail/init
}
