pkgname=cjail
pkgver=0
pkgrel=0
pkgdesc="cgroups-based jail tools"
arch=(i686 x86_64)
license=('GPL')
install=
source=(Makefile cjail.c mkcjail cjail-init.c)
md5sums=('e202b48227c1a9a6772f83f9be3d0ae6'
         'eb4d4590d8a5acaf0193b8e6e33ff12c'
         '52b3ede33017e65adce8fe458d53f18e'
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
