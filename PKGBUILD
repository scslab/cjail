pkgname=cjail
pkgver=0
pkgrel=0
pkgdesc="cgroups-based jail tools"
arch=(i686 x86_64)
license=('GPL')
install=
source=(Makefile cjail.c mkcjail cjail-init.c README)

build() {
  cd "$srcdir"
  make
}

package() {
  cd "$srcdir"
  install -Dm4755 cjail "$pkgdir"/usr/bin/cjail
  install -Dm744 mkcjail "$pkgdir"/usr/sbin/mkcjail
  install -Dm755 cjail-init "$pkgdir"/usr/lib/cjail/init
  install -Dm755 README "$pkgdir"/usr/share/doc/cjail/README
}
