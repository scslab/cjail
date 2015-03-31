pkgname=cjail
pkgver=0
pkgrel=0
pkgdesc="cgroups-based jail tools"
arch=(i686 x86_64)
license=('GPL')
install=
source=(Makefile cjail.c mkcjail cjail-init.c README.md)
md5sums=('80fd0270aba486af4934ad8772657782'
         'e658af3e85735d026659ed4bd00eefb2'
         '83f9a9caa3208299c79978eb99dd280b'
         '048731930ce167bd6857e87fe1ccc271'
         '7358f9439733feb24fe586c598ae5e38')

build() {
  cd "$srcdir"
  make
}

package() {
  cd "$srcdir"
  install -Dm4755 cjail "$pkgdir"/usr/bin/cjail
  install -Dm744 mkcjail "$pkgdir"/usr/bin/mkcjail
  install -Dm755 cjail-init "$pkgdir"/usr/lib/cjail/init
  install -Dm755 README.md "$pkgdir"/usr/share/doc/cjail/README.md
}
