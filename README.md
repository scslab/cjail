# About

cjail is a sandbox utility for Arch Linux

# Installation:

Install the cjail tool with:

```
git clone https://github.com/scslab/cjail
cd cjail
make install
```

and, optionally, the Haskell bindings:

```
cd cjail-haskell
cabal install
```





# Setup

Create a configuration file defining the packages you want installed.
There are two arrays, PACKAGES and AUR for packages from the two
different places.  For example:

```
cat > cjail.conf <<EOF
PACKAGES=(python)
AUR=(rails)
EOF
```

(These packages are in addition to the base and base-devel packages,
which are installed by default.)  Now, as root, cd someplace with
plenty of free disk space and create a jail:

```
mkcjail -c cjail.conf jail
```

If you want to add any more files, add them to jail/root.  If you want
to add more packages, you can just edit cjail.conf and run it again on
the same directory.  It's much faster if most of the packages are
already installed.

# Use

To run something in the jail, just run it with the cjail wrapper and
specify the path to the jail.  For example:

```
cjail jail bash
```

Only the /tmp directory will be writable, there will be no network
access, and there will be no communication between different cjail
instances (i.e., you can run cjail twice concurrently on the same jail
and the processes will not see the same /tmp file system, only the
same root which is not writable anyway).

You can also put a time limit in seconds on the jailed process (and
all subprocesses) with the -t option:

```
cjail -t 30 jail bash
```

(You may need to run "stty sane" afterwards, as bash does not die in a
friendly way.)

# Tuning

cjail sets up a cgroup in /cgroup/cjail.  It doesn't currently limit
any resources except for device access, but this could easily be
further customized.  If you create the group on bootup, cjail will not
modify the parameters, so make sure you disable most device access.
