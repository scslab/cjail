
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>
#include <libmount/libmount.h>

static int
revcmp (const void *_a, const void *_b)
{
  const char *const *a = _a, *const *b = _b;
  return strcmp (*b, *a);
}

char **
getmounts (const char *dir)
{
  int dirlen = strlen (dir);
  char **out = NULL;
  int outlen = 0;
  struct libmnt_table *tb;
  struct libmnt_iter *itr;
  struct libmnt_fs *fs = NULL;

  while (dirlen && dir[dirlen-1] == '/')
    dirlen--;

  tb = mnt_new_table ();
  if (mnt_table_parse_file (tb, "/proc/self/mountinfo")) {
    fprintf (stderr, "can't parse mountinfo\n");
    mnt_free_table (tb);
    return NULL;
  }

  itr = mnt_new_iter (MNT_ITER_BACKWARD);
  if (!itr) {
    fprintf (stderr, "mnt_new_iter failed\n");
    mnt_free_table (tb);
    return NULL;
  }

  while(mnt_table_next_fs (tb, itr, &fs) == 0) {
    const char *target = mnt_fs_get_target (fs);
    if (strncmp (target, dir, dirlen)
	|| (target[dirlen] != '/' && target[dirlen] != '\0'))
      continue;
    if (!(out = realloc (out, (outlen + 1) * sizeof (out[0])))
	|| !(out[outlen] = strdup (target))) {
      fprintf (stderr, "malloc failed\n");
      exit (1);
    }
    outlen++;
  }

  if (!(out = realloc (out, (outlen + 1) * sizeof (out[0])))) {
    fprintf (stderr, "malloc failed\n");
    exit (1);
  }
  out[outlen] = NULL;

  qsort (out, outlen, sizeof (out[0]), revcmp);

  mnt_free_iter (itr);
  mnt_free_table (tb);
  return out;
}

int
unmountold (void)
{
  char **mps, **mp;
  int err = 0;

  mps = getmounts ("/root/oldroot");
  if (!mps)
    return -1;

  for (mp = mps; *mp; mp++) {
    if (!err && (err = umount (*mp)))
      perror (*mp);
    free (*mp);
  }
  free (mps);

  return err;
}

int
main (int argc, char **argv)
{
  uid_t uid;
  char **av;
  int i;

  if (getpid () != 1) {
    fprintf (stderr, "%s: I should have PID 1\n", argv[0]);
    exit (1);
  }

  if (argc < 3) {
    fprintf (stderr, "usage: %s uid prog [arg ...]\n", argv[0]);
    exit (1);
  }
  uid = atoi (argv[1]);
  av = malloc ((argc - 1) * sizeof (av[0]));
  for (i = 2; i < argc; i++)
    av[i-2] = argv[i];
  av[i-2] = NULL;

  mount ("proc", "/proc", "proc", 0, NULL);
  mount ("tmp", "/tmp", "tmpfs", 0, NULL);
  unmountold ();
  if (setuid (uid)) {
    perror ("setuid");
    exit (1);
  }
  execvp (av[0], av);
  perror (av[0]);
  exit (1);
}
