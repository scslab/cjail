
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <libmount/libmount.h>

struct runstate {
  int fd;
  uid_t uid;
};

static int
runit (void *_rs)
{
  struct runstate *rs = _rs;

  if (mount ("proc", "/proc", "proc", 0, NULL)
      || mount ("tmp", "/tmp", "tmpfs", 0, NULL)
      || mount ("dev", "/dev", "devtmpfs", 0, NULL)) {
    perror ("mount");
    exit (1);
  }

  if (setuid (rs->uid)) {
    perror ("setuid");
    exit (1);
  }

  dup2 (rs->fd, 0);
  dup2 (rs->fd, 1);
  if (rs->fd > 1)
    close (rs->fd);

  execl ("/bin/bash", "/bin/bash", NULL);
  perror ("/bin/bash");
  exit (1);
}

void
accept_loop (int lfd, uid_t uid)
{
  int flags = (CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS
	       | CLONE_NEWUTS | CLONE_NEWPID);

  for (;;) {
    struct sockaddr_un sun;
    socklen_t sunlen = sizeof (sun);
    int fd;
    static struct runstate rs;
    long stack;

    memset (&sun, 0, sizeof (sun));
    fd = accept (lfd, (struct sockaddr *) &sun, &sunlen);
    rs.fd = fd;
    rs.uid = uid;
    clone (runit, &stack, flags, &rs);
    close (fd);
  }
}

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

  err = mount ("proc", "/proc", "proc", 0, NULL);
  mps = getmounts ("/root/oldroot");
  if (!err)
    umount ("/proc");
  err = 0;

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
echoTo (const char *contents, const char *file)
{
  int fd;
  if ((fd = open (file, O_WRONLY)) == -1) {
    perror (file);
    return -1;
  }
  if (write (fd, contents, strlen (contents)) == -1) {
    perror (file);
    close (fd);
    return -1;
  }
  close (fd);
  return 0;
}

int
entercgroup (void)
{
  char *pid;

  if (access ("/cgroup/tasks", 0)) {
    mkdir ("/cgroup", 0755);
    if (mount ("cgroup", "/cgroup", "cgroup", 0, NULL)) {
      perror ("/cgroup");
      return -1;
    }
  }

  if (echoTo ("1\n", "/cgroup/cgroup.clone_children"))
    return -1;
  mkdir ("/cgroup/nodev", 0755);
  asprintf (&pid, "%d\n", getpid ());
  if (echoTo ("a\n", "/cgroup/nodev/devices.deny")
      || echoTo ("c 1:3 rwm\n", "/cgroup/nodev/devices.allow") /* null */
      || echoTo ("c 1:5 rwm\n", "/cgroup/nodev/devices.allow") /* zero */
      || echoTo ("c 1:9 rm\n", "/cgroup/nodev/devices.allow") /* urandom */
      || echoTo ("c 5:0 rwm\n", "/cgroup/nodev/devices.allow") /* tty */
      || echoTo ("c 5:2 rwm\n", "/cgroup/nodev/devices.allow") /* ptms */
      || echoTo ("c 136:* rwm\n", "/cgroup/nodev/devices.allow") /* pts */
      || echoTo (pid, "/cgroup/nodev/tasks")) {
    free (pid);
    return -1;
  }

  free (pid);
  return 0;
}

static int
copy_self (const char *target)
{
  int in, out;
  char buf[8192];
  int n;

  in = open ("/proc/self/exe", O_RDONLY);
  if (in < 0) {
    perror ("/proc/self/exe");
    return -1;
  }

  unlink (target);
  out = open (target, O_CREAT|O_WRONLY, 0500);
  if (out < 0) {
    perror (target);
    close (in);
    return -1;
  }

  while ((n = read (in, buf, sizeof (buf))) > 0)
    if (write (out, buf, n) != n) {
      perror (target);
      close (in);
      close (out);
      return -1;
    }

  if (n < 0)
    perror ("/proc/self/exe");
  close (in);
  close (out);
  return n >= 0 ? 0 : -1;
}

int
setup_fs (const char *dir)
{
  char *pwd, *rw, *ro, *old, *init;

  if (unshare (CLONE_FS|CLONE_NEWNS)) {
    perror ("unshare");
    return -1;
  }

  pwd = get_current_dir_name ();
  if (!pwd) {
    perror ("getcwd");
    return -1;
  }
  asprintf (&rw, "%s/%s/root", dir[0] == '/' ? "" : pwd, dir);
  asprintf (&ro, "%s/%s/readonly", dir[0] == '/' ? "" : pwd, dir);
  free (pwd);

  asprintf (&init, "%s/init", rw);
  if (copy_self (init)) {
    free (init);
    free (rw);
    free (ro);
    return -1;
  }
  free (init);

  if (mount (rw, ro, "bind", MS_BIND|MS_REC, NULL)
      || mount (rw, ro, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY
		/*|MS_SLAVE*/, NULL)) {
    perror ("bind mount");
    free (rw);
    free (ro);
    return -1;
  }

  free (rw);
  asprintf (&old, "%s/root/oldroot", ro);

  if (syscall (SYS_pivot_root, ro, old)) {
    fprintf (stderr, "pivot_root (%s, %s): %s\n", ro, old, strerror (errno));
    perror ("pivot_root");
    free (ro);
    free (old);
    return -1;
  }
  free (ro);
  free (old);

  return chdir ("/");
}

int
mksock (char *dir)
{
  struct sockaddr_un sun;
  int s;

  memset (&sun, 0, sizeof (sun));
  sun.sun_family = AF_UNIX;
  if (snprintf (sun.sun_path, sizeof (sun.sun_path), "%s/control", dir)
      >= sizeof (sun.sun_path)) {
    fprintf (stderr, "%s: path too long\n", dir);
    return -1;
  }

  if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror ("socket");
    return -1;
  }
  unlink (sun.sun_path);
  if (bind (s, (struct sockaddr *) &sun, sizeof (sun))
      || listen (s, 5)) {
    perror (sun.sun_path);
    close (s);
    return -1;
  }
  return s;
}

void
usage (char *argv0)
{
  const char *p;
  if ((p = strrchr (argv0, '\n')))
    p++;
  else
    p = argv0;
  fprintf (stderr, "usage: %s [--user user] dir\n", p);
  exit (1);
}

int
main (int argc, char **argv)
{
  if (strcmp (argv[0], "init")) {
    int opt;
    struct option o[] = {
      { "user", required_argument, NULL, 'u'},
      { NULL, 0, 0, 0 }
    };
    char *dir;
    char *user = "nobody";
    struct passwd *pw;
    int ls;
    char *uid;

    while ((opt = getopt_long (argc, argv, "+u:", o, NULL)) != -1)
      switch (opt) {
      case 'u':
	user = optarg;
	break;
      default:
	usage (argv[0]);
	break;
      }
    if (optind + 1 != argc)
      usage (argv[0]);
    dir = argv[optind];

    if (!(pw = getpwnam (user))) {
      fprintf (stderr, "%s: no such user\n", user);
      exit (1);
    }
    if (setgid (pw->pw_gid)) {
      perror ("setgid");
      exit (1);
    }
    asprintf (&uid, "%d", pw->pw_uid);
    if (initgroups (user, pw->pw_gid)) {
      fprintf (stderr, "initgroups (%s) failed\n", user);
      exit (1);
    }

    ls = mksock (dir);
    if (ls < 0)
      exit (1);
    if (ls != 3) {
      dup2 (ls, 3);
      close (ls);
    }

    if (entercgroup ())
      exit (1);
    if (setup_fs (dir))
      exit (1);

    execl ("/init", "init", uid, NULL);
    perror ("/init");
    return -1;
  }
  else {
    /* We must re-exec ourselves to free up the mountpoint.  Execution
     * then continues here, and now we can unmount all the old file
     * systems. */
    uid_t uid;

    if (argc != 2) {
      fprintf (stderr, "do not invoke this program as init\n");
      exit (1);
    }
    uid = atoi (argv[1]);

    if (fcntl (3, F_SETFD, 1)) {
      fprintf (stderr, "error: file descriptor 3 should be listening socket\n");
      exit (1);
    }
    if (unmountold ())
      exit (1);

    accept_loop (3, uid);
#if 0
    if (setuid (uid)) {
      perror ("setuid");
      exit (1);
    }
    execl ("/bin/bash", "bashubashu", NULL);
    perror ("/bin/bash");
#endif
  }

  exit (0);
}

