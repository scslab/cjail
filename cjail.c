
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
mkcgroup (void)
{
  if (!access ("/cgroup/cjail", 0))
    return 0;

  if (access ("/cgroup/tasks", 0)) {
    mkdir ("/cgroup", 0755);
    if (mount ("cgroup", "/cgroup", "cgroup", 0, NULL)) {
      perror ("/cgroup");
      return -1;
    }
  }

  if (echoTo ("1\n", "/cgroup/cgroup.clone_children"))
    return -1;
  if (mkdir ("/cgroup/cjail~", 0755)) {
    perror ("/cgroup/cjail~");
    return -1;
  }

  if (echoTo ("a\n", "/cgroup/cjail~/devices.deny")
      || echoTo ("c 1:3 rwm\n", "/cgroup/cjail~/devices.allow") /* null */
      || echoTo ("c 1:5 rwm\n", "/cgroup/cjail~/devices.allow") /* zero */
      || echoTo ("c 1:9 rm\n", "/cgroup/cjail~/devices.allow") /* urandom */
      || echoTo ("c 5:0 rwm\n", "/cgroup/cjail~/devices.allow") /* tty */
      || echoTo ("c 5:2 rwm\n", "/cgroup/cjail~/devices.allow") /* ptmx */
      || echoTo ("c 136:* rwm\n", "/cgroup/cjail~/devices.allow")) /* pts */
    return -1;

  if (rename ("/cgroup/cjail~", "/cgroup/cjail")) {
    perror ("/cgroup/cjail");
    rmdir ("/cgroup/cjail~");
  }

  return 0;
}

int
entercgroup (void)
{
  char *pid;

  asprintf (&pid, "%d\n", getpid ());
  if (echoTo (pid, "/cgroup/cjail/tasks")) {
    free (pid);
    return -1;
  }

  free (pid);
  return 0;
}

int
setup_fs (const char *dir)
{
  char *pwd, *rw, *ro, *old;

  pwd = get_current_dir_name ();
  if (!pwd) {
    perror ("getcwd");
    return -1;
  }
  asprintf (&rw, "%s/%s/root", dir[0] == '/' ? "" : pwd, dir);
  asprintf (&ro, "%s/%s/readonly", dir[0] == '/' ? "" : pwd, dir);
  free (pwd);

  if (mount (rw, ro, "bind", MS_BIND|MS_REC, NULL)
      || mount (rw, ro, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_SLAVE, NULL)) {
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

struct state {
  char *dir;
  char **av;
};

static int
runinit (void *_s)
{
  struct state *s = _s;

  if (entercgroup ())
    _exit (1);
  if (setup_fs (s->dir))
    _exit (1);

  execv ("/init", s->av);
  perror ("/init");
  _exit (1);
}

int
main (int argc, char **argv)
{
  int opt;
  struct option o[] = {
    { "user", required_argument, NULL, 'u'},
    { NULL, 0, 0, 0 }
  };
  char *dir;
  char *user = "nobody";
  char *uid;
  struct passwd *pw;
  char **av;
  int i;
  int flags = (CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS
	       | CLONE_NEWUTS | CLONE_NEWPID | SIGCHLD);
  static struct state s;
  char *stack = malloc (0x10000);
  stack += 0x10000;

  while ((opt = getopt_long (argc, argv, "+u:", o, NULL)) != -1)
    switch (opt) {
    case 'u':
      user = optarg;
      break;
    default:
      usage (argv[0]);
      break;
    }
  if (optind + 2 > argc)
    usage (argv[0]);
  dir = argv[optind];
  optind++;

  mkcgroup ();

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

  av = malloc ((argc - optind + 3) * sizeof (av[0]));
  av[0] = "init";
  av[1] = uid;
  for (i = 0; i < (argc - optind); i++)
    av[i+2] = argv[i+optind];
  av[i+2] = NULL;

  s.dir = dir;
  s.av = av;
  i = clone (runinit, stack, flags, &s);
  if (i < 0) {
    perror ("clone");
    exit (1);
  }
  waitpid (-1, NULL, __WALL);
  return 0;
}
