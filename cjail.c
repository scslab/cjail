
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

#define DEV_CGROUP "/sys/fs/cgroup/devices"

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
  if (!access (DEV_CGROUP "/cjail", 0))
    return 0;

  if (access (DEV_CGROUP "/tasks", 0)) {
    perror (DEV_CGROUP "/tasks");
    return -1;
  }

  if (!access (DEV_CGROUP "/cjail", 0)) {
    fprintf (stderr, "using existing cgroup %s/cjail\n", DEV_CGROUP);
    return 0;
  }

  if (echoTo ("1\n", DEV_CGROUP "/cgroup.clone_children"))
    return -1;
  if (mkdir (DEV_CGROUP "/cjail~", 0755)) {
    perror (DEV_CGROUP "/cjail~");
    return -1;
  }

  if (echoTo ("a\n", DEV_CGROUP "/cjail~/devices.deny")
      || echoTo ("c 1:3 rwm\n", DEV_CGROUP "/cjail~/devices.allow") /* null */
      || echoTo ("c 1:5 rwm\n", DEV_CGROUP "/cjail~/devices.allow") /* zero */
      || echoTo ("c 1:9 rm\n", DEV_CGROUP "/cjail~/devices.allow") /* urandom */
      || echoTo ("c 5:0 rwm\n", DEV_CGROUP "/cjail~/devices.allow") /* tty */
      || echoTo ("c 5:2 rwm\n", DEV_CGROUP "/cjail~/devices.allow") /* ptmx */
      || echoTo ("c 136:* rwm\n", DEV_CGROUP "/cjail~/devices.allow")) /* pts */
    return -1;

  if (rename (DEV_CGROUP "/cjail~", DEV_CGROUP "/cjail")) {
    perror (DEV_CGROUP "/cjail");
    rmdir (DEV_CGROUP "/cjail~");
  }

  return 0;
}

int
entercgroup (void)
{
  char *pid;

  asprintf (&pid, "%d\n", getpid ());
  if (echoTo (pid, DEV_CGROUP "/cjail/tasks")) {
    free (pid);
    return -1;
  }

  free (pid);
  return 0;
}

void
ensure_root (const char *path, int suid)
{
  struct stat sb;
  if (stat (path, &sb)) {
    perror (path);
    exit (1);
  }
  if (sb.st_uid) {
    fprintf (stderr, "%s: must be owned by root\n", path);
    exit (1);
  }
  if (suid) {
    /* suid is kind of a flag saying it's okay to exec it as root; we
     * don't want non-root users running it anyway. */
    if ((sb.st_mode & 07777) != 04500) {
      fprintf (stderr, "%s: must have mode 04500 not 0%o\n", path, sb.st_mode);
      exit (1);
    }
  }
  else {
    if (sb.st_mode & 022) {
      fprintf (stderr, "%s: must not be writeable by group or other\n", path);
      exit (1);
    }
  }
}

int
setup_fs (const char *dir)
{
  seteuid (getuid ());
  if (chdir (dir)) {
    perror (dir);
    seteuid (0);
    return -1;
  }
  seteuid (0);
  ensure_root (".cjail", 0);
  ensure_root ("root", 0);
  ensure_root ("root/init", 1);

  if (mount ("none", "/", "none", MS_REC|MS_PRIVATE, NULL)
      || mount ("root", "readonly", "bind", MS_BIND|MS_REC, NULL)
      || mount ("root", "readonly", "bind",
		MS_BIND|MS_REMOUNT|MS_RDONLY|MS_SLAVE, NULL)) {
    perror ("bind mount");
    return -1;
  }

  if (syscall (SYS_pivot_root, "readonly", "readonly/root/oldroot")) {
    perror ("pivot_root");
    return -1;
  }

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
  fprintf (stderr,
	   "usage: %s [--user user] [--timeout sec] dir program [arg ...]\n"
	   "       %s --init\n", p, p);
  exit (1);
}

pid_t child;
static int killed;

void
sigpass (int signo)
{
  int waskilled = killed;
  killed = 1;
  kill (child, waskilled ? SIGKILL : signo);
  alarm (2);
}

struct state {
  char *dir;
  char **av;
  sigset_t mask;
};

static int
runinit (void *_s)
{
  struct state *s = _s;

  sigprocmask (SIG_SETMASK, &s->mask, NULL);
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
    { "init", no_argument, NULL, 'i'},
    { "timeout", required_argument, NULL, 't'},
    { NULL, 0, 0, 0 }
  };
  int init_only = 0;
  char *dir;
  char *user = NULL;
  char *uid;
  struct passwd *pw;
  char **av;
  int child_status = 0;
  int i;
  int flags = (CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS
	       | CLONE_NEWUTS | CLONE_NEWPID | SIGCHLD);
  static struct state s;
  sigset_t mask;
  struct sigaction sa;
  unsigned timeout = 0;
  char *stack = malloc (0x10000);
  stack += 0x10000;

  while ((opt = getopt_long (argc, argv, "+iu:t:", o, NULL)) != -1)
    switch (opt) {
    case 'i':
      init_only = 1;
      break;
    case 'u':
      user = optarg;
      break;
    case 't':
      timeout = atoi (optarg);
      break;
    default:
      usage (argv[0]);
      break;
    }
  if (init_only) {
    if (optind != argc || user || timeout) {
      fprintf (stderr, "cannot combine --init with other options\n");
      exit (1);
    }
    dir = NULL;
  }
  else {
    if (optind + 2 > argc)
      usage (argv[0]);
    dir = argv[optind];
    optind++;
  }

  if (!getuid ()) {
    mkcgroup ();
    if (init_only)
      return 0;
    if (!user)
      user = "nobody";
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
  }
  else {
    if (user) {
      fprintf (stderr, "can only specify user when running as root\n");
      exit (1);
    }
    if (init_only) {
      fprintf (stderr, "can only specify --init when running as root\n");
      exit (1);
    }
    asprintf (&uid, "%d", getuid ());
  }

  av = malloc ((argc - optind + 3) * sizeof (av[0]));
  av[0] = "init";
  av[1] = uid;
  for (i = 0; i < (argc - optind); i++)
    av[i+2] = argv[i+optind];
  av[i+2] = NULL;

  s.dir = dir;
  s.av = av;
  sigfillset (&mask);
  sigprocmask (SIG_SETMASK, &mask, &s.mask);
  child = clone (runinit, stack, flags, &s);
  if (child < 0) {
    perror ("clone");
    exit (1);
  }

  bzero (&sa, sizeof (sa));
  sa.sa_handler = sigpass;
  sigaction (SIGHUP, &sa, NULL);
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGQUIT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  sigaction (SIGALRM, &sa, NULL);
  if (timeout)
    alarm (timeout);
  sigprocmask (SIG_SETMASK, &s.mask, NULL);

  while (waitpid (-1, &child_status, __WALL) != child)
    ;

  if(WIFEXITED(child_status)) { 
    return WEXITSTATUS(child_status);
  }

  return 0;
}
