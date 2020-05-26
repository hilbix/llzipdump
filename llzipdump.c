#include <stdio.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#if 1
#define	D(S,...)	do { fprintf(stderr, "[[%s:%d %s" S "]]\n", __FILE__, __LINE__, __func__, __VA_ARGS__); } while (0)
#else
#define	D(...)
#endif

struct zipdump
{
FILE	*fd;
unsigned	part;
int		nr;
int		dirt;
    const char	*name;
  };

static void
OOPS(const char *s, ...)
{
  va_list	list;
  int		e = errno;

  fprintf(stderr, "OOPS: ");
  va_start(list, s);
  vfprintf(stderr, s, list);
  va_end(list);
  if (e)
    fprintf(stderr, ": %s", strerror(e));
  fprintf(stderr, "\n");
  exit(23);
}

static void
zipdump(struct zipdump *inf)
{
}

static void
zipdumpf(struct zipdump *inf, const char *name)
{
if (!strcmp(name, "-"))
    {
      inf->fd	= stdin;
      inf->name	= "(stdin)";
    }
  else if ((inf->fd = fopen(inf->name=name, "rb"))==0)
    OOPS("%s: cannot open", name);
  zipdump(inf);
  if (inf->fd != stdin)
    if (ferror(inf->fd) || fclose(inf->fd))
      OOPS("%s: close error", name);
}

static int
usage(const char *arg0)
{
  const char *tmp;

  tmp	= strrchr(arg0, '/');
  if (tmp)
    arg0	= tmp+1;
  fprintf(stderr, "# Usage: %s -- files..\n\toutput (possibly hidden) information about the given ZIP files\n", arg0);
  fprintf(stderr, "# Usage: %s -N files.. > part\n\textract the Nth part (0 is what starts the file)\n", arg0);
  return 42;
}

static unsigned
getunsigned(const char *s)
{
  char		*end;
  unsigned long	ul;
  unsigned	u;

  ul	= strtoul(s, &end, 10);
  if (!end || *end || !*s)
    OOPS("please give unsigned number");
  u	= (unsigned)ul;
  if ((unsigned long)u != ul)
    OOPS("number out of range");
  return u;
}

int
main(int argc, char **argv)
{
  struct zipdump	inf = {0};
  int			i;

  inf.part	= -1;
  i		= 1;
  if (i<argc && argv[i][0]=='-' && argv[i][1]!='-' && argv[i][1])
    inf.part	= getunsigned(argv[i++]+1)+1;
  if (i<argc && !strcmp(argv[i], "--"))
    i++;
  if (i>=argc)
    return usage(argv[0]);
  while (i<argc)
    zipdumpf(&inf, argv[i++]);
  return inf.dirt;
}

