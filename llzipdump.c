#include <stdio.h>

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if 1
#define	D(S,...)	do { fprintf(stderr, "[[%s:%d %s" S "]]\n", __FILE__, __LINE__, __func__, __VA_ARGS__); } while (0)
#else
#define	D(...)
#endif

#define	ZIP		struct zipdump *Z
#define	HEXWIDTH	16

enum zipartype
  {
    ZIP_EOF,
    ZIP_GARBAGE,
    ZIP_FILE,
    ZIP_NAME,
    ZIP_EXTRA,
    ZIP_DATA,
    ZIP_DESC,
    ZIP_DIR,
    ZIP_COMMENT,
    ZIP_END,
  };

static const char *zipartypes[] =
  { "Unexpected EOF"
  , "Garbage"
  , "File Header"
  , "File Name"
  , "File Extra"
  , "File Data"
  , "File Descriptor"
  , "Dir Entry"
  , "File Comment"
  , "ZIP End"
  };

typedef struct zipart
  {
    enum zipartype	type;
    unsigned		nr;
    unsigned long long	start;
    unsigned long long	len;
    int			gather;
    unsigned long long	gatherpos;
    unsigned		gatherlen;
    unsigned char	gatherbuf[HEXWIDTH];
  } *ZIPART;

typedef	uint32_t	Zoff;

struct zipdump
  {
    FILE	*fd;
    unsigned	part;
    const char	*name;

    int		nr;
    int		dirt;

    ZIPART	zip, current;

    unsigned long long	offset;
    Zoff		pos, fill;
    char		buf[65536+1];
  };

#define	Z_len	(Z->fill - Z->pos)

#define	FATAL(X)	do { if (X) { fprintf(stderr, "%s:%d: FATAL ERROR in function %s: %s\n", __FILE__, __LINE__, __func__, #X); fflush(stderr); exit(23); } } while (0)
#define	NOTYET		FATAL("not yet implemented")

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

static void *
alloc(void *ptr, size_t len)
{
  ptr	= realloc(ptr, len);
  if (!ptr)
    OOPS("out of memory");
  return ptr;
}

static void *
alloc0(size_t len)
{
  void	*ptr;

  ptr	= alloc(NULL, len);
  memset(ptr, 0, len);
  return ptr;
}

static uint16_t
Z_16(const unsigned char *tmp)
{
  return ((uint16_t)tmp[1])<< 8
       | ((uint16_t)tmp[0])<< 0
       ;
}

static uint32_t
Z_32(const unsigned char *tmp)
{
  return ((uint32_t)tmp[3])<<24
       | ((uint32_t)tmp[2])<<16
       | ((uint32_t)tmp[1])<< 8
       | ((uint32_t)tmp[0])<< 0
       ;
}

/* 4.4.5 https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.2.0.txt */
static const char *
Z_meth(int meth)
{
  switch (meth)
    {
    case 0:	return "Store";
    case 1:	return "LZW(Shrunk)";
    case 2:	return "Reduced1";
    case 3:	return "Reduced2";
    case 4:	return "Reduced3";
    case 5:	return "Reduced4";
    case 6:	return "Implode";
    case 7:	return "Tokened";
    case 8:	return "Deflate";
    case 9:	return "Deflate64";
    case 10:	return "PKimpode";
    case 11:	return "Reserved";
    case 12:	return "BZIP2";
    case 13:	return "Reserved";
    case 14:	return "LZMA";
    case 15:	return "Reserved";
    case 16:	return "IBM-CMPSC";
    case 17:	return "Reserved";
    case 18:	return "IBM-TERSE";
    case 19:	return "IBM-LZ77";
    case 20:	return "Zstd";
    case 96:	return "JPEG";
    case 97:	return "WavPack";
    case 98:	return "PPMd";
    case 99:	return "AE-x(enc)";
    default:	return "(unknown)";
    }
}

/* https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.2.0.txt */
static const char *
Z_id(int id)
{
  switch (id)
    {
    default:		return "(unknown)";
    case 0x0001:	return "Zip64";
    case 0x0007:	return "AV Info";
    case 0x0008:	return "Reserved(PFS)";
    case 0x0009:	return "OS/2";
    case 0x000a:	return "NTFS";
    case 0x000c:	return "OpenVMS";
    case 0x000d:	return "UNIX";
    case 0x000e:	return "Reserved(stream)";
    case 0x000f:	return "Patch Descriptor";
    case 0x0014:	return "PKCS#7 Store";
    case 0x0015:	return "X.509 Cert(File)";
    case 0x0016:	return "X.509 Cert(Dir)";
    case 0x0017:	return "Encryption-Header";
    case 0x0018:	return "Record Management Controls";
    case 0x0019:	return "PKCS#7 Cert List";
    case 0x0020:	return "Reserved(Timestamp)";
    case 0x0021:	return "Policy Decryption Key";
    case 0x0022:	return "Smartcrypt Key";
    case 0x0023:	return "Smartcrypt Policy Key";
    case 0x0065:	return "IBM attributes (uncompressed)";
    case 0x0066:	return "IBM attributes (compressed)";
    case 0x07c8:	return "Mac";
    case 0x2605:	return "ZipIt Mac";
    case 0x2705:	return "ZipIt Mac 1.3.5+ (A)";
    case 0x2805:	return "ZipIt Mac 1.3.5+ (B)";
    case 0x334d:	return "Info-Zip Mac";
    case 0x4690:	return "POSZIP";
    case 0x4341:	return "Acorn/SparkFS";
    case 0x4453:	return "Windows NT security descriptor (binary ACL)";
    case 0x4704:	return "VM/CMS";
    case 0x470f:	return "MVS";
    case 0x4b46:	return "FWKCS MD5 (see below)";
    case 0x4c41:	return "OS/2 access control list (text ACL)";
    case 0x4d49:	return "Info-ZIP OpenVMS";
    case 0x4f4c:	return "Xceed original location extra field";
    case 0x5356:	return "AOS/VS (ACL)";
    case 0x5455:	return "extended timestamp";
    case 0x554e:	return "Xceed unicode extra field";
    case 0x5855:	return "Info-ZIP UNIX (original, also OS/2, NT, etc)";
    case 0x6375:	return "Info-ZIP Unicode Comment Extra Field";
    case 0x6542:	return "BeOS/BeBox";
    case 0x7075:	return "Info-ZIP Unicode Path Extra Field";
    case 0x756e:	return "ASi UNIX";
    case 0x7855:	return "Info-ZIP UNIX (new)";
    case 0x9901:	return "AE-x encryption structure";
    case 0x9902:	return "3rd Party unknown";
    case 0xa11e:	return "Data Stream Alignment (Apache Commons-Compress)";
    case 0xa220:	return "Microsoft Open Packaging Growth Hint";
    case 0xfd4a:	return "SMS/QDOS";
    }
}

/* https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.2.0.txt */
static const char *
Z_ver(int nr)
{
  static char *types[] =
    { "FAT"
    , "Amiga"
    , "OpenVMS"
    , "Unix"
    , "VM/CMS"
    , "Atari ST"
    , "OS/2 H.P.F.S."
    , "Mac"
    , "Z-System"
    , "CP/M"
    , "NTFS"
    , "MVS 1"
    , "VSE"
    , "Arcorn Risc"
    , "VFAT"
    , "MVS 2"
    , "BeOS"
    , "Tandem"
    , "OS/400"
    , "OS/X"
    };
  return (nr>=0 && nr<(sizeof types/sizeof *types)) ? types[nr] : "(unknown)";
}

static const char *
Z_partype(enum zipartype nr)
{
  return (nr>=0 && nr<(sizeof zipartypes/sizeof *zipartypes)) ? zipartypes[nr] : "(unknown)";
}

static void
vsend(ZIP, const char *s, va_list list)
{
  FILE	*fd	= Z->part ? stderr : stdout;
  if (s)
    vfprintf(fd, s, list);
  else
    fflush(fd);
}

static void
send(ZIP, const char *s, ...)
{
  va_list	list;

  va_start(list, s);
  vsend(Z, s, list);
  va_end(list);
}

static void
out(ZIP, ZIPART p, const char *s, const char *d, ...)
{
  va_list	list;
  send(Z, "zipdump %s part %d", Z->name, p ? p->nr : 0);
  if (s)
    send(Z, "%-20s", s);
  else
    send(Z, " ");
  va_start(list, d);
  vsend(Z, d, list);
  va_end(list);
  send(Z, "\n");
  send(Z, NULL);
}

static void
hexdump(ZIP, unsigned long long off, const unsigned char *ptr, int i)
{
  int	j;

  FATAL(i>HEXWIDTH);

  send(Z, ":%08llx:", off);
  for (j=0; j<i; j++)
    send(Z, " %02x", ptr[j]);
  while (++j<=HEXWIDTH)
    send(Z, "   ");
  send(Z, "  ! ");
  for (j=0; j<i; j++)
    send(Z, "%c", ptr[j]>=32 && ptr[j]<127 ? ptr[j] : '.');
  send(Z, "\n");
}

static void
zipgather(ZIP)
{
  if (!Z->current->gather || !Z->current->gatherlen)
    return;
  hexdump(Z, Z->current->gatherpos, Z->current->gatherbuf, Z->current->gatherlen);
  Z->current->gatherlen	= 0;
}

static void
zipok(ZIP, Zoff n)
{
  FATAL(!Z->current);
  FATAL(Z->current->start + Z->current->len != Z->offset);

  if (Z->current->gather)
    while (n)
      {
        int max;

        if (Z->current->gatherlen >= sizeof Z->current->gatherbuf ||
            (Z->current->gatherlen &&
             Z->current->gatherpos + Z->current->gatherlen != Z->offset))
          zipgather(Z);
        if (!Z->current->gatherlen)
          Z->current->gatherpos	= Z->offset;
        FATAL(Z->current->gatherlen<0 || Z->current->gatherlen>=sizeof Z->current->gatherbuf);
        max	= sizeof Z->current->gatherbuf - Z->current->gatherlen;
        if (n<max)
          max	= n;
        FATAL(max<=0 || max>sizeof Z->current->gatherbuf);
        memcpy(Z->current->gatherbuf + Z->current->gatherlen, Z->buf + Z->pos, max);
        Z->current->gatherlen	+= max;
        Z->current->len		+= max;
        Z->offset		+= max;
        Z->pos			+= max;
        n			-= max;
      }
  Z->current->len	+= n;
  Z->offset		+= n;
  Z->pos		+= n;
  FATAL(Z->pos > Z->fill);
}

static int
zipfill(ZIP, Zoff n)
{
  if (Z->pos >= Z->fill)
    {
      Z->fill	= 0;
      Z->pos	= 0;
    }
  if (Z->pos + n >= sizeof Z->buf)
    {
      memmove(Z->buf, Z->buf + Z->pos, Z_len);
      Z->fill	-= Z->pos;
      Z->pos	= 0;
    }
  for (;;)
    {
      int	got;

      FATAL(Z->fill >= sizeof Z->buf);
      /* we always leave 1 byte free at the end
       * NUL it, just in case
       */
      Z->buf[Z->fill]	= 0;
      if (Z->fill - Z->pos >= n)
        return 1;
      if (feof(Z->fd))
        return 0;
      got	= fread(Z->buf + Z->fill, sizeof *Z->buf, (sizeof Z->buf)-1-Z->fill, Z->fd);
      if (ferror(Z->fd))
        OOPS("%s: read error", Z->name);
      if (!got)
        return 0;
      Z->fill	+= got;
    }

}

static void
zipart(ZIP, enum zipartype type)
{
  if (Z->current)
    {
      if (Z->current->type == type &&
          Z->current->start + Z->current->len == Z->offset)
        return;
      zipgather(Z);
      free(Z->current);
    }
  Z->current		= alloc0(sizeof *Z->current);
  Z->current->nr	= ++Z->nr;
  Z->current->type	= type;
  Z->current->start	= Z->offset;
  out(Z, Z->current, NULL, "%s", Z_partype(type));
  out(Z, Z->current, ": offset", "0x%llx (%llu)", Z->offset, Z->offset);
}

static void
zipgarbage(ZIP, int nr)
{
  zipart(Z, ZIP_GARBAGE);
  Z->current->gather	= 1;
  Z->dirt		= 1;
  zipok(Z, nr);
}

static const unsigned char *
zipeek(ZIP, int n)
{
  FATAL(Z_len < n);
  return (unsigned char *)Z->buf + Z->pos;
}

static const unsigned char *
zipget(ZIP, int n)
{
  const unsigned char *ptr;

  ptr	= zipeek(Z, n);
  zipok(Z, n);
  return ptr;
}

#if 0
static uint32_t zipeek16(ZIP)	{ return Z_16(zipeek(Z, 2)); }
#endif
static uint32_t zipget16(ZIP)	{ return Z_16(zipget(Z, 2)); }
static uint32_t zipeek32(ZIP)	{ return Z_32(zipeek(Z, 4)); }
static uint32_t zipget32(ZIP)	{ return Z_32(zipget(Z, 4)); }

static void
ziphexdump(ZIP, enum zipartype type, Zoff n)
{
  FATAL(Z_len < n);
  zipart(Z, type);
  while (n)
    {
      unsigned long long	o;
      int			i;

      i	= HEXWIDTH;
      if (n<i)
        i	= n;
      n		-= i;
      o		= Z->offset;
      hexdump(Z, o, zipget(Z, i), i);
    }
}

static void
zipeof(ZIP)
{
  zipart(Z, ZIP_EOF);
  if (Z_len)
    ziphexdump(Z, ZIP_EOF, Z_len);
}

static void
zipskip(ZIP, enum zipartype type, Zoff len)
{
  zipart(Z, type);
  out(Z, Z->current, ": size", "%llu (0x%llx)", (unsigned long long)len, (unsigned long long)len);
  while (len)
    {
      Zoff	n;

      n	= len<65536 ? len : 65536;
      if (!zipfill(Z, n))
        {
          zipok(Z, Z_len);
          return zipeof(Z);
        }
      zipok(Z, n);
      len	-= n;
    }
}

static void
ziphex(ZIP, enum zipartype type, Zoff n)
{
  if (!n)
    return;
  if (!zipfill(Z, n))
    zipeof(Z);
  else
    ziphexdump(Z, type, n);
}

static void
zipextra(ZIP, Zoff n)
{
  unsigned long long end;

  if (!zipfill(Z, n))
    return zipeof(Z);
  zipart(Z, ZIP_EXTRA);
  end	= Z->offset + n;
  while (Z->offset < end)
    {
      uint32_t	id, len;

      if (Z->offset + 4 > end)
        break;
      id	= zipget16(Z);
      len	= zipget16(Z);
      if (Z->offset + len > end)
        break;
      out(Z, Z->current, ": extra",	"0x%04x (%s)", id, Z_id(id));
      out(Z, Z->current, ": len",	"%d (0x%04x)", len, len);
      ziphexdump(Z, ZIP_EXTRA, len);
    }
  if (Z->offset < end)
    ziphexdump(Z, ZIP_EXTRA, end-Z->offset);
}

static void
zipdesc(ZIP, uint32_t crc1, uint32_t len1, uint32_t real1)
{
  uint32_t	sig2, crc2, len2, real2;

  if (!zipfill(Z, 16))
    return zipeof(Z);

  zipart(Z, ZIP_DESC);
  sig2	= zipget32(Z);
  crc2	= sig2 == 0x08074b50 ? zipget32(Z) : sig2;	/* WTF?	*/
  len2	= zipget32(Z);
  real2	= zipget32(Z);
  out(Z, Z->current, ": sig",		"%08lx", (unsigned long)sig2);
  out(Z, Z->current, ": crc32",		"0x%08x", (unsigned long)crc2);
  out(Z, Z->current, ": compressed",	"%lu (0x%08lx)", (unsigned long)len2, (unsigned long) len2);
  out(Z, Z->current, ": uncompressed",	"%lu (0x%08lx)", (unsigned long)real2, (unsigned long)real2);
}

/* 4.4.4 https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.2.0.txt
 * Flag bits:
 * 0	Encryption
 * 1+2	Compression type, used for Method 6, 8, 9, 14
 * 3	ZIP_DESC present
 * 4	(reserved)
 * 5	Compressed Patch data
 * 6	Strong Encryption
 * 7-a	(unused)
 * b	UTF-8
 * c	(reserved)
 * d	Central Directory Encryption
 * e	(reserved)
 * f	(reserved)
 */
static void
zipfile(ZIP)
{
  uint32_t	sig1, crc1, len1, real1;
  uint16_t	ver, flag, meth, time, date, name, extra;

  if (!zipfill(Z, 30))
    return zipgarbage(Z, 4);

  zipart(Z, ZIP_FILE);

  sig1	= zipget32(Z);
  ver	= zipget16(Z);
  flag	= zipget16(Z);
  meth	= zipget16(Z);
  time	= zipget16(Z);
  date	= zipget16(Z);
  crc1	= zipget32(Z);
  len1	= zipget32(Z);
  real1	= zipget32(Z);
  name	= zipget16(Z);
  extra	= zipget16(Z);

  out(Z, Z->current, ": sig",		"%08lx", (unsigned long)sig1);
  out(Z, Z->current, ": ver",		"%d (%s)", ver, Z_ver(ver));
  out(Z, Z->current, ": flag",		"0x%04x", flag);
  out(Z, Z->current, ": meth",		"0x%04x (%s)", meth, Z_meth(meth));
  out(Z, Z->current, ": date/time",	"%04x %04x", date, time);
  out(Z, Z->current, ": crc32",		"0x%08x", (unsigned long)crc1);
  out(Z, Z->current, ": compressed",	"%lu (0x%08lx)", (unsigned long)len1, (unsigned long) len1);
  out(Z, Z->current, ": uncompressed",	"%lu (0x%08lx)", (unsigned long)real1, (unsigned long)real1);
  out(Z, Z->current, ": name-len",	"%d", name);
  out(Z, Z->current, ": extra-len",	"%d", extra);

  ziphex(Z, ZIP_NAME, name);
  if (extra)
    zipextra(Z, extra);
  zipskip(Z, ZIP_DATA, len1);

  if (flag & 0x0008)
    zipdesc(Z, crc1, len1, real1);
}

static void
zipdir(ZIP)
{
  uint32_t	sig, crc, len, real, attre, offs;
  uint16_t	made, minv, flag, meth, time, date, name, extra, comt, disk, attri;

  if (!zipfill(Z, 46))
    return zipeof(Z);

  zipart(Z, ZIP_DIR);

  sig	= zipget32(Z);
  made	= zipget16(Z);
  minv	= zipget16(Z);
  flag	= zipget16(Z);
  meth	= zipget16(Z);
  time	= zipget16(Z);
  date	= zipget16(Z);
  crc	= zipget32(Z);
  len	= zipget32(Z);
  real	= zipget32(Z);
  name	= zipget16(Z);
  extra	= zipget16(Z);
  comt	= zipget16(Z);
  disk	= zipget16(Z);
  attri	= zipget16(Z);
  attre	= zipget32(Z);
  offs	= zipget32(Z);

  out(Z, Z->current, ": sig",		"%08lx", (unsigned long)sig);
  out(Z, Z->current, ": made",		"%d (%s)", made, Z_ver(made));
  out(Z, Z->current, ": minver",	"%d (%s)", minv, Z_ver(minv));
  out(Z, Z->current, ": flag",		"0x%04x", flag);
  out(Z, Z->current, ": meth",		"0x%04x (%s)", meth, Z_meth(meth));
  out(Z, Z->current, ": date/time",	"%04x %04x", date, time);
  out(Z, Z->current, ": crc32",		"0x%08x", (unsigned long)crc);
  out(Z, Z->current, ": compressed",	"%lu (0x%08lx)", (unsigned long)len, (unsigned long) len);
  out(Z, Z->current, ": uncompressed",	"%lu (0x%08lx)", (unsigned long)real, (unsigned long)real);
  out(Z, Z->current, ": name-len",	"%d", name);
  out(Z, Z->current, ": extra-len",	"%d", extra);
  out(Z, Z->current, ": comment-len",	"%d", comt);
  out(Z, Z->current, ": disk",		"%d", disk);
  out(Z, Z->current, ": attribute",	"%x", attri);
  out(Z, Z->current, ": ext-attr",	"%lx", (unsigned long)attre);
  out(Z, Z->current, ": data-offset",	"0x%08lx (%ld)", (unsigned long)offs, (unsigned long)offs);

  ziphex(Z, ZIP_NAME, name);
  if (extra)
    zipextra(Z, extra);
  ziphex(Z, ZIP_COMMENT, comt);
}

static void
zipend(ZIP)
{
  unsigned long	tmp32;
  Zoff		comt;

  if (!zipfill(Z, 22))
    return zipeof(Z);

  zipart(Z, ZIP_END);

  out(Z, Z->current, ": sig",		"%08lx", (unsigned long)zipget32(Z));
  out(Z, Z->current, ": disk-number",	"%d", zipget16(Z));
  out(Z, Z->current, ": start-disk",	"%d", zipget16(Z));
  out(Z, Z->current, ": entries-here",	"%d", zipget16(Z));
  out(Z, Z->current, ": entries-total",	"%d", zipget16(Z));
  tmp32	= zipget32(Z);
  out(Z, Z->current, ": dirsize",	"%lu (0x%08lx)", tmp32, tmp32);
  out(Z, Z->current, ": dir-offset",	"0x%08lx (%lu)", tmp32, tmp32);
  comt	= zipget16(Z);
  out(Z, Z->current, ": comment-len",	"%d", comt);

  ziphex(Z, ZIP_COMMENT, comt);

  while (zipfill(Z, 1))
    zipgarbage(Z, Z_len);
}

static void
ziparch(ZIP)
{
  NOTYET;
}

static void
zipsig(ZIP)
{
  NOTYET;
}

static void
zip64end(ZIP)
{
  NOTYET;
}

static void
zip64loc(ZIP)
{
  NOTYET;
}

static void
zipdump(ZIP)
{
  int	had;

  for (had=0; zipfill(Z, 4); had=1)
    {
      uint32_t	h;

      h	= zipeek32(Z);
      if (h == 0x04034b50)	zipfile(Z);
      else if (h == 0x08064b50)	ziparch(Z);
      else if (h == 0x02014b50)	zipdir(Z);
      else if (h == 0x05054b50)	zipsig(Z);
      else if (h == 0x06064b50)	zip64end(Z);
      else if (h == 0x07064b50)	zip64loc(Z);
      else if (h == 0x06054b50)	zipend(Z);
      else
        zipgarbage(Z, 1);
    }
  if (Z->fill > Z->pos)
    zipgarbage(Z, Z_len);
  else if (!had)
    zipeof(Z);
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
#if 0
  fprintf(stderr, "# Usage: %s -N files.. > part\n\textract the Nth part (0 is what starts the file)\n", arg0);
#endif
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

  inf.part	= 0;
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

