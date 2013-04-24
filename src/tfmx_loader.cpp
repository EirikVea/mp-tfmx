/*
 * tfmx.c
 * File loader and UI for TFMX player.
 * jhp 29Feb96
 */

#include "tfmx_loader.h"

extern struct Hdb hdb[8];
extern struct Pdblk pdb;
extern struct Mdb mdb;
extern char act[8];

U32 outRate=44100;
unsigned int mlen = 0;
U8 *smplbuf = 0;
U8 *smplbuf_end = 0;
int *macros = 0;
int *patterns = 0;
short ts[512][8];

struct TFMXHeader mdat_header;

U32 mdat_editbuf[MDAT_EDITBUF_LONGS];

int num_ts;
int num_pat;
int num_mac;
int gubed=0;
int printinfo=0;
int loops=1;
int songnum=0;
int startPat=-1;
int gemx=0;
extern int blend,filt,over;

/* MD5 digests for TFMX songs that need special treatment... */
unsigned const char* md5GemxTitle=(unsigned const char*)"\xf4\xa1\xd6\x04\xc4\xdf\xb3\x0f\x91\x0f\xd8\xac\x4b\x96\xe3\x06";
unsigned const char* md5DfreakTitle=(unsigned const char*)"\x9c\xf1\x72\x34\xbc\xe1\x0d\x21\xe2\x90\x11\x72\xeb\x1a\x2a\xcc";
unsigned const char* md5OopsUpBroken=(unsigned const char*)"\x79\x41\x33\xe1\xf1\x13\x1b\x23\xc0\x9c\xd7\x29\xe8\xa6\x2a\x4e";
unsigned const char* md5OopsUp=(unsigned const char*)"\x9a\x19\x78\x84\xa8\x15\x5e\xdd\x02\x90\x23\x57\xfa\xf2\x4e\x4e";

unsigned const char* md5Monkey=(unsigned const char*)"\xc9\x5a\xa4\xf4\x44\xe8\x9a\x3f\x61\x4d\xfd\xe4\x20\x29\x96\x2a";

/* this is the MDAT that causes a segfault and other errors on MacOS-X */
unsigned const char* md5WeirdZoutThm=(unsigned const char*)"\xb2\x7c\xa7\x9c\x14\x69\x63\x87\xc1\x9c\x01\xf6\x5e\x15\x3e\xff";

int weirdZoutThm=0;
int dangerFreakHack=0;
int oopsUpHack=0;
int monkeyHack=0;

/* do we have a single-file TFMX (mdat+smpl in one file) ? */
int singleFile=0;
/* are DOS extensions used? (.tfx/.sam) */
int dosExt=0;
/* header data for single-file TFMX */
udword nTFhd_offset=0;
udword nTFhd_mdatsize=0;
udword nTFhd_smplsize=0;

#include <stdarg.h>

#define VSNPRINTF(str, size, fmt, a) vsnprintf(str, size, fmt, a)

char *g_strdup_printf(const char *fmt, ...)
{
  size_t size;
  char *buf;
  va_list va;

  va_start (va, fmt);
  size = VSNPRINTF (NULL, 0, fmt, va) + 1;
  va_end (va);
  buf = (char*)malloc (size);
  va_start (va, fmt);
  VSNPRINTF (buf, size, fmt, va);
  va_end (va);
  return buf;
}


/* structure of of cyb tfmx module (mdat and smpl in one file) */
/* format by my weird friend Alexis 'Cyb' Nasr, back in 1995, yeah ! */
/* FYI, he stopped coding (used asm m68k back then), and is now a doctor ! */
/* values are stored in big endian in the file */
struct CybHeader {
    udword TFhd_head;    /* dc.l "TFHD" for recognition */
    udword TFhd_offset;  /* dc.l	TFhd_sizeof */
    ubyte  TFhd_type;    /* module type :0/1/2/3 (bit 7=FORCED) */
    ubyte  TFhd_version; /* currently 0 */
    udword _TFhd_mdatsize;  /* compiler may align them, use offsets */
    udword _TFhd_smplsize;
    uword _TFhd_sizeof;
};


static int tfmx_loader(char *mfn,char *sfn);


/* loading of a single Cyb' TFMX file */
/* return 0 on success */
static int
tfmx_cyb_file_load (char *fn)
{
    char *tmp_mdat = NULL;
    char *tmp_smpl = NULL;
    FILE *cybf = NULL;
    char *radix = NULL;
    ubyte *cybmem = NULL;
    long fileSize;
    FILE *mdatf = NULL;
    FILE *smplf = NULL;
    struct CybHeader *cybh = NULL;
    int retval = 1;
    int ulen;
    int mdatsize;
    int smplsize;
    udword offset;

    /* get radix from filename */
    if (!(radix = strrchr(fn,'\\')))
	radix = fn;
    else
	radix++;

    /* open the single file */
    cybf = fopen(fn, "rb");

    if (!cybf)
    {
	return retval;
    }

    /* get length */
    fseek(cybf,0, SEEK_END);
    fileSize = ftell(cybf);
    rewind(cybf);

    /* alloc mem */
    cybmem = (ubyte *)malloc(fileSize);
    if (!cybmem)
	goto cleanup;

    /* read it */
    if (fread(cybmem, fileSize, 1, cybf) < 1)
	goto cleanup;
    fclose(cybf);
    cybf = NULL;

    ulen = tfmx_sqsh_get_ulen(cybmem, fileSize);
    if (ulen)
    {
	ubyte *dest;

	dest = (ubyte *)malloc(ulen+100);
	if (!dest)
	    goto cleanup;

	tfmx_sqsh_unpack(cybmem+16, dest, ulen);

	free(cybmem);
	cybmem = dest;
    }

    if (strncmp((char *)cybmem, "TFHD", 4))
	goto cleanup;

    cybh = (struct CybHeader *)cybmem;

    offset = readBEdword((ubyte*)cybh->TFhd_offset);

    mdatsize = 0;
    mdatsize  = cybmem[10]; mdatsize <<= 8;
    mdatsize |= cybmem[11]; mdatsize <<= 8;
    mdatsize |= cybmem[12]; mdatsize <<= 8;
    mdatsize |= cybmem[13];

    smplsize = 0;
    smplsize  = cybmem[14]; smplsize <<= 8;
    smplsize |= cybmem[15]; smplsize <<= 8;
    smplsize |= cybmem[16]; smplsize <<= 8;
    smplsize |= cybmem[17];

    /* create temp file names from radix */
    tmp_mdat = g_strdup_printf("/tmp/__mdat_%s__", radix);
    tmp_smpl = g_strdup_printf("/tmp/__smpl_%s__", radix);

    /* open and write temp files */
    mdatf = fopen(tmp_mdat, "wb");
    if (!mdatf)
	goto cleanup;
    fwrite(cybmem + offset, mdatsize, 1, mdatf);
    fclose(mdatf);

    smplf = fopen(tmp_smpl, "wb");
    if (!smplf)
	goto cleanup;
    fwrite(cybmem + offset + mdatsize, smplsize, 1, mdatf);
    fclose(smplf);

    /* tfmx loading */
    if (tfmx_loader(tmp_mdat, tmp_smpl) == 1) {
	goto cleanup;
    }
    retval = 0;

/* a kind of poor man exception handling :-/ */
  cleanup:
    /* if value for tmpfile => remove it */
    if (mdatf)
	remove(tmp_mdat);
    if (smplf)
	remove(tmp_smpl);
    if (tmp_mdat)
	free(tmp_mdat);
    if (tmp_smpl)
	free(tmp_smpl);
    if (cybmem)
	free(cybmem);
    if (cybf)
	fclose(cybf);
    return retval;
}

/* misc vars for TFMX format test */
#define MAGIK_LEN 11        /* length including final null byte */
unsigned int nMagikLen=MAGIK_LEN;
char pMagikBuf[MAGIK_LEN];




/* TFMX format test from UADE */
static int tfmxtest(unsigned char *buf, int filesize, char *pre)
{
  int ret = 0;

  if (buf[0] == 'T' && buf[1] == 'F' && buf[2] =='H' && buf[3] =='D')
  {
    if (buf[0x8] == 0x01) {
      strncpy (pre, "TFHD1.5\x00", nMagikLen-1);		/* One File TFMX format */
      /* by Alexis NASR */
      ret = 1;
    } else if (buf[0x8] == 0x02) {
      strncpy (pre, "TFHDPro\x00",nMagikLen-1);
      ret = 1;
    } else if (buf[0x8] == 0x03) {
      strncpy (pre, "TFHD7V\x00",nMagikLen-1);
      ret = 1;
    }

  } else if ((buf[0] == 'T' && buf[1] == 'F' && buf[2] =='M' && buf[3] == 'X')||
	     (buf[0] == 't' && buf[1] == 'f' && buf[2] =='m' && buf[3] == 'x'))  {

    strncpy (pre, "MDAT\x00",nMagikLen-1);	/*default TFMX: TFMX Pro*/
    ret = 1;

    if ((buf [4] == '-' &&  buf[5] == 'S' && buf[6] =='O' && buf[7] == 'N' && buf[8] == 'G' && buf[9] == ' ')||
	(buf [4] == '_' &&  buf[5] == 'S' && buf[6] =='O' && buf[7] == 'N' && buf[8] == 'G' && buf[9] == ' ')||
	(buf [4] == 'S' &&  buf[5] == 'O' && buf[6] =='N' && buf[7] == 'G')||
	(buf [4] == 's' &&  buf[5] == 'o' && buf[6] =='n' && buf[7] == 'g')||
	(buf [4] == 0x20)) {
      if ((buf [10] =='b'  && buf[11] =='y')  ||
	  (buf [16] == ' ' && buf[17] ==' ')  ||
	  (buf [16] == '(' && buf[17] =='E' && buf[18] == 'm' && buf[19] =='p' && buf[20] =='t' && buf[21] == 'y' && buf[22] ==')' ) ||
	  (buf [16] == 0x30 && buf[17] == 0x3d) || /*lethal Zone*/
	  (buf [4]  == 0x20)) {
	if (buf[464]==0x00 && buf[465]==0x00 && buf[466]==0x00 && buf[467]==0x00) {
	  if ((buf [14]!=0x0e && buf[15] !=0x60) || /*z-out title */
	      (buf [14]==0x08 && buf[15] ==0x60 && buf[4644] != 0x09 && buf[4645] != 0x0c) || /* metal law */
	      (buf [14]==0x0b && buf[15] ==0x20 && buf[5120] != 0x8c && buf[5121] != 0x26) || /* bug bomber */
	      (buf [14]==0x09 && buf[15] ==0x20 && buf[3876] != 0x93 && buf[3977] != 0x05)) { /* metal preview */
	    strncpy (pre, "TFMX1.5\x00",nMagikLen-1);	/*TFMX 1.0 - 1.6*/
	  }
	}
      } else if (((buf[0x0e]== 0x08 && buf[0x0f] ==0xb0) &&   /* BMWi */
		  (buf[0x140] ==0x00 && buf[0x141]==0x0b) && /*End tackstep 1st subsong*/
		  (buf[0x1d2]== 0x02 && buf[0x1d3] ==0x00) && /*Trackstep datas*/

		  (buf[0x200] == 0xff && buf[0x201] ==0x00 && /*First effect*/
		   buf[0x202] == 0x00 && buf[0x203] ==0x00 &&
		   buf[0x204] == 0x01 && buf[0x205] ==0xf4 &&
		   buf[0x206] ==0xff && buf[0x207] ==0x00)) ||

		 ((buf[0x0e]== 0x0A && buf[0x0f] ==0xb0) && /* B.C Kid */
		  (buf[0x140] ==0x00 && buf[0x141]==0x15) && /*End tackstep 1st subsong*/
		  (buf[0x1d2]== 0x02 && buf[0x1d3] ==0x00) && /*Trackstep datas*/

		  (buf[0x200] == 0xef && buf[0x201] ==0xfe && /*First effect*/
		   buf[0x202] == 0x00 && buf[0x203] ==0x03 &&
		   buf[0x204] == 0x00 && buf[0x205] ==0x0d &&
		   buf[0x206] ==0x00 && buf[0x207] ==0x00)))  {
	strncpy (pre, "TFMX7V\x00",nMagikLen-1);	/* "special cases TFMX 7V*/

      } else {

	int e, i, s, t;

	/* Trackstep datas offset */
	if (buf[0x1d0] ==0x00 && buf[0x1d1] ==0x00 && buf[0x1d2] ==0x00 && buf[0x1d3] ==0x00) {
	  /* unpacked*/
	  s = 0x00000800;
	} else {
	  /*packed */
	  s = (buf[0x1d0] <<24) + (buf[0x1d1] <<16) + (buf[0x1d2] <<8) + buf[0x1d3]; /*packed*/
	}

	for (i = 0; i < 0x3d; i += 2) {
	  if (( (buf[0x140+i] <<8 ) +buf[0x141+i]) > 0x00 ) { /*subsong*/
	    t = (((buf[0x100+i]<<8) +(buf[0x101+i]))*16 +s ); /*Start of subsongs Trackstep data :)*/
	    e = (((buf[0x140+i]<<8) +(buf[0x141+i]))*16 +s ); /*End of subsongs Trackstep data :)*/
	    if (t < filesize || e < filesize) {
	      for (t = t ; t < e ; t += 2) {
		if (buf[t] == 0xef && buf[t+1] == 0xfe) {
		  if (buf[t+2] == 0x00 && buf[t+3] == 0x03 &&
		      buf[t+4] == 0xff && buf[t+5] == 0x00 && buf[t+6] == 0x00) {
		    i=0x3d;
		    strncpy (pre, "TFMX7V\x00",nMagikLen-1);	/*TFMX 7V*/
		    break;
		  }
		}
	      }
	    }
	  }
	}
      }
    }
  }
  return ret;
}


void check_md5_and_headers(char *mfile)
{
	EVP_MD_CTX mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len;

	/* return value of format test */
	int nUadeRet=0;

	int mc=0;
	int dfc=0;
	int gxc=0;
	int zxc=0;
	int ooxc=0;
	int ooxc2=0;
	int monkeyc=0;
	long size=-1;
	unsigned long pos=0;
	unsigned char* fdat;

	FILE *fp=0;

	if ((fp=fopen(mfile,"r")) == 0)
	{
		perror("fopen");
		return;
	}
	while ( !feof(fp) )
	{
		getc(fp);
		size++;
	}
	/* have filesize */
	fclose(fp);
	/* allocale buffer */
	fdat=(unsigned char*)malloc((sizeof(unsigned char))*((unsigned long)size));
	/* fill buffer */
	if ((fp=fopen(mfile,"r")) == 0)
	{
		perror("fopen");
		return;
	}
	for (pos=0; pos < ((unsigned long)(size)); pos++)
	{
		fdat[pos]=getc(fp);
	}
	fclose(fp);

	/* since we have got the file loaded, it's a good time to run the format test... */
	/* first clear magik buffer */
	memcpy(pMagikBuf,"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",nMagikLen);
	/* run test */
        nUadeRet=tfmxtest(fdat, ((unsigned long)size), pMagikBuf);
	/* print result */
	printf("\nmagik[%s] ret[%d]\n",pMagikBuf,nUadeRet);
        /*
	TODO do something with result...
	"MDAT"
	"TFMX1.5"
	"TFMXPro" (we only get this for 1-file TFMX-songs, which are not supported anyway ATM.)
	"TFMX7V"
	nUadeRet==1 ==> some kind of TFMX format, otherwise not recognized
	*/

	/* if it's a single-file TFMX, let's grab the pointers to mdat+smpl while we're at it */
	if (singleFile==1)
	{
		memcpy( (void*)(&nTFhd_offset), (void*)(fdat+4), 4);
		nTFhd_offset=ntohl(nTFhd_offset);
		/* now we have the size of the header */
		memcpy( (void*)(&nTFhd_mdatsize), (void*)(fdat+10), 4);
		nTFhd_mdatsize=ntohl(nTFhd_mdatsize);
		/* now we have the size of the mdat */
		memcpy( (void*)(&nTFhd_smplsize), (void*)(fdat+14), 4);
		nTFhd_smplsize=ntohl(nTFhd_smplsize);
		/* now we have the size of the smpl */

		/* check if the actual filesize matches the size given by the header */
		if (nTFhd_offset+nTFhd_mdatsize+nTFhd_smplsize != size)
		{
			printf("\nERROR! 1-file TFMX header defines illegal size:\
[%d] instead of [%d] \n",nTFhd_offset+nTFhd_mdatsize+nTFhd_smplsize,(unsigned long)size);
			exit(0);
		}

	}

	/* create md5 digest */
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("MD5");
	if (!md) {
		printf("Unknown message digest MD5");
		exit(1);
	}
	EVP_DigestInit(&mdctx, md);
	EVP_DigestUpdate(&mdctx, fdat, size);
	EVP_DigestFinal(&mdctx, md_value, (unsigned int*)&md_len);
	/* compare md5 sums */
	for (mc=0; mc<16; mc++)
	{
		if (md_value[mc]==md5DfreakTitle[mc])
			dfc++;
	}
	for (mc=0; mc<16; mc++)
	{
		if (md_value[mc]==md5GemxTitle[mc])
			gxc++;
	}
	for (mc=0; mc<16; mc++)
	{
		if (md_value[mc]==md5WeirdZoutThm[mc])
			zxc++;
	}
	for (mc=0; mc<16; mc++)
	{
		if (md_value[mc]==md5OopsUp[mc])
			ooxc++;
	}
	for (mc=0; mc<16; mc++)
	{
		if (md_value[mc]==md5OopsUpBroken[mc])
			ooxc2++;
	}
	for (mc=0; mc<16; mc++)
	{
		if (md_value[mc]==md5Monkey[mc])
			monkeyc++;
	}
	if (dfc==16)
		dangerFreakHack=1;
	else if (gxc==16)
		gemx=1;
	else if (ooxc==16)
	        oopsUpHack=1;
	else if (ooxc2==16)
	        oopsUpHack=1;
	else if (zxc==16)
	        weirdZoutThm=1;
	else if (monkeyc==16)
	        monkeyHack=1;

#ifdef WORDS_BIGENDIAN
	if (weirdZoutThm==1)
	{
		printf("Warning! Problematic Z-Out theme mdat detected!\n\
May cause crashes/hangups on big-endian CPUs!\n");
	}
#endif

	/* free buffer */
	free(fdat);
	return;
}

char LoadTFMXFile(char *fName)
{
    int suffixPos, status;
    char *mfn = fName, *sfn, *c;

    if(!fName) return 1;
    if(!(sfn = strdup(mfn))) return 1;

    if (!(c = strrchr(sfn,'\\')))
	c = sfn;
    else
	c++;
    suffixPos = strlen(c) - 4;	/* Get filename length */

    if (strncasecmp(c,"mdat.",5) == 0) {
	/* Case-preserving conversion of "mdat" to "smpl" */
	(*c++)^='m'^'s'; (*c++)^='d'^'m'; (*c++)^='a'^'p'; (*c++)^='t'^'l';
	c-=4;
    }
    else if (strncasecmp(c,"tfmx.",5) == 0) { /* Single Cyb' TFMX file */
	free(sfn);
	return tfmx_cyb_file_load(fName);
    }
    else if (suffixPos >= 0 && strncasecmp(c + suffixPos,".tfx", 4) == 0) {
	/* Case-preserving conversion of ".tfx" to ".sam" */
	*(c+suffixPos+1)^='t'^'s'; *(c+suffixPos+2)^='f'^'a'; *(c+suffixPos+3)^='x'^'m';
    }
    else
    {
        TFMXERR("LoadTFMX: Song name prefix / suffix missing ?!");
        free(sfn);
        return 1;
    }

    if ((status=tfmx_loader(mfn,sfn))==1)
    {
        /* TFMXERR("LoadTFMXFile: Loading of module failed"); */
        free(sfn); return 1;
    }
    else if (status==2) {
        /* TFMXERR("LoadTFMXFile: Not an MDAT file"); */
        free(sfn); return 1;
    }

    free(sfn);
    return 0;
}

//int tfmx_loader(char *mfn, char *sfn)
//{
//	FILE *gfd;
//	struct stat s;
//	unsigned int x,y,z=0;
//	U16 *sh,*lg;
//
//	if ((gfd=fopen(mfn,"r")) == 0)
//	{
//		perror("fopen");
//		return(1);
//	}
//
//	/* jump to mdat start if single-file format */
//	if (singleFile==1)
//	{
//		fseek(gfd, nTFhd_offset, SEEK_CUR);
//	}
//
//	if (!fread(&mdat_header,sizeof(mdat_header),1,gfd))
//	{
//		perror("fread");
//		fclose(gfd);
//		return(1);
//	}
//	if (strncmp("TFMX-SONG",mdat_header.magic,9)&&
//	    strncmp("TFMX_SONG",mdat_header.magic,9)&&
//	    strncasecmp("TFMXSONG",mdat_header.magic,8) &&
//	    strncmp("TFMX",mdat_header.magic,4))
//	{
//		fclose(gfd);
//		return(2);
//	}
//	if (!(x=fread(&mdat_editbuf,sizeof(int),16384,gfd)))
//	{
//		perror("fread");
//		fclose(gfd);
//		return(1);
//	}
//
//	/* close file if we have two files for mdat+smpl */
//	if (singleFile==0)
//	{
//        	fclose(gfd);
//	}
//
//	mlen=x;
//	mdat_editbuf[x]=-1;
//
//	if (!mdat_header.trackstart)
//		mdat_header.trackstart=0x180;
//	else
//		mdat_header.trackstart=(ntohl(mdat_header.trackstart)-0x200)>>2;
//
//	if (!mdat_header.pattstart)
//		mdat_header.pattstart=0x80;
//	else
//		mdat_header.pattstart=(ntohl(mdat_header.pattstart)-0x200)>>2;
//
//	if (!mdat_header.macrostart)
//		mdat_header.macrostart=0x100;
//	else
//		mdat_header.macrostart=(ntohl(mdat_header.macrostart)-0x200)>>2;
//
//	if (x<136)
//	{
//		return(2);
//	}
//
//	for (x=0;x<32;x++)
//	{
//		mdat_header.start[x]=ntohs(mdat_header.start[x]);
//		mdat_header.end[x]=ntohs(mdat_header.end[x]);
//		mdat_header.tempo[x]=ntohs(mdat_header.tempo[x]);
//	}
//
///* Now that we have pointers to most everything, this would be a good time to
//   fix everything we can... ntohs tracksteps, convert pointers to array
//   indices, ntohl patterns and macros.  We fix the macros first, then the
//   patterns, and then the tracksteps (because we have to know when the
//   patterns begin to know when the tracksteps end...) */
//	z=mdat_header.macrostart;
//	macros = (int*)&mdat_editbuf[z];
//
//	for (x=0;x<128;x++)
//	{
//		y=(ntohl(mdat_editbuf[z])-0x200);
//		if ((y&3)||((y>>2)>mlen)) /* probably not strictly right */
//			break;
//		mdat_editbuf[z++]=y>>2;
//	}
//	num_mac=x;
//
//	z=mdat_header.pattstart;
//	patterns = (int*)&mdat_editbuf[z];
//	for (x=0;x<128;x++)
//	{
//		y=(ntohl(mdat_editbuf[z])-0x200);
//		if ((y&3)||((y>>2)>mlen))
//			break;
//		mdat_editbuf[z++]=y>>2;
//	}
//	num_pat=x;
//
//	lg=(U16 *)&mdat_editbuf[patterns[0]];
//	sh=(U16 *)&mdat_editbuf[mdat_header.trackstart];
//	num_ts=(patterns[0]-mdat_header.trackstart)>>2;
//	y=0;
//	while (sh<lg)
//	{
//		x=ntohs(*sh);
//		*sh++=x;
//	}
//
///* Now at long last we load the sample file/data. */
//
//	/* different handling for single- and dual-file formats */
//	if (singleFile==1)
//	{
//	        /* jump to smpl start */
//	        uword nSmplPos=nTFhd_offset+nTFhd_mdatsize;
//		fseek(gfd, nSmplPos, SEEK_SET);
//                /* allocate mem */
//		if (!(smplbuf=(U8 *)malloc(nTFhd_smplsize)))
//		{
//			perror("malloc");
//			fclose(gfd);
//			return(1);
//		}
//		/* read samples */
//		if (!fread(smplbuf,sizeof(char),nTFhd_smplsize,gfd))
//		{
//			perror("read");
//			fclose(gfd);
//			free(smplbuf);
//			return(1);
//		}
//		/* finally close the file */
//	        fclose(gfd);
//	}
//	else
//	{
//		if ((y=open(sfn,O_RDONLY))<=0)
//		{
//			perror("fopen");
//			return(1);
//		}
//		if (fstat(y,&s))
//		{
//			perror("fstat");
//			close(y);
//			return(1);
//		}
//		if (!(smplbuf=(U8 *)malloc(s.st_size)))
//		{
//			perror("malloc");
//			close(y);
//			return(1);
//		}
//		if (!read(y,smplbuf,s.st_size))
//		{
//			perror("read");
//			close(y);
//			free(smplbuf);
//			return(1);
//		}
//		close(y);
//	}
//	return (0);
//}

static int tfmx_loader (char *mfn,char *sfn)
{
    FILE *gfd, *smplFile;
    /* struct stat s; */
    int x, y, z = 0;
    U16 *sh, *lg;

    if ((gfd = fopen(mfn,"rb"))<=0) {
	TFMXERR("LoadTFMX: Failed to open song");
	return(1);
    }

    if (!fread(&mdat_header, sizeof(mdat_header), 1, gfd)) {
	TFMXERR("LoadTFMX: Failed to read TFMX header");
	fclose(gfd);
	return(1);
    }
    if (strncmp("TFMX-SONG", mdat_header.magic, 9)
	&& strncmp("TFMX_SONG", mdat_header.magic, 9)
	&& strncasecmp("TFMXSONG", mdat_header.magic, 8)
	&& strncasecmp("TFMX ", mdat_header.magic, 5))
    {
	TFMXERR("LoadTFMX: Not a TFMX module");
	fclose(gfd);
	return(2);
    }

    if (!(x = fread(&mdat_editbuf, sizeof(U32), MDAT_EDITBUF_LONGS, gfd)))
    {
	TFMXERR("LoadTFMX: Read error in MDAT file");
	fclose(gfd);
	return(1);
    }

    fclose(gfd);

    mlen = x;

    mdat_editbuf[x] = -1;
    if (!mdat_header.trackstart)
	mdat_header.trackstart = 0x180;
    else
	mdat_header.trackstart = (ntohl(mdat_header.trackstart) - 0x200L) >> 2;
    if (!mdat_header.pattstart)
	mdat_header.pattstart = 0x80;
    else mdat_header.pattstart = (ntohl(mdat_header.pattstart) - 0x200L) >> 2;
    if (!mdat_header.macrostart) mdat_header.macrostart=0x100;
    else mdat_header.macrostart=(ntohl(mdat_header.macrostart)-0x200L)>>2;
    if (x<136) {
	return(2);
    }

    for (x=0;x<32;x++) {
	mdat_header.start[x]=ntohs(mdat_header.start[x]);
	mdat_header.end[x]=ntohs(mdat_header.end[x]);
	mdat_header.tempo[x]=ntohs(mdat_header.tempo[x]);
    }

    /* Calc the # of subsongs */
    nSongs = 0;
    for (x = 0; x < 31; x++)
    {
	if ((mdat_header.start[x] <= mdat_header.end[x])
	    && !(x > 0 && mdat_header.end[x] == 0L))
	{
	    nSongs++;
	}
    }
/* Now that we have pointers to most everything, this would be a good time to
   fix everything we can... ntohs tracksteps, convert pointers to array
   indices, ntohl patterns and macros.  We fix the macros first, then the
   patterns, and then the tracksteps (because we have to know when the
   patterns begin to know when the tracksteps end...) */
    z = mdat_header.macrostart;
    macros = (int*)&(mdat_editbuf[z]);

    for (x = 0; x < 128; x++) {
	y=(ntohl(mdat_editbuf[z])-0x200);
	if ((y&3) || ((y>>2) > mlen)) /* probably not strictly right */
	    break;
	mdat_editbuf[z++]=y >> 2;
    }
    num_mac = x;

    z=mdat_header.pattstart;
    patterns = (int*)&mdat_editbuf[z];
    for (x = 0; x < 128; x++) {
	y=(ntohl(mdat_editbuf[z])-0x200);
	if ((y&3) || ((y>>2) > mlen))
	    break;
	mdat_editbuf[z++] = y>>2;
    }
    num_pat = x;

    lg = (U16 *)&mdat_editbuf[patterns[0]];
    sh = (U16 *)&mdat_editbuf[mdat_header.trackstart];
    num_ts = (patterns[0] - mdat_header.trackstart) >> 2;
    y=0;
    while (sh<lg) {
	x=ntohs(*sh);
	*sh++=x;
    }

/* Now at long last we calc the size of and load the sample file. */
    {
	long fileSize = 0;

	if ((smplFile=fopen(sfn,"rb")) == NULL) {
	    TFMXERR("LoadTFMX: Error opening SMPL file");
	    return(1);
	}
	if (fseek(smplFile,0, SEEK_END)) {
	    TFMXERR("LoadTFMX: fseek failed in SMPL file"); fclose(smplFile);
	    return(1);
	}
	if ((fileSize = ftell(smplFile)) < 0) {
	    TFMXERR("LoadTFMX: ftell failed in SMPL file"); fclose(smplFile);
	    return(1);
	}

	if(smplbuf) {	// Dealloc any left behind samplebuffer
	    free(smplbuf);
	    smplbuf=0;
	}

	if (!(smplbuf=(U8 *)malloc(fileSize))) {
	    TFMXERR("LoadTFMX: Error allocating samplebuffer"); fclose(smplFile);
	    return(1);
	}

	smplbuf_end = smplbuf + fileSize - 1;
	rewind(smplFile);

	if (!fread(smplbuf,1,fileSize,smplFile)) {
	    TFMXERR("LoadTFMX: Error reading SMPL file");
	    fclose(smplFile);
	    free(smplbuf);
	    return(1);
	}
	fclose(smplFile);
    }

    if (plugin_cfg.blend)
	output_chans = 2;
    plugin_cfg.blend &= 1;

    tfmx_calc_sizes();
    TFMXRewind();

    return 0;

/* Now the song is fully loaded.  Everything is done but ntohl'ing the actual
   pattern and macro data. The routines that use the data do it for themselves.*/
}

void tfmx_fill_module_info(char *t)
{
    int x;

    /* Don't print info if there's no song... */
    if(!smplbuf) {
	sprintf(t, "No song loaded!");
	return;
    }

    t += sprintf(t, "Module text section:\n\n");
    for (x = 0;x < 6; x++)
	t += sprintf(t, ">%40.40s\n", mdat_header.text[x]);

    t += sprintf(t, "\n%d tracksteps at 0x%04lx\n", num_ts, (mdat_header.trackstart<<2)+0x200);
    t += sprintf(t, "%d patterns at 0x%04lx\n", num_pat, (mdat_header.pattstart<<2)+0x200);
    t += sprintf(t, "%d macros at 0x%04lx\n", num_mac, (mdat_header.macrostart<<2)+0x200);

    t += sprintf(t, "\nSubsongs:\n\n");
    for (x = 0; x < 31; x++)
    {
	if ((mdat_header.start[x] <= mdat_header.end[x])
	    && !(x > 0 && mdat_header.end[x] == 0L))
	{
	    t += sprintf(t,"Song %2d: start %3x end %3x tempo %d\n", x,
			 ntohs(mdat_header.start[x]), ntohs(mdat_header.end[x]),
			 mdat_header.tempo[x]);
	}
    }
}

void tfmx_get_module_info(char *info)
{
    for (int x = 0;x < 6; x++)
        sprintf(info, ">%40.40s\n", mdat_header.text[x]);
}
