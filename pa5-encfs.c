/*
 * 
 * Encrypted Filesystem Mirror 
 * written by Anne Gatchell
 * 
 * 
 * 
 * Modified from:
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/
#include "params.h"
#include "aes-crypt.h"

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <limits.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

void log_msg(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);

    vfprintf(ENCR_DATA->logfile, format, ap);
}

// Report errors to logfile and give -errno to caller
static int encr_error(char *str)
{
    int ret = -errno;
    fprintf(stderr, "%s",str);
    return ret;
}
//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.
static void encr_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, ENCR_DATA->rootdir);
    strncat(fpath, path, PATH_MAX); // ridiculously long paths will
				    // break here
}

static void encr_tempfilename(char feditpath[PATH_MAX], const char *fpath)
{
	char rawpath[PATH_MAX];
	char rawfilename[PATH_MAX];
	char prepend[PATH_MAX];
	//strcpy(prepend, "/AA");
	strcpy(rawpath, fpath);
	char* token;
	token = strtok(rawpath, "/");
	while(token != NULL){
		printf ("%s\n",token);
		if(token != NULL)
			strcpy(rawfilename, token);
		token = strtok(NULL, "/");
	}
	
	//Get size of the raw file name
	int filename_size = strlen(rawfilename);
	int fpath_size = strlen(fpath);
	printf("length filename = %d, length path = %d\n", filename_size, fpath_size);
	strncpy(prepend, fpath, strlen(fpath)-filename_size -1);
	strcat(prepend, "/AA");
	printf("prepend = %s\n", prepend);
	//Now we have the raw filename with prepended temp symbol,
	//must now add back to the original path
	strcat(prepend, rawfilename);
	printf("rawfilename = %s, rawpath = %s, path = %s\n", rawfilename, rawpath, prepend);
	strcpy(feditpath, prepend);
     // ridiculously long paths will
				    // break here
	memset(rawpath, '\0', sizeof(rawpath));
	memset(rawfilename, '\0', sizeof(rawfilename));
	memset(prepend, '\0', sizeof(prepend));
	
}

static char* encr_key(){
	return ENCR_DATA->key_phrase;
}

//Updated to fullpath
static int encr_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	
	encr_fullpath(fpath, path);

	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to fullpath
static int encr_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX];
	
	encr_fullpath(fpath, path);

	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to fullpath
static int encr_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX];
	
	encr_fullpath(fpath, path);
	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int encr_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	int retstat = 0;
	DIR *dp;
	struct dirent *de;
	
	//Get rid of unused parameter warnings
	char fpath[PATH_MAX];
	encr_fullpath(fpath, path);
	off_t warn_relief = offset;
	offset = warn_relief;

	// once again, no need for fullpath -- but note that I need to cast fi->fh
	//I do not understand this
	dp = (DIR *) (uintptr_t) fi->fh;

	// Every directory contains at least two entries: . and ..  If my
    // first call to the system readdir() returns NULL I've got an
    // error; near as I can tell, that's the only condition under
    // which I can get an error from readdir()
    de = readdir(dp);
    if (de == 0) {
		retstat = encr_error("encr_readdir readdir");
		return retstat;
    }
    
    // This will copy the entire directory into the buffer.  The loop exits
    // when either the system readdir() returns NULL, or filler()
    // returns something non-zero.  The first case just means I've
    // read the whole directory; the second means the buffer is full.
    do {
		//log_msg("calling filler with name %s\n", de->d_name);
		if (filler(buf, de->d_name, NULL, 0) != 0) {
			//log_msg("    ERROR bb_readdir filler:  buffer full");
			return -ENOMEM;
		}
    } while ((de = readdir(dp)) != NULL);
    
    
    return retstat;
}
//Updated to fullpath
static int encr_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode)){
		res = mkfifo(fpath, mode);
	} else{
		res = mknod(fpath, mode, rdev);
	}
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to fullpath
static int encr_mkdir(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);
    //Make the directory
	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;
	return 0;
}
//Updated to fullpath
static int encr_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to full path
static int encr_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);
	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to full path
/** Create a symbolic link */
// The parameters here are a little bit confusing, but do correspond
// to the symlink() system call.  The 'path' is where the link points,
// while the 'link' is the link itself.  So we need to leave the path
// unaltered, but insert the link into the mounted directory.
static int encr_symlink(const char *from, const char *to)
{
	int res;
	char fto[PATH_MAX];
    
    encr_fullpath(fto, to);

	//retstat = symlink(path, flink);
	res = symlink(from, fto);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to full path
static int encr_rename(const char *from, const char *to)
{
	int res;
	char fpath[PATH_MAX];
    char fnewpath[PATH_MAX];
    
    encr_fullpath(fpath, from);
    encr_fullpath(fnewpath, to);
	
	res = rename(fpath,fnewpath);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to full path
static int encr_link(const char *from, const char *to)
{
	int res;
	char fpath[PATH_MAX];
    char fnewpath[PATH_MAX];
    
    encr_fullpath(fpath, from);
    encr_fullpath(fnewpath, to);

	res = link(fpath, fnewpath);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to full path
static int encr_chmod(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
   
    encr_fullpath(fpath, path);

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to full path
static int encr_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];

    encr_fullpath(fpath, path);
    
	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to full path
static int encr_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);
    
	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to full path
static int encr_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to full path
static int encr_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
	char feditpath[PATH_MAX];
	FILE* inFile;
	FILE* outFile;
	
	printf("\nencr_open fpath=\"%s", path);
	encr_fullpath(fpath, path);
	//encr_tempfullpath(feditpath, fpath);
	///* Set Vars */
	////Will have to check for decryption status and add a
	////pass through copy case
	
	//int action = 0;
	
	///* Open Files */
    //inFile = fopen(fpath, "rb");
    //if(!inFile){
		//perror("infile fopen error");
		//return EXIT_FAILURE;
    //}
    //outFile = fopen(feditpath, "wb+");
    //if(!outFile){
		//perror("outfile fopen error");
		//return EXIT_FAILURE;
    //}
	//printf("\nOpen, key phrase %s\n", encr_key());
    ///* Perform do_crpt action (encrypt, decrypt, copy) */
    //if(!do_crypt(inFile, outFile, action, encr_key())){
	//fprintf(stderr, "do_crypt failed\n");
    //}

    ///* Cleanup */
    //if(fclose(outFile)){
        //perror("outFile fclose error\n");
    //}
    //if(fclose(inFile)){
	//perror("inFile fclose error\n");
    //}
    
    //rename(feditpath, fpath);
	
	//Open the file for the caller
	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;
	
	close(res);
	return 0;
}
//Updated to full path
static int encr_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;
	char tempfilename[PATH_MAX];
	char fpath[PATH_MAX];
	char feditpath[PATH_MAX];
	FILE* inFile;
	FILE* outFile;
    
    printf("\nencr_read fpath=\"%s\n", path);
    encr_tempfilename(tempfilename, path);
    encr_fullpath(fpath, path);
    encr_fullpath(feditpath, tempfilename);
    
    printf("\nencr_read fullpath=\"%s\n decrypted=%s\n", fpath, feditpath);
	/* Set Vars */
	//Will have to check for decryption status and add a
	//pass through copy case
	
	//Action = 0 means decryption
	int action = 0;
	
	/* Open Files */
    inFile = fopen(fpath, "rb");
    if(!inFile){
		perror("infile fopen error");
		return EXIT_FAILURE;
    }
    outFile = fopen(feditpath, "wb+");
    if(!outFile){
		perror("outfile fopen error");
		return EXIT_FAILURE;
    }

	printf("\nOpen, key phrase %s\n", encr_key());
    /* Perform do_crpt action (encrypt, decrypt, copy) */
    if(!do_crypt(inFile, outFile, action, encr_key())){
	fprintf(stderr, "do_crypt failed\n");
    }

    /* Cleanup */
    if(fclose(outFile)){
        perror("outFile fclose error\n");
    }
    if(fclose(inFile)){
	perror("inFile fclose error\n");
    }
    
    //rename(feditpath, fpath);
    
	//Do the read on the new files
	(void) fi;
	fd = open(feditpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	memset(tempfilename, '\0', sizeof(tempfilename));
	memset(fpath, '\0', sizeof(fpath));
	memset(feditpath, '\0', sizeof(feditpath));
	//remove(feditpath);
	return res;
}
//Updated to full path
static int encr_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;
	char fpath[PATH_MAX];
    char feditpath[PATH_MAX];
    char tempfilename[PATH_MAX];
	FILE* inFile;
	FILE* outFile;
	
	printf("\nencr_write fpath=\"%s", path);
	encr_tempfilename(tempfilename, fpath);
    encr_fullpath(fpath, path);
	encr_fullpath(feditpath, tempfilename);
	/* Set Vars */
	//Will have to check for decryption status and add a
	//pass through copy case
	
	//Decrypt
	int action = 0;
	
	/* Open Files */
    inFile = fopen(fpath, "rb");
    if(!inFile){
		perror("infile fopen error");
		return EXIT_FAILURE;
    }
    outFile = fopen(feditpath, "wb+");
    if(!outFile){
		perror("outfile fopen error");
		return EXIT_FAILURE;
    }
	printf("\nOpen, key phrase %s\n", encr_key());
    /* Perform do_crpt action (encrypt, decrypt, copy) */
    if(!do_crypt(inFile, outFile, action, encr_key())){
	fprintf(stderr, "do_crypt failed\n");
    }

    /* Cleanup */
    if(fclose(outFile)){
        perror("outFile fclose error\n");
    }
    if(fclose(inFile)){
	perror("inFile fclose error\n");
    }
	
	//Do the write
	(void) fi;
	fd = open(feditpath, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	
	//Now recrypt
	action = 0;
	
	/* Open Files */
    inFile = fopen(feditpath, "rb");
    if(!inFile){
		perror("infile fopen error");
		return EXIT_FAILURE;
    }
    outFile = fopen(fpath, "wb+");
    if(!outFile){
		perror("outfile fopen error");
		return EXIT_FAILURE;
    }

    /* Perform do_crpt action (encrypt, decrypt, copy) */
    if(!do_crypt(inFile, outFile, action, encr_key())){
	fprintf(stderr, "do_crypt failed\n");
    }

    /* Cleanup */
    if(fclose(outFile)){
        perror("outFile fclose error\n");
    }
    if(fclose(inFile)){
	perror("inFile fclose error\n");
    }
    remove(feditpath);
    
	return res;
}
//Updated to full path
static int encr_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}
//Updated to full path
static int encr_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;
    char fpath[PATH_MAX];
	
	//Need to add the encrypted flag
    printf("\nencr_create fpath=\"%s", path);
    encr_fullpath(fpath, path);

    int res;
    res = creat(fpath, mode);
    if(res == -1)
	return -errno;

    close(res);

    return 0;
}


static int encr_release(const char *path, struct fuse_file_info *fi)
{
	printf("\nPath to release= %s\n", path);
	//int fd;
	//int res;
	char tempfilename[PATH_MAX];
	char fpath[PATH_MAX];
	char feditpath[PATH_MAX];
	//FILE* inFile;
	//FILE* outFile;
    
    encr_tempfilename(tempfilename, path);
    encr_fullpath(fpath, path);
    //printf("\nencr_release fpath=\"%s\n", fpath);
    encr_fullpath(feditpath, tempfilename);
    
    printf("\nencr_release fullpath=\"%s\n decrypted=%s\n", fpath, feditpath);
	
	//Delete the temp file that we had made
	remove(feditpath);
	
	memset(tempfilename, '\0', sizeof(tempfilename));
	memset(fpath, '\0', sizeof(fpath));
	memset(feditpath, '\0', sizeof(feditpath));
	///* Set Vars */
	////Will have to check for decryption status and add a
	////pass through copy case
	
	////Action = 0 means decryption
	//int action = 0;
	
	///* Open Files */
    //inFile = fopen(fpath, "rb");
    //if(!inFile){
		//perror("infile fopen error");
		//return EXIT_FAILURE;
    //}
    //outFile = fopen(feditpath, "wb+");
    //if(!outFile){
		//perror("outfile fopen error");
		//return EXIT_FAILURE;
    //}

	//printf("\nOpen, key phrase %s\n", encr_key());
    ///* Perform do_crpt action (encrypt, decrypt, copy) */
    //if(!do_crypt(inFile, outFile, action, encr_key())){
	//fprintf(stderr, "do_crypt failed\n");
    //}

    ///* Cleanup */
    //if(fclose(outFile)){
        //perror("outFile fclose error\n");
    //}
    //if(fclose(inFile)){
	//perror("inFile fclose error\n");
    //}
    
    ////rename(feditpath, fpath);
    
	////Do the read on the new files
	//(void) fi;
	//fd = open(feditpath, O_RDONLY);
	//if (fd == -1)
		//return -errno;

	//res = pread(fd, buf, size, offset);
	//if (res == -1)
		//res = -errno;

	//close(fd);
	////remove(feditpath);
	//return res;

	(void) path;
	(void) fi;
	return 0;
}

static int encr_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
int encr_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp;
    int retstat = 0;
    char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);
    
    dp = opendir(fpath);
    if (dp == NULL)
		fprintf(stderr,"encr_opendir opendir");
    
    fi->fh = (intptr_t) dp;
    
    //log_fi(fi);
    
    return retstat;
}




#ifdef HAVE_SETXATTR
//Updated to full path
static int encr_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}
//Updated to full path
static int encr_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);
	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}
//Updated to full path
static int encr_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}
//Updated to full path
static int encr_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
    
    encr_fullpath(fpath, path);
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */



static struct fuse_operations encr_oper = {
	.getattr	= encr_getattr,
	.access		= encr_access,
	.readlink	= encr_readlink,
	.readdir	= encr_readdir,
	.mknod		= encr_mknod,
	.mkdir		= encr_mkdir,
	.symlink	= encr_symlink,
	.unlink		= encr_unlink,
	.rmdir		= encr_rmdir,
	.rename		= encr_rename,
	.link		= encr_link,
	.chmod		= encr_chmod,
	.chown		= encr_chown,
	.truncate	= encr_truncate,
	.utimens	= encr_utimens,
	.open		= encr_open,
	.read		= encr_read,
	.write		= encr_write,
	.statfs		= encr_statfs,
	.create     = encr_create,
	.release	= encr_release,
	.fsync		= encr_fsync,
	.opendir	= encr_opendir,
#ifdef HAVE_SETXATTR
	.setxattr	= encr_setxattr,
	.getxattr	= encr_getxattr,
	.listxattr	= encr_listxattr,
	.removexattr	= encr_removexattr,
#endif
};

void encr_usage(){
	fprintf(stderr, "Usage: ./pa5-encfs <Key Phrase> <Mirror Directory> <Mount Point>");
	abort();
}

FILE *log_open()
{
    FILE *logfile;
    
    // very first thing, open up the logfile and mark that we got in
    // here.  If we can't open the logfile, we're dead.
    logfile = fopen("bbfs.log", "w");
    if (logfile == NULL) {
	perror("logfile");
	exit(EXIT_FAILURE);
    }
    
    // set logfile to line buffering
    setvbuf(logfile, NULL, _IOLBF, 0);

    return logfile;
}



int main(int argc, char *argv[])
{
	struct encr_state *encr_data; //place to store my private data
	umask(0); //Really not sure what this does.
	
	// bbfs doesn't do any access checking on its own (the comment
    // blocks in fuse.h mention some of the functions that need
    // accesses checked -- but note there are other functions, like
    // chown(), that also need checking!).  Since running bbfs as root
    // will therefore open Metrodome-sized holes in the system
    // security, we'll check if root is trying to mount the filesystem
    // and refuse if it is.  The somewhat smaller hole of an ordinary
    // user doing it with the allow_other flag is still there because
    // I don't want to parse the options string.
    if ((getuid() == 0) || (geteuid() == 0)) {
	fprintf(stderr, "Running BBFS as root opens unnacceptable security holes\n");
	return 1;
    }
    
    // Perform some sanity checking on the command line:  make sure
    // there are enough arguments, and that neither of the last two
    // start with a hyphen (this will break if you actually have a
    // rootpoint or mountpoint whose name starts with a hyphen, but so
    // will a zillion other programs)
    if ((argc < 4) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
		encr_usage();
    encr_data = malloc(sizeof (struct encr_state));
    if(encr_data == NULL){
		perror("Main, malloc error");
		abort();	
	}
	
	// Pull the rootdir out of the argument list and save it in my
    // internal data
    encr_data->rootdir = realpath(argv[argc-2], NULL);
    encr_data->key_phrase = argv[argc-3];
    encr_data->logfile = log_open();
    argv[argc-3] = argv[argc-1]; //Move the mount point to the first arg
    argv[argc-2] = NULL; //Set later args to null
    argv[argc-1] = NULL;
    argc-=2;
    
	
	return fuse_main(argc, argv, &encr_oper, encr_data);
}
