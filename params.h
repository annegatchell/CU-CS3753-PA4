/*
 * Written by Anne Gatchell
 * For Programming Assignment 4 
 * in CSCI 3753 Operating Systems
 * 
 * Inspired by the work from the tutorial for
 * Big Brother File System
 * Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>
*/

//#ifndef _PARAMS_H_
//#define _PARAMS_H_

struct encr_state{
	char *rootdir;
	char *key_phrase;
};
#define ENCR_DATA ((struct encr_state *) fuse_get_context()->private_data)

//#endif
