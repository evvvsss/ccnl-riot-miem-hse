/*
 * @f ccnl-defs.h
 * @b header file with constants for CCN lite (CCNL)
 *
 * Copyright (C) 2011-14, Christian Tschudin, University of Basel
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * File history:
 * 2011-03-30 created
 */

#ifndef CCNL_DEFS_H
#define CCNL_DEFS_H

#define CCNL_VERSION "2015-07-07"

#define ETHTYPE_XEROX_PUP               0x0a00
#define ETHTYPE_PARC_CCNX               0x0801

#define CCNL_ETH_TYPE                   ETHTYPE_PARC_CCNX
//#define CCNL_ETH_TYPE                 0x88b5

#define CCNL_DEFAULT_UNIXSOCKNAME       "/tmp/.ccnl.sock"

/* assuming that all broadcast addresses consist of a sequence of equal octets */
#define CCNL_BROADCAST_OCTET            0xFF

#if defined(CCNL_ARDUINO) || defined(CCNL_RIOT)
# define CCNL_MAX_INTERFACES             1
# define CCNL_MAX_IF_QLEN                14
#ifndef CCNL_MAX_PACKET_SIZE
# define CCNL_MAX_PACKET_SIZE            120
#endif
#ifndef CCNL_MAX_PREFIX_SIZE
# define CCNL_MAX_PREFIX_SIZE            50
#endif
# define CCNL_MAX_ADDRESS_LEN            8
# define CCNL_MAX_NAME_COMP              8
#ifndef CCNL_DEFAULT_MAX_PIT_ENTRIES
# define CCNL_DEFAULT_MAX_PIT_ENTRIES    20
#endif
#elif defined(CCNL_ANDROID) // max of BTLE and 2xUDP
# define CCNL_MAX_INTERFACES             3
# define CCNL_MAX_IF_QLEN                10
# define CCNL_MAX_PACKET_SIZE            4096
# define CCNL_MAX_ADDRESS_LEN            6
# define CCNL_MAX_NAME_COMP              16
# define CCNL_DEFAULT_MAX_PIT_ENTRIES    100
# define CCNL_MAX_PREFIX_SIZE            2048
#else
# define CCNL_MAX_INTERFACES             10
# define CCNL_MAX_IF_QLEN                64
# define CCNL_MAX_PACKET_SIZE            8096
# define CCNL_MAX_ADDRESS_LEN            6
# define CCNL_MAX_NAME_COMP              64
# define CCNL_MAX_PREFIX_SIZE            2048
# define CCNL_DEFAULT_MAX_PIT_ENTRIES    (-1)
#endif

#ifndef CCNL_CONTENT_TIMEOUT
# define CCNL_CONTENT_TIMEOUT            0 // sec Все проходящие сообщения в кэше не остаются. Но в CS созданном лежат
//# define CCNL_CONTENT_TIMEOUT            300 // sec
#endif
#ifndef CCNL_INTEREST_TIMEOUT
# define CCNL_INTEREST_TIMEOUT           10  // sec
#endif
#ifndef CCNL_MAX_INTEREST_RETRANSMIT
# define CCNL_MAX_INTEREST_RETRANSMIT    7
#endif

#ifndef CCNL_FACE_TIMEOUT
// # define CCNL_FACE_TIMEOUT    60 // sec
# define CCNL_FACE_TIMEOUT       30 // sec
#endif

#define CCNL_DEFAULT_MAX_CACHE_ENTRIES  0   // means: no content caching
#ifdef CCNL_RIOT
#define CCNL_MAX_NONCES                 -1 // -1 --> detect dups by PIT
#else //!CCNL_RIOT
#define CCNL_MAX_NONCES                 256 // for detected dups
#endif //CCNL_RIOT

enum {
#ifdef USE_SUITE_CCNB
  CCNL_SUITE_CCNB = 1,
#endif
#ifdef USE_SUITE_CCNTLV
  CCNL_SUITE_CCNTLV = 2,
#endif
#ifdef USE_SUITE_LOCALRPC
  CCNL_SUITE_LOCALRPC = 5,
#endif
#ifdef USE_SUITE_NDNTLV
  CCNL_SUITE_NDNTLV = 6,
#endif
  CCNL_SUITE_LAST = 7
};

#define CCNL_SUITE_DEFAULT (CCNL_SUITE_LAST - 1)

// ----------------------------------------------------------------------
// our own packet format extension for switching encodings:
// 0x80 followed by:
// (add new encodings at the end)

/**
 * @brief Provides an (internal) mapping to the supported packet types
 *
 * Note: Previous versions of CCN-lite supported Cisco's IOT packet format
 * which has since be removed. In previous versions, this enum had a 
 * member CCNL_ENC_IOT2014 (with an implictly assigned value of 3).
 */
typedef enum ccnl_enc_e {
  CCNL_ENC_CCNB,     /**< encoding for CCN */
  CCNL_ENC_NDN2013,  /**< NDN encoding (version 2013) */
  CCNL_ENC_CCNX2014, /**< CCNx encoding (version 2014) */
  CCNL_ENC_LOCALRPC  /**< encoding type for local rpc mechanism */
} ccnl_enc;

// ----------------------------------------------------------------------
// our own CCN-lite extensions for the ccnb encoding:

// management protocol: (ccnl-ext-mgmt.c)
#define CCNL_DTAG_MACSRC        99001 // newface: which L2 interface
#define CCNL_DTAG_IP4SRC        99002 // newface: which L3 interface
#define CCNL_DTAG_IP6SRC        99003 // newface: which L3 interface
#define CCNL_DTAG_UNIXSRC       99004 // newface: which UNIX path
#define CCNL_DTAG_FRAG          99005 // fragmentation protocol, see core.h
#define CCNL_DTAG_FACEFLAGS     99006 //
#define CCNL_DTAG_DEVINSTANCE   99007 // adding/removing a device/interface
#define CCNL_DTAG_DEVNAME       99008 // name of interface (eth0, wlan0)
#define CCNL_DTAG_DEVFLAGS      99009 //
#define CCNL_DTAG_MTU           99010 //
#define CCNL_DTAG_WPANADR       99011 // newface: WPAN 
#define CCNL_DTAG_WPANPANID     99012 // newface: WPAN 

#define CCNL_DTAG_DEBUGREQUEST  99100 //
#define CCNL_DTAG_DEBUGACTION   99101 // dump, halt, dump+halt

//FOR THE DEBUG_REPLY MSG
#define CCNL_DTAG_DEBUGREPLY    99201 // dump reply
#define CCNL_DTAG_INTERFACE     99202 // interface list
#define CCNL_DTAG_NEXT          99203 // next pointer e.g. for faceinstance
#define CCNL_DTAG_PREV          99204 // prev pointer e.g. for faceinstance
#define CCNL_DTAG_IFNDX         99205
#define CCNL_DTAG_IP            99206
#define CCNL_DTAG_ETH           99207
#define CCNL_DTAG_UNIX          99208
#define CCNL_DTAG_PEER          99209
#define CCNL_DTAG_FWD           99210
#define CCNL_DTAG_FACE          99211
#define CCNL_DTAG_ADDRESS       99212
#define CCNL_DTAG_SOCK          99213
#define CCNL_DTAG_REFLECT       99214
#define CCNL_DTAG_PREFIX        99215
#define CCNL_DTAG_INTERESTPTR   99216
#define CCNL_DTAG_LAST          99217
#define CCNL_DTAG_MIN           99218
#define CCNL_DTAG_MAX           99219
#define CCNL_DTAG_RETRIES       99220
#define CCNL_DTAG_PUBLISHER     99221
#define CCNL_DTAG_CONTENTPTR    99222
#define CCNL_DTAG_LASTUSE       99223
#define CCNL_DTAG_SERVEDCTN     99224
#define CCNL_DTAG_VERIFIED      99225
#define CCNL_DTAG_CALLBACK      99226
#define CCNL_DTAG_SUITE         99300
#define CCNL_DTAG_COMPLENGTH    99301
#define CCNL_DTAG_CHUNKNUM      99302
#define CCNL_DTAG_CHUNKFLAG     99303


// ----------------------------------------------------------------------
// fragmentation protocol: (ccnl-ext-frag.c, FRAG_SEQUENCED2012)
#define CCNL_DTAG_FRAGMENT2012  144144 // http://redmine.ccnx.org/issues/100803

#define CCNL_DTAG_FRAG2012_TYPE         (CCNL_DTAG_FRAGMENT2012+1)
#define CCNL_DTAG_FRAG2012_FLAGS        (CCNL_DTAG_FRAGMENT2012+2)
#define CCNL_DTAG_FRAG2012_SEQNR        (CCNL_DTAG_FRAGMENT2012+3)  // our seq number

#define CCNL_DTAG_FRAG2012_OLOSS        (CCNL_DTAG_FRAGMENT2012+5)  // our loss count
#define CCNL_DTAG_FRAG2012_YSEQN        (CCNL_DTAG_FRAGMENT2012+6)  // your (highest) seq no

// fragmentation protocol: (ccnl-ext-frag.c, FRAG_CCNx2013)
#define CCNL_DTAG_FRAGMENT2013          CCN_DTAG_FragP // requested 2013-07-24, assigned 2013-08-12

#define CCNL_DTAG_FRAG2013_TYPE         CCN_DTAG_FragA
#define CCNL_DTAG_FRAG2013_SEQNR        CCN_DTAG_FragB  // our seq number
#define CCNL_DTAG_FRAG2013_FLAGS        CCN_DTAG_FragC

#define CCNL_DTAG_FRAG2013_OLOSS        CCNL_DTAG_FRAG2012_OLOSS  // our loss count
#define CCNL_DTAG_FRAG2013_YSEQN        CCNL_DTAG_FRAG2012_YSEQN  // your (highest) seq no


#define CCNL_DTAG_FRAG_FLAG_MASK        0x03
#define CCNL_DTAG_FRAG_FLAG_FIRST       0x01
#define CCNL_DTAG_FRAG_FLAG_MID         0x00
#define CCNL_DTAG_FRAG_FLAG_LAST        0x02
#define CCNL_DTAG_FRAG_FLAG_SINGLE      0x03

// echo "FHBH" | base64 -d | hexdump -v -e '/1 "@x%02x"'| tr @ '\\'; echo
#define CCNL_FRAG_TYPE_CCNx2013_VAL     "\x14\x70\x47"

// ----------------------------------------------------------------------
// face mgmt protocol:
#define CCNL_DTAG_FRAG_FLAG_STATUSREQ   0x04

// ----------------------------------------------------------------------
// begin-end fragmentation protocol:
#define CCNL_BEFRAG_FLAG_MASK        0x03
#define CCNL_BEFRAG_FLAG_FIRST       0x01
#define CCNL_BEFRAG_FLAG_MID         0x00
#define CCNL_BEFRAG_FLAG_LAST        0x02
#define CCNL_BEFRAG_FLAG_SINGLE      0x03

//#define USE_SIGNATURES


#define EXACT_MATCH 1
#define PREFIX_MATCH 0

#define CMP_EXACT   0 // used to compare interests among themselves
#define CMP_MATCH   1 // used to match interest and content
#define CMP_LONGEST 2 // used to lookup the FIB

#define CCNL_FACE_FLAGS_STATIC  1
#define CCNL_FACE_FLAGS_REFLECT 2
#define CCNL_FACE_FLAGS_SERVED  4
#define CCNL_FACE_FLAGS_FWDALLI 8 // forward all interests, also known ones

#define CCNL_FRAG_NONE          0
#define CCNL_FRAG_SEQUENCED2012 1
#define CCNL_FRAG_CCNx2013      2
#define CCNL_FRAG_SEQUENCED2015 3
#define CCNL_FRAG_BEGINEND2015  4

#if defined(CCNL_RIOT) || defined(USE_WPAN)
#define CCNL_LLADDR_STR_MAX_LEN    (3 * 8)
#else
/* unless a platform supports a link layer with longer addresses than Ethernet,
 * 6 is enough */
#define CCNL_LLADDR_STR_MAX_LEN    (3 * 6)
#endif
// ----------------------------------------------------------------------


#ifdef USE_CCNxDIGEST
#  define compute_ccnx_digest(buf) SHA256(buf->data, buf->datalen, NULL)
#else
#  define compute_ccnx_digest(b) NULL
#endif

#endif //CCNL_DEFS_H

//define true / false
#define true 1
#define false 0


// eof
