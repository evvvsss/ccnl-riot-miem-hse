/*
 * Copyright (C) 2015, 2016  INRIA.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_shell_commands
 * @{
 *
 * @file
 * @brief       Shell commands to interact with the CCN-Lite stack
 *
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 *
 * @}
 */

#include <string.h>
#include "ccnl-os-time.h"
#include "ccn-lite-riot.h"
#include "ccnl-pkt-ndntlv.h"
#include "net/gnrc/netif.h"
#include "random.h"
#include "sched.h"
#include "shell.h"
#include "xtimer.h"

//#include "xtimer/tick_conversion.h"
//
//#include "xtimer/implementation.h"
//#include <time.h>
//#include "timex.h"
//#include "ztimer64.h"

#define BUF_SIZE (64)

#define MAX_ADDR_LEN            (GNRC_NETIF_L2ADDR_MAXLEN)

static unsigned char _int_buf[BUF_SIZE];

static unsigned char _out[CCNL_MAX_PACKET_SIZE];

/* usage for open command */
static void _open_usage(void)
{
    puts("ccnl <interface>");
}

static int _ccnl_open(int argc, char **argv)
{
    /* check if already running */
    if (ccnl_relay.ifcount >= CCNL_MAX_INTERFACES) {
        puts("Already opened max. number of interfaces for CCN!");
        return -1;
    }

    /* check if parameter is given */
    if (argc != 2) {
        _open_usage();
        return -1;
    }

    /* check if given number is a valid netif PID */
    int pid = atoi(argv[1]);
    if (gnrc_netif_get_by_pid(pid) == NULL) {
        printf("%i is not a valid interface!\n", pid);
        return -1;
    }

    ccnl_start();

    /* set the relay's PID, configure the interface to interface to use CCN
     * nettype */
    if (ccnl_open_netif(pid, GNRC_NETTYPE_CCN) < 0) {
        puts("Error registering at network interface!");
        return -1;
    }

    return 0;
}

SHELL_COMMAND(ccnl_open, "opens an interface or socket", _ccnl_open);

static void _content_usage(char *argv)
{
    printf("usage: %s [URI] [content]\n"
            "prints the CS if called without parameters:\n"
            "%% %s /riot/peter/schmerzl RIOT\n",
            argv, argv);
}

static int _ccnl_content(int argc, char **argv)
{
    if (argc < 2) {
        ccnl_cs_dump(&ccnl_relay);
        return 0;
    }
    if (argc == 2) {
        _content_usage(argv[0]);
        return -1;
    }


    int arg_len;
    char buf[BUF_SIZE+1]; /* add one extra space to fit trailing '\0' */

    unsigned pos = 0;
    for (int i = 2; (i < argc) && (pos < BUF_SIZE); ++i) {
        arg_len = strlen(argv[i]);
        if ((pos + arg_len) > BUF_SIZE) {
            arg_len = BUF_SIZE - pos;
        }
        strncpy(&buf[pos], argv[i], arg_len);
        pos += arg_len;
        /* increment pos _after_ adding ' ' */
        buf[pos++] = ' ';
    }
    /* decrement pos _before_ to overwrite last ' ' with '\0' */
    buf[--pos] = '\0';

    arg_len = strlen(buf);

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(argv[1], CCNL_SUITE_NDNTLV, NULL);
    size_t offs = CCNL_MAX_PACKET_SIZE;
    size_t reslen = 0;
    arg_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) buf, arg_len, NULL, NULL, &offs, _out, &reslen);

    ccnl_prefix_free(prefix);

    unsigned char *olddata;
    unsigned char *data = olddata = _out + offs;

    size_t len;
    uint64_t typ;

    if (ccnl_ndntlv_dehead(&data, &reslen, &typ, &len) ||
        typ != NDN_TLV_Data) {
        return -1;
    }

    struct ccnl_content_s *c = 0;
    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &reslen);
    c = ccnl_content_new(&pk);
    c->flags |= CCNL_CONTENT_FLAGS_STATIC;
    msg_t m = { .type = CCNL_MSG_CS_ADD, .content.ptr = c };

    if(msg_send(&m, ccnl_event_loop_pid) < 1){
        puts("could not add content");
    }

    return 0;
}

SHELL_COMMAND(ccnl_cs, "shows CS or creates content and populates it",
        _ccnl_content);

static struct ccnl_face_s *_intern_face_get(char *addr_str)
{
    /* initialize address with 0xFF for broadcast */
    uint8_t relay_addr[MAX_ADDR_LEN];
    memset(relay_addr, UINT8_MAX, MAX_ADDR_LEN);
    size_t addr_len = gnrc_netif_addr_from_str(addr_str, relay_addr);

    if (addr_len == 0) {
        printf("Error: %s is not a valid link layer address\n", addr_str);
        return NULL;
    }

    sockunion sun;
    sun.sa.sa_family = AF_PACKET;
    memcpy(&(sun.linklayer.sll_addr), relay_addr, addr_len);
    sun.linklayer.sll_halen = addr_len;
    sun.linklayer.sll_protocol = htons(ETHERTYPE_NDN);

    /* TODO: set correct interface instead of always 0 */
    struct ccnl_face_s *fibface = ccnl_get_face_or_create(&ccnl_relay, 0, &sun.sa, sizeof(sun.linklayer));

    return fibface;
}

static int _intern_fib_add(char *pfx, char *addr_str)
{
    int suite = CCNL_SUITE_NDNTLV;
    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(pfx, suite, NULL);
    if (!prefix) {
        puts("Error: prefix could not be created!");
        return -1;
    }

    struct ccnl_face_s *fibface = _intern_face_get(addr_str);
    if (fibface == NULL) {
        return -1;
    }
    fibface->flags |= CCNL_FACE_FLAGS_STATIC;

    if (ccnl_fib_add_entry(&ccnl_relay, prefix, fibface) != 0) {
        printf("Error adding (%s : %s) to the FIB\n", pfx, addr_str);
        return -1;
    }

    return 0;
}

static void _interest_usage(char *arg)
{
    printf("usage: %s <URI> [relay]\n"
            "%% %s /riot/peter/schmerzl                     (classic lookup)\n",
            arg, arg);
}

static int _ccnl_interest(int argc, char **argv)
{
    if (argc < 2) {
        _interest_usage(argv[0]);
        return -1;
    }

    if (argc > 2) {
        if (_intern_fib_add(argv[1], argv[2]) < 0) {
            _interest_usage(argv[0]);
            return -1;
        }
    }

    memset(_int_buf, '\0', BUF_SIZE);

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(argv[1], CCNL_SUITE_NDNTLV, NULL);
    int res = ccnl_send_interest(prefix, _int_buf, BUF_SIZE, NULL);
    ccnl_prefix_free(prefix);

    return res;
}

SHELL_COMMAND(ccnl_int, "sends an interest", _ccnl_interest);

static void _ccnl_fib_usage(char *argv)
{
    printf("usage: %s [<action> <options>]\n"
           "prints the FIB if called without parameters:\n"
           "%% %s\n"
           "<action> may be one of the following\n"
           "  * \"add\" - adds an entry to the FIB, requires a prefix and a next-hop address, e.g.\n"
           "            %s add /riot/peter/schmerzl ab:cd:ef:01:23:45:67:89\n"
           "  * \"del\" - deletes an entry to the FIB, requires a prefix or a next-hop address, e.g.\n"
           "            %s del /riot/peter/schmerzl\n"
           "            %s del ab:cd:ef:01:23:45:67:89\n",
            argv, argv, argv, argv, argv);
}

static int _ccnl_fib(int argc, char **argv)
{
    if (argc < 2) {
        ccnl_fib_show(&ccnl_relay);
    }
    else if ((argc == 3) && (strncmp(argv[1], "del", 3) == 0)) {
        int suite = CCNL_SUITE_NDNTLV;
        if (strchr(argv[2], '/')) {
            struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(argv[2], suite, NULL);
            if (!prefix) {
                puts("Error: prefix could not be created!");
                return -1;
            }
            int res = ccnl_fib_rem_entry(&ccnl_relay, prefix, NULL);
            ccnl_prefix_free(prefix);
            return res;
        }
        else {
            struct ccnl_face_s *face = _intern_face_get(argv[2]);
            if (face == NULL) {
                printf("There is no face for address %s\n", argv[1]);
                return -1;
            }
            int res = ccnl_fib_rem_entry(&ccnl_relay, NULL, face);
            return res;
        }
    }
    else if ((argc == 4) && (strncmp(argv[1], "add", 3) == 0)) {
        if (_intern_fib_add(argv[2], argv[3]) < 0) {
            _ccnl_fib_usage(argv[0]);
            return -1;
        }
    }
    else {
        _ccnl_fib_usage(argv[0]);
        return -1;
    }
    return 0;
}

SHELL_COMMAND(ccnl_fib, "shows or modifies the CCN-Lite FIB", _ccnl_fib);


static int _fib_copy(int argc, char **argv)
{
    if (argc < 2) {
        ccnl_fib_show(&ccnl_relay);
    }
    else if ((argc == 3) && (strncmp(argv[1], "del", 3) == 0)) {
        int suite = CCNL_SUITE_NDNTLV;
        if (strchr(argv[2], '/')) {
            struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(argv[2], suite, NULL);
            if (!prefix) {
                puts("Error: prefix could not be created!");
                return -1;
            }
            int res = ccnl_fib_rem_entry(&ccnl_relay, prefix, NULL);
            ccnl_prefix_free(prefix);
            return res;
        }
        else {
            struct ccnl_face_s *face = _intern_face_get(argv[2]);
            if (face == NULL) {
                printf("There is no face for address %s\n", argv[1]);
                return -1;
            }
            int res = ccnl_fib_rem_entry(&ccnl_relay, NULL, face);
            return res;
        }
    }
    else if ((argc == 4) && (strncmp(argv[1], "add", 3) == 0)) {
        if (_intern_fib_add(argv[2], argv[3]) < 0) {
            _ccnl_fib_usage(argv[0]);
            return -1;
        }
    }
    else {
        _ccnl_fib_usage(argv[0]);
        return -1;
    }
    return 0;
}

SHELL_COMMAND(fib_copy, "CUSTOM COMMAND FIB", _fib_copy);


static int _custom(int argc, char **argv)
{
    // функция кладет сообщение в нужный URL

    printf("This is printf in  _custom\n");
    puts("this is puts\n");
    argv[0] = "\0"; // команда
    argv[1] = "/folder1/folder2\0";
    argv[2] = "our message\0";
    int arg_len;
    char buf[BUF_SIZE+1]; /* add one extra space to fit trailing '\0' */

    unsigned pos = 0;
    for (int i = 2; (i < argc) && (pos < BUF_SIZE); ++i) {
        arg_len = strlen(argv[i]);
        if ((pos + arg_len) > BUF_SIZE) {
            arg_len = BUF_SIZE - pos;
        }
        strncpy(&buf[pos], argv[i], arg_len);
        pos += arg_len;
        /* increment pos _after_ adding ' ' */
        buf[pos++] = ' ';
    }
    printf("buf: %s", buf);
    /* decrement pos _before_ to overwrite last ' ' with '\0' */
    buf[--pos] = '\0';

    arg_len = strlen(buf);

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(argv[1], CCNL_SUITE_NDNTLV, NULL);
    size_t offs = CCNL_MAX_PACKET_SIZE;
    size_t reslen = 0;
    arg_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) buf, arg_len, NULL, NULL, &offs, _out, &reslen);

    ccnl_prefix_free(prefix);

    unsigned char *olddata;
    unsigned char *data = olddata = _out + offs;

    size_t len;
    uint64_t typ;

    if (ccnl_ndntlv_dehead(&data, &reslen, &typ, &len) ||
        typ != NDN_TLV_Data) {
        return -1;
    }
    printf("typ: %lld", typ);
    struct ccnl_content_s *c = 0;
    // printf("vars666 %lld %s %s %ls", typ, olddata, &data, &reslen);

    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &reslen);

    c = ccnl_content_new(&pk);
    // printf("c12345678 %s", c);
    c->flags |= CCNL_CONTENT_FLAGS_STATIC;
    printf("CCNL_CONTENT_FLAGS_STATIC %d", CCNL_CONTENT_FLAGS_STATIC);
    msg_t m = { .type = CCNL_MSG_CS_ADD, .content.ptr = c };

    if(msg_send(&m, ccnl_event_loop_pid) < 1){
        puts("could not add content");
    }

    return 0;
}

SHELL_COMMAND(custom, "CUSTOM COMMAND FOR CS", _custom);


static void _content_delete_usage(char *argv)
{
    printf("usage: %s [URI] [content]\n"
           "prints the CS if called without parameters:\n"
           "%% %s /riot/peter/schmerzl RIOT\n",
           argv, argv);
}

static int _ccnl_content_delete(int argc, char **argv)
{
    // просто выводим данные cs
    if (argc < 2) {
        ccnl_cs_dump(&ccnl_relay);
        return 0;
    }
    // description
    if (argc == 2) {
        _content_delete_usage(argv[0]);
        return -1;
    }
    puts("Удаление контента по префиксу запущено\n");
    puts("Префикс ");
    printf("%s", argv[1]);
    puts(" \n");
    puts("Сообщение ");
    printf("%s", argv[2]);
    puts(" \n");

    // PIT table
//    struct ccnl_forward_s *fib = ccnl_relay->fib;
//    printf("\n number of cached item");
//    printf("%i",ccnl_relay.contentcnt);
//    struct ccnl_interest_s *pit = ccnl_relay.pit;
//    printf("PIT TABLE INFO");
//    puts("pit lifetime ");
//    printf("%lu",pit->lifetime);
//    puts("\ndata of first pkt in PIT ");
//    printf("%d", pit->pkt->buf->data[1]);
//    puts("\nprefix of first pkt in PIT ");
//    ccnl_prefix_to_str(P, buf, buflen);
    // char *prefix_for_print = ccnl_prefix_to_str(pit->pkt->pfx, (char *)pit->pkt->buf->data,CCNL_MAX_PREFIX_SIZE);
    // printf("suite %s", prefix_for_print->suite);
    int arg_len;
    char buf[BUF_SIZE+1]; /* add one extra space to fit trailing '\0' */

    unsigned pos = 0;
    for (int i = 2; (i < argc) && (pos < BUF_SIZE); ++i) {
        arg_len = strlen(argv[i]);
        if ((pos + arg_len) > BUF_SIZE) {
            arg_len = BUF_SIZE - pos;
        }
        strncpy(&buf[pos], argv[i], arg_len);
        pos += arg_len;
        /* increment pos _after_ adding ' ' */
        buf[pos++] = ' ';
    }
    /* decrement pos _before_ to overwrite last ' ' with '\0' */
    buf[--pos] = '\0';

    arg_len = strlen(buf);

    char *prefix;
    prefix = argv[1];
    ccnl_cs_remove(&ccnl_relay, prefix);

//    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(argv[1], CCNL_SUITE_NDNTLV, NULL);
//    size_t offs = CCNL_MAX_PACKET_SIZE;
//    size_t reslen = 0;
//    arg_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) buf, arg_len, NULL, NULL, &offs, _out, &reslen);
//
//    ccnl_prefix_free(prefix);
//
//    unsigned char *olddata;
//    unsigned char *data = olddata = _out + offs;
//
//    size_t len;
//    uint64_t typ;
//
//    if (ccnl_ndntlv_dehead(&data, &reslen, &typ, &len) ||
//        typ != NDN_TLV_Data) {
//        return -1;
//    }

//    struct ccnl_content_s *c = 0;
//    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &reslen);
//    ccnl_content_free(&pk);
//    c->flags |= CCNL_CONTENT_FLAGS_STATIC;
//    msg_t m = { .type = CCNL_MSG_CS_DEL, .content.ptr = prefix };

//    if(msg_send(&m, ccnl_event_loop_pid) < 1){
//        puts("could not remove content");
//    }
    printf("Success deleted \n");
    return 0;
}

SHELL_COMMAND(ccnl_cs_delete, "shows CS or DELETE content",
_ccnl_content_delete);


static void _content_info_usage(char *argv)
{
    printf("usage: %s [URI] [content]\n"
           "prints the CS if called without parameters:\n"
           "%% %s /riot/peter/schmerzl RIOT\n",
           argv, argv);
}

static int _ccnl_info(int argc, char **argv)
{
    printf("CCNL_NOW() time now %.4g", current_time());
//    printf("CCNL_NOW() time now %.4g", CCNL_NOW());
    // просто выводим данные cs
    if (argc < 2) {
        ccnl_cs_dump(&ccnl_relay);
        return 0;
    }
    // description
    if (argc == 2) {
        _content_info_usage(argv[0]);
        return -1;
    }
    // PIT table
//    struct ccnl_forward_s *fib = ccnl_relay->fib;
    printf("\n number of cached item: ");
    printf("%i \n",ccnl_relay.contentcnt);
    struct ccnl_interest_s *pit = ccnl_relay.pit;
    printf("\nPIT TABLE INFO ");
    puts("pit lifetime: ");
    printf("%lu \n",pit->lifetime);
    puts("\ndata of first pkt in PIT ");
    if (pit->pkt->buf->data[0]) {
    printf("%d", pit->pkt->buf->data[0]);}
    puts("\nprefix of first pkt in PIT ");
//    ccnl_prefix_to_str(P, buf, buflen);
    // char *prefix_for_print = ccnl_prefix_to_str(pit->pkt->pfx,pit->pkt->buf->data,CCNL_MAX_PREFIX_SIZE);

    // printf("suite %d", pit->pkt->pfx->suite);
    int arg_len;
    char buf[BUF_SIZE+1]; /* add one extra space to fit trailing '\0' */

    unsigned pos = 0;
    for (int i = 2; (i < argc) && (pos < BUF_SIZE); ++i) {
        arg_len = strlen(argv[i]);
        if ((pos + arg_len) > BUF_SIZE) {
            arg_len = BUF_SIZE - pos;
        }
        strncpy(&buf[pos], argv[i], arg_len);
        pos += arg_len;
        /* increment pos _after_ adding ' ' */
        buf[pos++] = ' ';
    }
    /* decrement pos _before_ to overwrite last ' ' with '\0' */
    buf[--pos] = '\0';


    return 0;
}

SHELL_COMMAND(ccnl_info, "shows CS or info",
_ccnl_info);



//static void ccnl_run_send_int_usage()
//{
//
//    printf("usage: ccnl_run X. Где X - необязательное число пакетов. Запуск обмена пакетами. \n");
//}

static int ccnl_run_send_int(int argc, char **argv)
{
    int num_of_packages = 20;

    if (argc == 2) {
        num_of_packages = atoi(argv[1]);
    }

    char *random_path_headers[4][1]= {
            {"/riot"},
            {"/miem"},
            {"/hse"},
            {"/ccnlite"}
    };

    //for CS
//    char *random_path_data[4][2] = {
//            {"/riot", "data1"},
//            {"/miem", "data2"},
//            {"/hse", "data3"},
//            {"/ccnllite", "data4"}
//    };
    printf("\nPackages amount is %i\n", num_of_packages);
    printf("Run sending Interest packages\n");
    for(int i=1; i < num_of_packages+1; i++)
    {
        xtimer_usleep(1000000); // 1 sec sleep
        printf("Random_path_header: %s \n", random_path_headers[i % 4][0]);
        _ccnl_interest(2, random_path_headers[i % 4]);
    };
    printf("\nFinish sending Interest packages\n");
    return 0;
}

SHELL_COMMAND(ccnl_run_send_int, "Run sending Interests",
ccnl_run_send_int);


static int ccnl_run_fill_cs(int argc, char **argv)
{
    int num_of_packages = 4;

    if (argc == 2) {
        num_of_packages = atoi(argv[1]);
    }

    //for filling CS
    char *random_path_data[4][2] = {
            {"data1", "/riot"},
            {"data2", "/miem"},
            {"data3", "/hse"},
            {"data4", "/ccnlite"}
    };

    printf("\nPackages amount is %i\n", num_of_packages);
    printf("\nRun filling CS\n");
    for(int i=1; i < num_of_packages+1; i++)
    {
        printf("Random_path_data: %s %s \n", random_path_data[i % 4][0], random_path_data[i % 4][1]);
        _ccnl_content(3, random_path_data[i % 4]);
    };

    //show final CS
    printf("\nFinish filling CS\n");

    _ccnl_content(1, random_path_data[1]);
    return 0;
}

SHELL_COMMAND(ccnl_run_fill_cs, "Run filling Content Storage",
ccnl_run_fill_cs);