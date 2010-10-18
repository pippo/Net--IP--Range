#ifndef __RANGE_H
#define __RANGE_H

#include <netinet/in.h>


/*******************************************
 * Types
 ******************************************/

typedef struct in6_addr ip_addr;

typedef struct {
    unsigned char   status;
    void *next;
} range_item_t;

typedef struct {
    unsigned char    status;
    range_item_t *next;
    ip_addr          first;
    ip_addr          last;
} range_item_range_t;

typedef struct {
    unsigned char    status;
    range_item_t *next;
    ip_addr          ip;
    char            *host;
} range_item_ip_t;

typedef struct {
    int              family;
    size_t           addr_len;
    ip_addr          first;
    ip_addr          last;
    range_item_t *items;
} range_t;

typedef struct {
    int              family;
    unsigned char    type;
    range_item_t *next;
} range_iterator_t;


/*
 * The following enumerates possible address/range statuses
 */

enum {
    STATUS_FREE,
    STATUS_OCCUPIED
};

/*
 * The following enumerates iterator types
 */

enum {
    ITERATOR_FREE,
    ITERATOR_OCCUPIED
};

/*
 * The following enumerates all the error codes
 */

enum {
    ERR_OK=0,
    ERR_BAD_RANGE,
    ERR_MIXED_RANGE,
    ERR_UNPARSABLE_ADDR,
    ERR_UNPARSABLE_CIDR,
    ERR_UNINITIALIZED,
    ERR_NOT_IN_RANGE,
    ERR_OVERFLOW,
    ERR_OCCUPIED,
    ERR_BUFFER_FULL,
    ERR_NOT_FOUND
};

/*******************************************
 * Interface functions
 ******************************************/

int
range_init_from_ip(range_t *map, int family, ip_addr *first, ip_addr *last);

int
range_init_from_str(range_t *map, const char *first, const char *last);

int
range_init_from_cidr(range_t *map, const char *cidr);

void
range_destroy(range_t *map);

int
range_occupy_ip(range_t *map, ip_addr *ip, const char *host);

int
range_free_ip(range_t *map, ip_addr *ip);

int
range_lookup_ip(range_t *map, ip_addr *ip, range_item_ip_t **res);

#ifdef DEBUG
void
range_dump(range_t *map);
#endif

range_iterator_t*
range_free_addrs_iterator(range_t *map);

range_iterator_t*
range_occupied_addrs_iterator(range_t *map);

range_item_t*
range_iterator_next(range_iterator_t *it);

void
range_iterator_destroy(range_iterator_t *it);


#endif // defined __RANGE_H
