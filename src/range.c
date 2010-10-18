#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "range.h"


static void
_init_first_range(range_t *map);

static int
_split_range(range_t *map, range_item_range_t *ir, range_item_t *prev,
               ip_addr *ip, const char *host);

static int
_inc_address(ip_addr *ip, size_t addr_len);

static int
_dec_address(ip_addr *ip, size_t addr_len);

static void
_dump_address(FILE *stream, ip_addr *ip, size_t addr_len);


/*
 * Func: range_init_from_ip()
 * Desc: Initializes range using binary representation (as it's stored in
 *       in_addr, in network byte order) of its first and last bounds.
 */
 
int
range_init_from_ip(range_t *map, int family, ip_addr *first, ip_addr *last)
{
    size_t addr_len = ( family == AF_INET ?
                        sizeof(struct in_addr) :
                        sizeof(struct in6_addr) );

    if ( memcmp(first, last, addr_len) > 0 ) {
        return ERR_BAD_RANGE;
    }

    map->family   = family;
    map->addr_len = addr_len;
    memcpy(&map->first, first, addr_len);
    memcpy(&map->last,  last, addr_len);

    _init_first_range(map);

    return ERR_OK;
}


/*
 * Func: range_init_from_str()
 * Desc: Initializes range using stringified representation of its
 *       first and last bounds (dotted-decimal notation or colon-separated
 *       hexademical words)
 */

int
range_init_from_str(range_t *map, const char *first, const char *last)
{
    int af_first, af_last;

    af_first = (strchr(first, ':')) ? AF_INET6 : AF_INET;
    af_last  = (strchr(last, ':')) ? AF_INET6 : AF_INET;

    if (af_first != af_last) {
        return ERR_MIXED_RANGE;
    }
 
    map->family = af_first;
    map->addr_len = (map->family == AF_INET ?
                     sizeof(struct in_addr) :
                      sizeof(struct in6_addr) );

    if ( !inet_pton(af_first, first, &map->first) ) {
        return ERR_UNPARSABLE_ADDR;
    }

    if ( !inet_pton(af_last, last, &map->last) ) {
        return ERR_UNPARSABLE_ADDR;
    }

    if ( memcmp(first, last, map->addr_len) > 0 ) {
        return ERR_BAD_RANGE;
    }

    _init_first_range(map);

    return ERR_OK;
}


/*
 * Func: range_init_from_cidr()
 * Desc: Initializes range using CIDR notation of a network
 */

int
range_init_from_cidr(range_t *map, const char *cidr)
{
    int af, offset;
    size_t bits;
    unsigned char *p, bt;

    af = (strchr(cidr, ':')) ? AF_INET6 : AF_INET;

    map->family = af;
    map->addr_len = (af == AF_INET ?
                     sizeof(struct in_addr) :
                     sizeof(struct in6_addr) );

    bits = inet_net_pton(af, cidr, &map->first, map->addr_len);
    if (bits == -1) {
        return ERR_UNPARSABLE_CIDR;
    }

    p = (unsigned char*)&map->last;
    memcpy(p, &map->first, map->addr_len);

    offset = (int)(bits / 8);
    bits = bits % 8;

    bt = 0xff;
    bt >>= bits;
    p[offset] |= bt;

    while(++offset < map->addr_len) {
        p[offset] = 0xff;
    }

    _init_first_range(map);

    return ERR_OK;
}


/*
 * Func: range_destroy()
 * Desc: Frees memory, allocated by a range map's internals
 */

void
range_destroy(range_t *map)
{
    range_item_t *pitem, *pnext;

    if (map->items) {
        pitem = map->items->next;
        free(map->items);

        while (pitem) {
            pnext = pitem->next;
            if (pitem->status == STATUS_OCCUPIED) {
                free( ((range_item_ip_t*)pitem)->host );
            }
            free(pitem);
            pitem = pnext;
        }
    }
}


/*
 * Func: range_occupy_ip()
 * Desc: Marks an IP address as occupied by the specified host
 */

int
range_occupy_ip(range_t *map, ip_addr *ip, const char *host)
{
    range_item_t       *pi, *pprev = NULL;
    range_item_range_t *pir;

    if (!map || !map->items)
        return ERR_UNINITIALIZED;
    if ( memcmp(&map->first, ip, map->addr_len)  > 0 )
        return ERR_NOT_IN_RANGE;
    if ( memcmp(&map->last, ip, map->addr_len)  < 0 )
        return ERR_NOT_IN_RANGE;

    pi = map->items;
    while (pi) {
        if (pi->status == STATUS_FREE) {
            pir = (range_item_range_t*)pi;
            if ( memcmp(&pir->last, ip, map->addr_len) >= 0 ) {
                if ( memcmp(&pir->first, ip, map->addr_len) <= 0 ) {
                    return _split_range(map, pir, pprev, ip, host);
                }
                else {
                    return ERR_OCCUPIED;
                }
            }

        }

        pprev = pi;
        pi    = pi->next;
    }

    return ERR_NOT_IN_RANGE;
}


/*
 * Func: range_free_ip()
 * Desc: Frees an IP
 */

int
range_free_ip(range_t *map, ip_addr *ip)
{
    range_item_t       *pi, *pprev = NULL;
    range_item_range_t *new;

    if (!map || !map->items)
        return ERR_UNINITIALIZED;
    if ( memcmp(&map->first, ip, map->addr_len)  > 0 )
        return ERR_NOT_IN_RANGE;
    if ( memcmp(&map->last, ip, map->addr_len)  < 0 )
        return ERR_NOT_IN_RANGE;

    pi = map->items;
    while (pi) {
        if (pi->status == STATUS_FREE) {
            if ( memcmp(&((range_item_range_t*)pi)->last,
                        ip, map->addr_len) >= 0 ) {
                return ERR_NOT_FOUND;
            }

        }
        else {
            if ( !memcmp(&((range_item_ip_t*)pi)->ip, ip, map->addr_len) ) {

                if (pprev && pprev->status == STATUS_FREE) {
                    _inc_address(&((range_item_range_t*)pprev)->last,
                                 map->addr_len);
                    pprev->next = pi->next;
                }
                else if (pi->next &&
                         ((range_item_t*)pi->next)->status == STATUS_FREE) {
                    _dec_address(&((range_item_range_t*)pi->next)->first,
                                 map->addr_len);
                    pprev->next = pi->next;
                }
                else {
                    new = (range_item_range_t*) malloc(sizeof *new);
                    new->status = STATUS_FREE;
                    new->next   = pi->next;
                    memcpy(&new->first, ip, map->addr_len);
                    memcpy(&new->last, ip, map->addr_len);

                    pprev->next = new;
                }

                free( ((range_item_ip_t*)pi)->host );
                free(pi);
                return ERR_OK;
            }
        }

        pprev = pi;
        pi    = pi->next;
    }

    return ERR_NOT_IN_RANGE;

}


/*
 * Func: range_lookup_ip()
 * Desc: Looks up an IP in the map.
 */

int
range_lookup_ip(range_t *map, ip_addr *ip, range_item_ip_t **res)
{
    range_item_t       *pi;
    range_item_range_t *pir;
    range_item_ip_t    *pip;

    if (!map || !map->items)
        return ERR_UNINITIALIZED;
    if ( memcmp(&map->first, ip, map->addr_len)  > 0 )
        return ERR_NOT_IN_RANGE;
    if ( memcmp(&map->last, ip, map->addr_len)  < 0 )
        return ERR_NOT_IN_RANGE;

    pi = map->items;
    while (pi) {
        if (pi->status == STATUS_FREE) {
            pir = (range_item_range_t*)pi;
            if ( memcmp(&pir->last, ip, map->addr_len) >= 0 ) {
                    *res = NULL;
                    return ERR_OK;
            }

        }
        else {
            pip = (range_item_ip_t*)pi;
            if ( !memcmp(&pip->ip, ip, map->addr_len) ) {
                *res = pip;
                return ERR_OK;
            }
        }

        pi = pi->next;
    }

    return ERR_NOT_IN_RANGE;
}


#ifdef DEBUG

/*
 * Func: range_dump()
 * Desc: Dumps all the range structs into the STDERR
 */

void
range_dump(range_t *map)
{
    range_item_t *item;

    fprintf(stderr, "DBG: range is: ");
    if (map) {
        fprintf(stderr, "{\nDBG:\tfamily => %i\n", map->family);

        fprintf(stderr, "DBG:\tfirst  => ");
        _dump_address(stderr, &map->first, map->addr_len);

        fprintf(stderr, "\nDBG:\tlast   => ");
        _dump_address(stderr, &map->last, map->addr_len);

        fprintf(stderr, "\nDBG:\titems  => [");
        if (map->items) {
            item = map->items;
            while (item) {
                fprintf(stderr, "\nDBG:\t\t%p: {\n", (void*)item);
                if (item->status == STATUS_FREE) {
                    fprintf(stderr, "DBG:\t\t\tfirst => ");
                    _dump_address(stderr,&((range_item_range_t*)item)->first,
                                  map->addr_len);

                    fprintf(stderr, "\nDBG:\t\t\tlast  => ");
                    _dump_address(stderr,&((range_item_range_t*)item)->last,
                                  map->addr_len);
                }
                else {
                    fprintf(stderr, "DBG:\t\t\tip   => ");
                    _dump_address(stderr,&((range_item_ip_t*)item)->ip,
                                  map->addr_len);
                    fprintf(stderr, "\nDBG:\t\t\thost   => %s",
                            ((range_item_ip_t*)item)->host);
                }
                fprintf(stderr, "\nDBG:\t\t\tnext  => %p\nDBG:\t\t},",
                        item->next);
                item = item->next;
            }
            fprintf(stderr, "\nDBG: ");
        }
        fprintf(stderr, "\t]\n");
        fprintf(stderr, "DBG: }\n");
    }
    else {
        fprintf(stderr, "NULL\n");
    }
}

#endif // defined DEBUG

/*
 * Func: range_free_addrs_iterator()
 * Desc: Returns iterator to walk through all the free addresses
 */

range_iterator_t*
range_free_addrs_iterator(range_t *map)
{
    range_iterator_t *it = (range_iterator_t*) malloc(sizeof *it);

    it->family = map->family;
    it->type = ITERATOR_FREE;
    it->next = map->items;

    return it;
}


/*
 * Func: range_occupied_addrs_iterator()
 * Desc: Returns iterator to walk through all the occupied addresses
 */

range_iterator_t*
range_occupied_addrs_iterator(range_t *map)
{
    range_iterator_t *it = (range_iterator_t*) malloc(sizeof *it);

    it->family = map->family;
    it->type   = ITERATOR_OCCUPIED;
    it->next   = map->items;

    return it;
}

/*
 * Func: range_iterator_next()
 * Desc: Returns next available item from an iterator or NULL if none
 */

range_item_t*
range_iterator_next(range_iterator_t *it)
{
    range_item_t *item;

    while (it->next && it->type != ((range_item_t*)it->next)->status) {
        it->next = ((range_item_t*)it->next)->next;
    }
    item = it->next;
    if (item)
        it->next = item->next;

    return item;
}


/*
 * Func: range_iterator_destroy()
 * Desc: Returns next available item from an iterator or NULL if none
 */

void
range_iterator_destroy(range_iterator_t *it)
{
    free(it);
}


/*
 * Misc helper-functions...
 */

static void
_init_first_range(range_t *map)
{
    range_item_range_t *r;
    size_t addr_len = map->addr_len ?
                          map->addr_len :
                          sizeof(ip_addr);

    r = (range_item_range_t*) malloc(sizeof *r);
    r->next   = NULL;
    r->status = STATUS_FREE;
    memcpy(&r->first, &map->first, addr_len);
    memcpy(&r->last, &map->last, addr_len);

    map->items = (range_item_t*)r;
}


static int
_split_range(range_t *map, range_item_range_t *ir, range_item_t *prev,
               ip_addr *ip, const char *host)
{
    range_item_ip_t    *new;
    range_item_range_t *new_range;

    /* prepare new item to insert */
    new = (range_item_ip_t*) malloc(sizeof *new);
    new->status = STATUS_OCCUPIED;
    new->host   = strndup(host, (size_t)255);
    memcpy(&new->ip, ip, map->addr_len);

    /*
     * NB: We assume here that an IP is within this range
     * This should be checked before calling range_split_range()
     */

    /* if it's the first address in the range ... */
    if ( !memcmp(&ir->first, ip, map->addr_len) ) {

        /* see if that was the last free ip in this range */
        if ( !memcmp(&ir->first, &ir->last, map->addr_len) ) {
            new->next  = ir->next;
            free(ir);
        }
        else {
            new->next   = (range_item_t*)ir;
            _inc_address(&ir->first, map->addr_len);
        }

        /* insert new ip right before this range */
        if (prev) {
            prev->next = (range_item_t*)new;
        }
        else {
            map->items = (range_item_t*)new;
        }

        return ERR_OK;
    }

    /* if it's the last address in the range ... */
    else if ( !memcmp(&ir->last, ip, map->addr_len) ) {
        new->next = ir->next;
        ir->next = (range_item_t*)new;
        _dec_address(&ir->last, map->addr_len);
        return ERR_OK;
    }

    /* otherwise (somewhere in the middle) */
    else {
        /* prepare new range to insert */
        new_range = (range_item_range_t*) malloc(sizeof *new_range);
        new_range->status = STATUS_FREE;
        new_range->next   = ir->next;
        memcpy(&new_range->first, ip, map->addr_len);
        memcpy(&new_range->last, &ir->last, map->addr_len);

        /* cut this range at the ip */
        memcpy(&ir->last, ip, map->addr_len);

        /* insert new ip and range right after the current one */
        new->next = (range_item_t*)new_range;
        ir->next  = (range_item_t*)new;

        /* exclude the ip from both ranges at left & right */
        _dec_address(&ir->last, map->addr_len);
        _inc_address(&new_range->first, map->addr_len);

        return ERR_OK;
    }

}


static int
_inc_address(ip_addr *ip, size_t addr_len)
{
    int i_ok = 0;
    unsigned char *p = (unsigned char*)ip + (addr_len - 1); // the last byte

    while (p >= (unsigned char*)ip) {
        if (*p != 255) {
            (*p)++;
            i_ok = 1;
            break;
        }

        *p = 0;
    }

    return i_ok ? ERR_OK : ERR_OVERFLOW;
}


static int
_dec_address(ip_addr *ip, size_t addr_len)
{
    int i_ok = 0;
    unsigned char *p = (unsigned char*)ip + (addr_len - 1); // the last byte

    while (p >= (unsigned char*)ip) {
        if (*p) {
            (*p)--;
            i_ok = 1;
            break;
        }

        *p = 255;
    }

    return i_ok ? ERR_OK : ERR_OVERFLOW;
}


static void
_dump_address(FILE *stream, ip_addr *ip, size_t addr_len)
{
    int i;
    unsigned char *p = (unsigned char*) ip;

    for(i=0; i < addr_len; i++) {
        fprintf(stream, "%02x", (unsigned char)*p++);
    }
}

