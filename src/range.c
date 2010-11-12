#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "range.h"


static void
_init_first_range(range_t *r);

static int
_split_range(range_t *r, range_item_range_t *ir, range_item_t *prev,
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
range_init_from_ip(range_t *r, int family, ip_addr *first, ip_addr *last)
{
    size_t addr_len = ( family == AF_INET ?
                        sizeof(struct in_addr) :
                        sizeof(struct in6_addr) );

    if ( memcmp(first, last, addr_len) > 0 ) {
        return ERR_BAD_RANGE;
    }

    r->family   = family;
    r->addr_len = addr_len;
    memcpy(&r->first, first, addr_len);
    memcpy(&r->last,  last, addr_len);

    _init_first_range(r);

    return ERR_OK;
}


/*
 * Func: range_init_from_str()
 * Desc: Initializes range using stringified representation of its
 *       first and last bounds (dotted-decimal notation or colon-separated
 *       hexademical words)
 */

int
range_init_from_str(range_t *r, const char *first, const char *last)
{
    int af_first, af_last;

    af_first = GUESS_AF(first);
    af_last  = GUESS_AF(last);

    if (af_first != af_last) {
        return ERR_MIXED_RANGE;
    }
 
    r->family = af_first;
    r->addr_len = (r->family == AF_INET ?
                     sizeof(struct in_addr) :
                      sizeof(struct in6_addr) );

    if ( !inet_pton(af_first, first, &r->first) ) {
        return ERR_UNPARSABLE_ADDR;
    }

    if ( !inet_pton(af_last, last, &r->last) ) {
        return ERR_UNPARSABLE_ADDR;
    }

    if ( memcmp(first, last, r->addr_len) > 0 ) {
        return ERR_BAD_RANGE;
    }

    _init_first_range(r);

    return ERR_OK;
}


/*
 * Func: range_init_from_cidr()
 * Desc: Initializes range using CIDR notation of a network
 */

int
range_init_from_cidr(range_t *r, const char *cidr)
{
    int af, offset, bits;
    char *bitstr;
    unsigned char *p, bt;

    af = GUESS_AF(cidr);

    r->family = af;
    r->addr_len = (af == AF_INET ?
                     sizeof(struct in_addr) :
                     sizeof(struct in6_addr) );

    if ( !(bitstr = strchr(cidr, '/')) ) {
        return ERR_UNPARSABLE_CIDR;
    }
    *bitstr++ = '\x0';

    if ( !inet_pton(af, cidr, &r->first) ) {
        return ERR_UNPARSABLE_CIDR;
    }

    bits = (int) strtol(bitstr, (char **) NULL, 10);

    p = (unsigned char*)&r->last;
    memcpy(p, &r->first, r->addr_len);

    offset = (int)(bits / 8);
    bits = bits % 8;

    bt = 0xff;
    bt >>= bits;

    if (p[offset] & bt) {
        return ERR_UNPARSABLE_CIDR;
    }

    p[offset] |= bt;

    while(++offset < r->addr_len) {
        if (p[offset])
            return ERR_UNPARSABLE_CIDR;
        p[offset] = 0xff;
    }

    _init_first_range(r);

    return ERR_OK;
}


/*
 * Func: range_destroy()
 * Desc: Frees memory, allocated by a range r's internals
 */

void
range_destroy(range_t *r)
{
    range_item_t *pitem, *pnext;

    if (r->items) {
        pitem = r->items->next;
        free(r->items);

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
range_occupy_ip(range_t *r, ip_addr *ip, const char *host)
{
    range_item_t       *pi, *pprev = NULL;
    range_item_range_t *pir;

    if (!r || !r->items)
        return ERR_UNINITIALIZED;
    if ( memcmp(&r->first, ip, r->addr_len)  > 0 )
        return ERR_NOT_IN_RANGE;
    if ( memcmp(&r->last, ip, r->addr_len)  < 0 )
        return ERR_NOT_IN_RANGE;

    pi = r->items;
    while (pi) {
        if (pi->status == STATUS_FREE) {
            pir = (range_item_range_t*)pi;
            if ( memcmp(&pir->last, ip, r->addr_len) >= 0 ) {
                if ( memcmp(&pir->first, ip, r->addr_len) <= 0 ) {
                    return _split_range(r, pir, pprev, ip, host);
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
range_free_ip(range_t *r, ip_addr *ip)
{
    range_item_t       *pi, *pprev = NULL;
    range_item_range_t *new;

    if (!r || !r->items)
        return ERR_UNINITIALIZED;
    if ( memcmp(&r->first, ip, r->addr_len)  > 0 )
        return ERR_NOT_IN_RANGE;
    if ( memcmp(&r->last, ip, r->addr_len)  < 0 )
        return ERR_NOT_IN_RANGE;

    pi = r->items;
    while (pi) {
        if (pi->status == STATUS_FREE) {
            if ( memcmp(&((range_item_range_t*)pi)->last,
                        ip, r->addr_len) >= 0 ) {
                return ERR_NOT_FOUND;
            }

        }
        else {
            if ( !memcmp(&((range_item_ip_t*)pi)->ip, ip, r->addr_len) ) {

                if (pprev && pprev->status == STATUS_FREE) {
                    _inc_address(&((range_item_range_t*)pprev)->last,
                                 r->addr_len);
                    pprev->next = pi->next;
                }
                else if (pi->next &&
                         ((range_item_t*)pi->next)->status == STATUS_FREE) {
                    _dec_address(&((range_item_range_t*)pi->next)->first,
                                 r->addr_len);
                    pprev->next = pi->next;
                }
                else {
                    new = (range_item_range_t*) malloc(sizeof *new);
                    new->status = STATUS_FREE;
                    new->next   = pi->next;
                    memcpy(&new->first, ip, r->addr_len);
                    memcpy(&new->last, ip, r->addr_len);

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
 * Desc: Checks an IP allocation status.
 */

int
range_lookup_ip(range_t *r, ip_addr *ip, range_item_ip_t **res)
{
    range_item_t       *pi;
    range_item_range_t *pir;
    range_item_ip_t    *pip;

    if (!r || !r->items)
        return ERR_UNINITIALIZED;
    if ( memcmp(&r->first, ip, r->addr_len)  > 0 )
        return ERR_NOT_IN_RANGE;
    if ( memcmp(&r->last, ip, r->addr_len)  < 0 )
        return ERR_NOT_IN_RANGE;

    pi = r->items;
    while (pi) {
        if (pi->status == STATUS_FREE) {
            pir = (range_item_range_t*)pi;
            if ( memcmp(&pir->last, ip, r->addr_len) >= 0 ) {
                    *res = NULL;
                    return ERR_OK;
            }

        }
        else {
            pip = (range_item_ip_t*)pi;
            if ( !memcmp(&pip->ip, ip, r->addr_len) ) {
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
range_dump(range_t *r)
{
    range_item_t *item;

    fprintf(stderr, "DBG: range is: ");
    if (r) {
        fprintf(stderr, "{\nDBG:\tfamily => %i\n", r->family);

        fprintf(stderr, "DBG:\tfirst  => ");
        _dump_address(stderr, &r->first, r->addr_len);

        fprintf(stderr, "\nDBG:\tlast   => ");
        _dump_address(stderr, &r->last, r->addr_len);

        fprintf(stderr, "\nDBG:\titems  => [");
        if (r->items) {
            item = r->items;
            while (item) {
                fprintf(stderr, "\nDBG:\t\t%p: {\n", (void*)item);
                if (item->status == STATUS_FREE) {
                    fprintf(stderr, "DBG:\t\t\tfirst => ");
                    _dump_address(stderr,&((range_item_range_t*)item)->first,
                                  r->addr_len);

                    fprintf(stderr, "\nDBG:\t\t\tlast  => ");
                    _dump_address(stderr,&((range_item_range_t*)item)->last,
                                  r->addr_len);
                }
                else {
                    fprintf(stderr, "DBG:\t\t\tip   => ");
                    _dump_address(stderr,&((range_item_ip_t*)item)->ip,
                                  r->addr_len);
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
range_free_addrs_iterator(range_t *r)
{
    range_iterator_t *it = (range_iterator_t*) malloc(sizeof *it);

    it->family = r->family;
    it->type = ITERATOR_FREE;
    it->next = r->items;

    return it;
}


/*
 * Func: range_occupied_addrs_iterator()
 * Desc: Returns iterator to walk through all the occupied addresses
 */

range_iterator_t*
range_occupied_addrs_iterator(range_t *r)
{
    range_iterator_t *it = (range_iterator_t*) malloc(sizeof *it);

    it->family = r->family;
    it->type   = ITERATOR_OCCUPIED;
    it->next   = r->items;

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
_init_first_range(range_t *r)
{
    range_item_range_t *ir;
    size_t addr_len = r->addr_len ?
                          r->addr_len :
                          sizeof(ip_addr);

    ir = (range_item_range_t*) malloc(sizeof *ir);
    ir->next   = NULL;
    ir->status = STATUS_FREE;
    memcpy(&ir->first, &r->first, addr_len);
    memcpy(&ir->last, &r->last, addr_len);

    r->items = (range_item_t*)ir;
}


static int
_split_range(range_t *r, range_item_range_t *ir, range_item_t *prev,
               ip_addr *ip, const char *host)
{
    range_item_ip_t    *new;
    range_item_range_t *new_range;

    /* prepare new item to insert */
    new = (range_item_ip_t*) malloc(sizeof *new);
    new->status = STATUS_OCCUPIED;
    new->host   = strndup(host, (size_t)255);
    memcpy(&new->ip, ip, r->addr_len);

    /*
     * NB: We assume here that an IP is within this range
     * This should be checked before calling range_split_range()
     */

    /* if it's the first address in the range ... */
    if ( !memcmp(&ir->first, ip, r->addr_len) ) {

        /* see if that was the last free ip in this range */
        if ( !memcmp(&ir->first, &ir->last, r->addr_len) ) {
            new->next  = ir->next;
            free(ir);
        }
        else {
            new->next   = (range_item_t*)ir;
            _inc_address(&ir->first, r->addr_len);
        }

        /* insert new ip right before this range */
        if (prev) {
            prev->next = (range_item_t*)new;
        }
        else {
            r->items = (range_item_t*)new;
        }

        return ERR_OK;
    }

    /* if it's the last address in the range ... */
    else if ( !memcmp(&ir->last, ip, r->addr_len) ) {
        new->next = ir->next;
        ir->next = (range_item_t*)new;
        _dec_address(&ir->last, r->addr_len);
        return ERR_OK;
    }

    /* otherwise (somewhere in the middle) */
    else {
        /* prepare new range to insert */
        new_range = (range_item_range_t*) malloc(sizeof *new_range);
        new_range->status = STATUS_FREE;
        new_range->next   = ir->next;
        memcpy(&new_range->first, ip, r->addr_len);
        memcpy(&new_range->last, &ir->last, r->addr_len);

        /* cut this range at the ip */
        memcpy(&ir->last, ip, r->addr_len);

        /* insert new ip and range right after the current one */
        new->next = (range_item_t*)new_range;
        ir->next  = (range_item_t*)new;

        /* exclude the ip from both ranges at left & right */
        _dec_address(&ir->last, r->addr_len);
        _inc_address(&new_range->first, r->addr_len);

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
        p--;
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
        p--;
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

