#define PERL_NO_GET_CONTEXT

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include "range.h"

#define DECLARE_SELF \
    range_t *self = INT2PTR(range_t *, SvIVX((SV*) SvRV( ST(0) )) )

#define CROAK_NEW_PREFIX "Net::IP::Range::new: "


MODULE = Net::IP::Range    PACKAGE = Net::IP::Range

PROTOTYPES: DISABLE

void
new(class, type, range)
   CODE:
   {
       AV *av;
       SV *self, *range;
       int rc;
       char *CLASS;
       const char *type;
       range_t *r;

       CLASS = SvPV_nolen(ST(0));
       type = SvPV_nolen(ST(1));
       range = ST(2);

       Newx(r, 1, range_t);

       /* binary IPv4/v6 range */
       if ( !strncmp(type, "range", (size_t)5) ) {

           if ((!SvROK(range)) || (SvTYPE(SvRV(range)) != SVt_PVAV)) {
               Safefree(r);
               croak(CROAK_NEW_PREFIX "bad range (not an array ref)");
           }

           av = (AV*)SvRV(range);
           if ( (av_len(av)) != 1 ) {
               Safefree(r);
               croak(CROAK_NEW_PREFIX "bad range ($#range != 2)");
           }

           {
               unsigned char *first, *last;
               STRLEN flen, llen;
               size_t addr_len;
               int family;

               if ( type[5] == '6' ) {
                   family = AF_INET6;
                   addr_len = sizeof(struct in6_addr);
               }
               else {
                   family = AF_INET;
                   addr_len = sizeof(struct in_addr);
               }

               first = (unsigned char*)SvPV((SV*)*(av_fetch(av, 0, 0)), flen);
               last =  (unsigned char*)SvPV((SV*)*(av_fetch(av, 1, 0)), llen);

               if ( flen != addr_len || llen != addr_len ) {
                   Safefree(r);
                   croak(CROAK_NEW_PREFIX "bad range (illegal data)");
               }

               rc = range_init_from_ip(r, family, (ip_addr*)first, (ip_addr*)last);
               if (rc) {
                   Safefree(r);
                   croak(CROAK_NEW_PREFIX "bad range (error #%d)", rc);
               }
           }
       }

       /* stringified IPv4/v6 range */
       else if ( !strcmp(type, "parse") ) {

           if ((!SvROK(range)) || (SvTYPE(SvRV(range)) != SVt_PVAV)) {
               Safefree(r);
               croak(CROAK_NEW_PREFIX "bad range (not an array ref)");
           }

           av = (AV*)SvRV(range);
           if ( (av_len(av)) != 1 ) {
               Safefree(r);
               croak(CROAK_NEW_PREFIX "bad range ($#range != 2)");
           }

           {
               const char *first, *last;

               first = SvPV_nolen((SV*)*(av_fetch(av, 0, 0)));
               last =  SvPV_nolen((SV*)*(av_fetch(av, 1, 0)));

               rc = range_init_from_str(r, first, last);
               if (rc) {
                   Safefree(r);
                   croak(CROAK_NEW_PREFIX "bad range (error #%d)", rc);
               }
           }
       }

       /* CIDR-notation range */
       else if ( !strcmp(type, "cidr") ) {

           if (!SvOK(range)) {
               Safefree(r);
               croak(CROAK_NEW_PREFIX "bad range (undefined)");
           }

           {
               const char *cidr = SvPV_nolen(range);

               rc = range_init_from_cidr(r, cidr);
               if (rc) {
                   Safefree(r);
                   croak(CROAK_NEW_PREFIX "bad range (error #%d)", rc);
               }
           }
       }

       else {        
           Safefree(r);
           croak(CROAK_NEW_PREFIX "Unsupported type '%s'\n", type);
       }

       self = sv_newmortal();
       sv_setref_pv( self, CLASS, (void*)r );

       ST(0) = self;
   }

void
DESTROY(self)
   CODE:
   {
       DECLARE_SELF;
       range_destroy(self);
       Safefree(self);
   }

void
min_addr(self)
   PPCODE:
   {
       DECLARE_SELF;
       mXPUSHs ( sv_setref_pvn ( newSV ( (STRLEN)self->addr_len ),
                                 "Net::IP::Range::Item",
                                 (const char*)&self->first,
                                 (STRLEN)self->addr_len ) );
   }

void
max_addr(self)
   PPCODE:
   {
       DECLARE_SELF;
       mXPUSHs ( sv_setref_pvn ( newSV ( (STRLEN)self->addr_len ),
                                 "Net::IP::Range::Item",
                                 (const char*)&self->last,
                                 (STRLEN)self->addr_len ) );
   }

void
size(self)
   PPCODE:
   {
       // TODO: implement this
       mXPUSHs( newSViv(0) );
   }

void
free_addrs(self)
   PPCODE:
   {
       // TODO: implement this
       mXPUSHs( newSViv(0) );
   }

void
occupy(self, ip, host)
   CODE:
   {
       int rc, af;
       const char *ip, *host;
       ip_addr packed_ip;
       DECLARE_SELF;

       ip   = SvPV_nolen(ST(1));
       host = SvPV_nolen(ST(2));

       if ( !inet_pton(self->family, ip, &packed_ip) ) {
           XSRETURN_UNDEF;
       }

       if ( !(rc = range_occupy_ip(self, &packed_ip, host)) ) {
           XSRETURN_YES;
       }
       else {
 #if DEBUG
           warn("DBG: range_occupy_ip() returned %d\n", rc);
 #endif
           XSRETURN_UNDEF;
       }
   }

void
free(self, ip)
   CODE:
   {
       int rc;
       const char *ip;
       ip_addr packed_ip;
       DECLARE_SELF;

       ip = SvPV_nolen(ST(1));

       if ( !inet_pton(self->family, ip, &packed_ip) ) {
           XSRETURN_UNDEF;
       }

       if ( !(rc = range_free_ip(self, &packed_ip)) ) {
           XSRETURN_YES;
       }
       else {
 #if DEBUG
           warn("DBG: range_free_ip() returned %d\n", rc);
 #endif
           XSRETURN_UNDEF;
       }
   }

void
iterator_free(self)
   CODE:
   {
       SV *iterator;
       range_iterator_t *it;
       DECLARE_SELF;

       it = range_free_addrs_iterator(self);

       iterator = sv_newmortal();
       /* XXX: hm... is this okay? */
       sv_setref_pv( iterator, "Net::IP::Range::Iterator", (void*)it );

       ST(0) = iterator;
   }

void
iterator_occupied(self)
   CODE:
   {
       SV *iterator;
       range_iterator_t *it;
       DECLARE_SELF;

       it = range_occupied_addrs_iterator(self);

       iterator = sv_newmortal();
       /* XXX: hm... is this okay? */
       sv_setref_pv( iterator, "Net::IP::Range::Iterator", (void*)it );

       ST(0) = iterator;
   }

void
lookup(self, ip)
   CODE:
   {
       int rc;
       const char *ip;
       ip_addr packed_ip;
       range_item_ip_t *res;
       STRLEN iplen;
       DECLARE_SELF;

       ip   = SvPV_nolen(ST(1));
       if ( !inet_pton(self->family, ip, &packed_ip) ) {
           XSRETURN_UNDEF;
       }

       if ( !( rc = range_lookup_ip(self, &packed_ip, &res)) ) {
           if (res) {
               ST(0) = newSVpvn(res->host, strlen(res->host));
           }
           else {
               XSRETURN_UNDEF;
           }
       }
       else {
 #if DEBUG
           warn("DBG: range_lookup_ip() returned %d\n", rc);
 #endif
           XSRETURN_UNDEF;
       }
   }

#ifdef DEBUG

void
dump(self)
   CODE:
   {
       DECLARE_SELF;
       range_dump(self);
   }

#endif


MODULE = Net::IP::Range  PACKAGE = Net::IP::Range::Iterator

void
next(self)
   PPCODE:
   {
       int rc;
       char ip_str[INET6_ADDRSTRLEN + 1];
       range_t *r;
       range_item_t *item;
       range_item_ip_t *ii;
       range_item_range_t *ir;

       range_iterator_t   *self =
           INT2PTR(range_iterator_t *, SvIVX((SV*) SvRV( ST(0) )) );

       item = range_iterator_next(self);
       if (!item)
           XSRETURN_UNDEF;


       if (item->status == STATUS_FREE) {
           Newx(r, 1, range_t);
           if (!r) {
               XSRETURN_UNDEF;
           }

           ir = (range_item_range_t*) item;
           rc = range_init_from_ip(r, self->family, &ir->first, &ir->last);
           if (rc) {
               Safefree(r);
               XSRETURN_UNDEF;
           }

           mXPUSHs ( sv_setref_pv ( newSV(0),
                                    "Net::IP::Range",
                                    (void*) r ) );
       }
       else {
           STRLEN addr_len = (self->family == AF_INET ?
                      sizeof(struct in_addr) :
                      sizeof(struct in6_addr) );

           ii = (range_item_ip_t*) item;
           mXPUSHs ( sv_setref_pvn ( newSV (addr_len),
                                     "Net::IP::Range::Item",
                                     (const char*) &ii->ip,
                                     addr_len ) );
           mXPUSHs ( newSVpvn(ii->host, strlen(ii->host)) );
       }
   }


MODULE = Net::IP::Range  PACKAGE = Net::IP::Range::Item

void
unpacked(self)
   CODE:
   {
       int    i;
       char   *data;
       char   buf[33];
       STRLEN len;
       SV     *self = ST(0);

       data = SvPV(SvRV(self), len);
       for (i=0; i<len; i++) {
           sprintf( &(buf[2*i]), "%02hhx", (char)data[i] );
       }
       buf[len*2] = '\x0';

       ST(0) = sv_2mortal( newSVpvn(buf, strlen(buf)) );
   }
