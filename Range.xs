#define PERL_NO_GET_CONTEXT

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include "range.h"

#define DECLARE_SELF \
    range_t *self = INT2PTR(range_t *, SvIVX((SV*) SvRV( ST(0) )) )

#define CROAK_NEW_PREFIX "Net::IP::Range::new: "
#define XS_DEBUG 1


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
       range_t *map;

       CLASS = SvPV_nolen(ST(0));
       type = SvPV_nolen(ST(1));
       range = ST(2);

       Newx( map, 1, range_t );

       /* binary IPv4/v6 range */
       if ( !strncmp(type, "range", (size_t)5) ) {

           if ((!SvROK(range)) || (SvTYPE(SvRV(range)) != SVt_PVAV)) {
               Safefree(map);
               croak(CROAK_NEW_PREFIX "bad range (not an array ref)");
           }

           av = (AV*)SvRV(range);
           if ( (av_len(av)) != 1 ) {
               Safefree(map);
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
                   Safefree(map);
                   croak(CROAK_NEW_PREFIX "bad range (illegal data)");
               }

               rc = range_init_from_ip(map, family, (ip_addr*)first, (ip_addr*)last);
               if (rc) {
                   Safefree(map);
                   croak(CROAK_NEW_PREFIX "bad range (error #%d)", rc);
               }
           }
       }

       /* stringified IPv4/v6 range */
       else if ( !strcmp(type, "parse") ) {

           if ((!SvROK(range)) || (SvTYPE(SvRV(range)) != SVt_PVAV)) {
               Safefree(map);
               croak(CROAK_NEW_PREFIX "bad range (not an array ref)");
           }

           av = (AV*)SvRV(range);
           if ( (av_len(av)) != 1 ) {
               Safefree(map);
               croak(CROAK_NEW_PREFIX "bad range ($#range != 2)");
           }

           {
               const char *first, *last;

               first = SvPV_nolen((SV*)*(av_fetch(av, 0, 0)));
               last =  SvPV_nolen((SV*)*(av_fetch(av, 1, 0)));

               rc = range_init_from_str(map, first, last);
               if (rc) {
                   Safefree(map);
                   croak(CROAK_NEW_PREFIX "bad range (error #%d)", rc);
               }
           }
       }

       /* CIDR-notation range */
       else if ( !strcmp(type, "cidr") ) {

           if (!SvOK(range)) {
               Safefree(map);
               croak(CROAK_NEW_PREFIX "bad range (undefined)");
           }

           {
               const char *cidr = SvPV_nolen(range);

               rc = range_init_from_cidr(map, cidr);
               if (rc) {
                   Safefree(map);
                   croak(CROAK_NEW_PREFIX "bad range (error #%d)", rc);
               }
           }
       }

       else {        
           Safefree(map);
           croak(CROAK_NEW_PREFIX "Unsupported type '%s'\n", type);
       }

       self = sv_newmortal();
       sv_setref_pv( self, CLASS, (void*)map );

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
first(self)
   PPCODE:
   {
       DECLARE_SELF;
       mXPUSHs( newSVpvn((const char*)&self->first, self->addr_len) );
   }

void
last(self)
   PPCODE:
   {
       DECLARE_SELF;
       mXPUSHs( newSVpvn((const char*)&self->last, self->addr_len) );
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
       int rc;
       const char *ip, *host;
       STRLEN iplen, hlen;
       DECLARE_SELF;

       ip   = SvPV(ST(1), iplen);
       host = SvPV(ST(2), hlen);

       if ( iplen != self->addr_len ) {
           XSRETURN_UNDEF;
       }

       if ( !(rc = range_occupy_ip(self, (ip_addr*)ip, host)) ) {
           XSRETURN_YES;
       }
       else {
 #if XS_DEBUG
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
       STRLEN iplen;
       DECLARE_SELF;

       ip   = SvPV(ST(1), iplen);

       if ( iplen != self->addr_len ) {
           XSRETURN_UNDEF;
       }

       if ( !(rc = range_free_ip(self, (ip_addr*)ip)) ) {
           XSRETURN_YES;
       }
       else {
 #if XS_DEBUG
           warn("DBG: range_free_ip() returned %d\n", rc);
 #endif
           XSRETURN_UNDEF;
       }
   }

void
free_addrs_iterator(self)
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
occupied_addrs_iterator(self)
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
       range_item_ip_t *res;
       STRLEN iplen;
       DECLARE_SELF;

       ip   = SvPV(ST(1), iplen);
       if ( iplen != self->addr_len ) {
           XSRETURN_UNDEF;
       }

       if ( !( rc = range_lookup_ip(self, (ip_addr*)ip, &res)) ) {
           if (res) {
               ST(0) = newSVpvn(res->host, strlen(res->host));
           }
           else {
               XSRETURN_UNDEF;
           }
       }
       else {
 #if XS_DEBUG
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
   CODE:
   {
       AV                    *av;
       char                   ip_str[INET6_ADDRSTRLEN + 1];
       range_item_t       *item;
       range_item_ip_t    *ii;
       range_item_range_t *ir;

       range_iterator_t   *self =
           INT2PTR(range_iterator_t *, SvIVX((SV*) SvRV( ST(0) )) );

       item = range_iterator_next(self);
       if (!item)
           XSRETURN_UNDEF;

       av = newAV();

       if (item->status == STATUS_FREE) {
           ir = (range_item_range_t*) item;
           inet_ntop(self->family, &ir->first, ip_str, INET6_ADDRSTRLEN + 1);
           av_push(av, newSVpvn(ip_str, strlen(ip_str)));
           inet_ntop(self->family, &ir->last, ip_str, INET6_ADDRSTRLEN + 1);
           av_push(av, newSVpvn(ip_str, strlen(ip_str)));
       }
       else {
           ii = (range_item_ip_t*) item;
           inet_ntop(self->family, &ii->ip, ip_str, INET6_ADDRSTRLEN + 1);
           av_push(av, newSVpvn(ip_str, strlen(ip_str)));
           av_push(av, newSVpvn(ii->host, strlen(ii->host)));
       }

       ST(0) = sv_2mortal( newRV_noinc((SV*)av) );
   }

