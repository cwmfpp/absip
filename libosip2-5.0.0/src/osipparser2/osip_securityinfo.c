/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001-2015 Aymeric MOIZARD amoizard@antisip.com
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <osipparser2/internal.h>

#include <osipparser2/osip_port.h>
#include <osipparser2/osip_message.h>
#include <osipparser2/osip_parser.h>
#include "parser.h"

int
osip_securityinfo_init (osip_securityinfo_t ** dest)
{
  *dest = (osip_securityinfo_t *) osip_malloc (sizeof (osip_securityinfo_t));
  if (*dest == NULL)
    return OSIP_NOMEM;
  memset (*dest, 0, sizeof (osip_securityinfo_t));
  return OSIP_SUCCESS;
}

/* fills the www-securityinfo header of message.               */
/* INPUT :  char *hvalue | value of header.   */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
int
osip_message_set_securityinfo (osip_message_t * sip, const char *hvalue)
{
  osip_securityinfo_t *securityinfo;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return OSIP_SUCCESS;

  if (sip == NULL)
    return OSIP_BADPARAMETER;
  i = osip_securityinfo_init (&securityinfo);
  if (i != 0)
    return i;
  i = osip_securityinfo_parse (securityinfo, hvalue);
  if (i != 0) {
    osip_securityinfo_free (securityinfo);
    return i;
  }
  sip->message_property = 2;
  osip_list_add (&sip->securityinfos, securityinfo, -1);
  return OSIP_SUCCESS;
}

/* fills the www-securityinfo structure.           */
/* INPUT : char *hvalue | value of header.         */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
/* TODO:
   digest-challenge tken has no order preference??
   verify many situations (extra SP....)
*/
int
osip_securityinfo_parse (osip_securityinfo_t * secu, const char *hvalue)
{
  const char *space;
  const char *next = NULL;
  int i;

  space = strchr (hvalue, ' '); /* SEARCH FOR SPACE */
  if (space == NULL)
    return OSIP_SYNTAXERROR;

  if (space - hvalue < 1)
    return OSIP_SYNTAXERROR;
  secu->auth_type = (char *) osip_malloc (space - hvalue + 1);
  if (secu->auth_type == NULL)
    return OSIP_NOMEM;
  osip_strncpy (secu->auth_type, hvalue, space - hvalue);

  for (;;) {
    int parse_ok = 0;

    i = __osip_quoted_string_set ("username", space, &(secu->username), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("realm", space, &(secu->realm), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("nonce", space, &(secu->nonce), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("uri", space, &(secu->uri), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("response", space, &(secu->response), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("digest", space, &(secu->digest), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_token_set ("algorithm", space, &(secu->algorithm), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("cnonce", space, &(secu->cnonce), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("opaque", space, &(secu->opaque), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_token_set ("qop", space, &(secu->message_qop), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_token_set ("nc", space, &(secu->nonce_count), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_token_set ("version", space, &(secu->version), &next);
    if (i!=0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;               /* end of header detected! */
    else if (next != space) {
        space = next;
        parse_ok++;
    }
    i = __osip_quoted_string_set ("targetname", space, &(secu->targetname), &next);
    if (i!=0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;               /* end of header detected! */
    else if (next != space) {
        space = next;
        parse_ok++;
    }
    i = __osip_quoted_string_set ("gssapi-data", space, &(secu->gssapi_data), &next);
    if (i!=0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;               /* end of header detected! */
    else if (next != space) {
        space = next;
        parse_ok++;
    }
    i = __osip_quoted_string_set ("crand", space, &(secu->crand), &next);
    if (i!=0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;               /* end of header detected! */
    else if (next != space) {
        space = next;
        parse_ok++;
    }
    i = __osip_quoted_string_set ("cnum", space, &(secu->cnum), &next);
    if (i!=0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;               /* end of header detected! */
    else if (next != space) {
        space = next;
        parse_ok++;
    }
    i = __osip_quoted_string_set ("random1", space, &(secu->random1), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("random2", space, &(secu->random2), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("deviceid", space, &(secu->deviceid), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("serverid", space, &(secu->serverid), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("sign1", space, &(secu->sign1), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("keyversion", space, &(secu->keyversion), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("cryptkey", space, &(secu->cryptkey), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("sign2", space, &(secu->sign2), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    /* nothing was recognized:
       here, we should handle a list of unknown tokens where:
       token1 = ( token2 | quoted_text ) */
    /* TODO */

    if (0 == parse_ok) {
      const char *quote1, *quote2, *tmp;

      /* CAUTION */
      /* parameter not understood!!! I'm too lazy to handle IT */
      /* let's simply bypass it */
      if (strlen (space) < 1)
        return OSIP_SUCCESS;
      tmp = strchr (space + 1, ',');
      if (tmp == NULL)          /* it was the last header */
        return OSIP_SUCCESS;
      quote1 = __osip_quote_find (space);
      if ((quote1 != NULL) && (quote1 < tmp)) { /* this may be a quoted string! */
        quote2 = __osip_quote_find (quote1 + 1);
        if (quote2 == NULL)
          return OSIP_SYNTAXERROR;      /* bad header format... */
        if (tmp < quote2)       /* the comma is inside the quotes! */
          space = strchr (quote2, ',');
        else
          space = tmp;
        if (space == NULL)      /* it was the last header */
          return OSIP_SUCCESS;
      }
      else
        space = tmp;
      /* continue parsing... */
    }
  }
  return OSIP_SUCCESS;          /* ok */
}

#ifndef MINISIZE
/* returns the securityinfo header.   */
/* INPUT : osip_message_t *sip | sip message.   */
/* returns null on error. */
int
osip_message_get_securityinfo (const osip_message_t * sip, int pos, osip_securityinfo_t ** dest)
{
  osip_securityinfo_t *securityinfo;

  *dest = NULL;
  if (osip_list_size (&sip->securityinfos) <= pos)
    return OSIP_UNDEFINED_ERROR;        /* does not exist */
  securityinfo = (osip_securityinfo_t *) osip_list_get (&sip->securityinfos, pos);
  *dest = securityinfo;
  return pos;
}
#endif

char *
osip_securityinfo_get_auth_type (const osip_securityinfo_t * securityinfo)
{
  return securityinfo->auth_type;
}

void
osip_securityinfo_set_auth_type (osip_securityinfo_t * securityinfo, char *auth_type)
{
  securityinfo->auth_type = (char *) auth_type;
}

char *
osip_securityinfo_get_username (osip_securityinfo_t * securityinfo)
{
  return securityinfo->username;
}

void
osip_securityinfo_set_username (osip_securityinfo_t * securityinfo, char *username)
{
  securityinfo->username = (char *) username;
}

char *
osip_securityinfo_get_realm (osip_securityinfo_t * securityinfo)
{
  return securityinfo->realm;
}

void
osip_securityinfo_set_realm (osip_securityinfo_t * securityinfo, char *realm)
{
  securityinfo->realm = (char *) realm;
}

char *
osip_securityinfo_get_nonce (osip_securityinfo_t * securityinfo)
{
  return securityinfo->nonce;
}

void
osip_securityinfo_set_nonce (osip_securityinfo_t * securityinfo, char *nonce)
{
  securityinfo->nonce = (char *) nonce;
}

char *
osip_securityinfo_get_uri (osip_securityinfo_t * securityinfo)
{
  return securityinfo->uri;
}

void
osip_securityinfo_set_uri (osip_securityinfo_t * securityinfo, char *uri)
{
  securityinfo->uri = (char *) uri;
}

char *
osip_securityinfo_get_response (osip_securityinfo_t * securityinfo)
{
  return securityinfo->response;
}

void
osip_securityinfo_set_response (osip_securityinfo_t * securityinfo, char *response)
{
  securityinfo->response = (char *) response;
}

char *
osip_securityinfo_get_digest (osip_securityinfo_t * securityinfo)
{
  return securityinfo->digest;
}

void
osip_securityinfo_set_digest (osip_securityinfo_t * securityinfo, char *digest)
{
  securityinfo->digest = (char *) digest;
}

char *
osip_securityinfo_get_algorithm (osip_securityinfo_t * securityinfo)
{
  return securityinfo->algorithm;
}

void
osip_securityinfo_set_algorithm (osip_securityinfo_t * securityinfo, char *algorithm)
{
  securityinfo->algorithm = (char *) algorithm;
}

char *
osip_securityinfo_get_cnonce (osip_securityinfo_t * securityinfo)
{
  return securityinfo->cnonce;
}

void
osip_securityinfo_set_cnonce (osip_securityinfo_t * securityinfo, char *cnonce)
{
  securityinfo->cnonce = (char *) cnonce;
}

char *
osip_securityinfo_get_opaque (osip_securityinfo_t * securityinfo)
{
  return securityinfo->opaque;
}

void
osip_securityinfo_set_opaque (osip_securityinfo_t * securityinfo, char *opaque)
{
  securityinfo->opaque = (char *) opaque;
}

char *
osip_securityinfo_get_message_qop (osip_securityinfo_t * securityinfo)
{
  return securityinfo->message_qop;
}

void
osip_securityinfo_set_message_qop (osip_securityinfo_t * securityinfo, char *message_qop)
{
  securityinfo->message_qop = (char *) message_qop;
}

char *
osip_securityinfo_get_nonce_count (osip_securityinfo_t * securityinfo)
{
  return securityinfo->nonce_count;
}

void
osip_securityinfo_set_nonce_count (osip_securityinfo_t * securityinfo, char *nonce_count)
{
  securityinfo->nonce_count = (char *) nonce_count;
}

char *
osip_securityinfo_get_version (osip_securityinfo_t * securityinfo)
{
  return securityinfo->version;
}

void
osip_securityinfo_set_version (osip_securityinfo_t * securityinfo,
				char *version)
{
  securityinfo->version = (char *) version;
}

char *
osip_securityinfo_get_targetname (osip_securityinfo_t * securityinfo)
{
  return securityinfo->targetname;
}

void
osip_securityinfo_set_targetname (osip_securityinfo_t * securityinfo,
				   char *targetname)
{
  securityinfo->targetname = (char *) targetname;
}

char *
osip_securityinfo_get_gssapi_data (osip_securityinfo_t * securityinfo)
{
  return securityinfo->gssapi_data;
}

void
osip_securityinfo_set_gssapi_data (osip_securityinfo_t * securityinfo,
                                    char *gssapi_data)
{
  securityinfo->gssapi_data = (char *) gssapi_data;
}

char *
osip_securityinfo_get_crand (osip_securityinfo_t * securityinfo)
{
  return securityinfo->crand;
}

void
osip_securityinfo_set_crand (osip_securityinfo_t * securityinfo,
			      char *crand)
{
  securityinfo->crand = (char *) crand;
}

char *
osip_securityinfo_get_cnum (osip_securityinfo_t * securityinfo)
{
  return securityinfo->cnum;
}

void
osip_securityinfo_set_cnum (osip_securityinfo_t * securityinfo,
			     char *cnum)
{
  securityinfo->cnum = (char *) cnum;
}

char *
osip_securityinfo_get_random1 (osip_securityinfo_t * securityinfo)
{
  return securityinfo->random1;
}

void
osip_securityinfo_set_random1 (osip_securityinfo_t * securityinfo, char *random1)
{
  securityinfo->random1 = (char *) random1;
}

char *
osip_securityinfo_get_random2 (osip_securityinfo_t * securityinfo)
{
  return securityinfo->random2;
}

void
osip_securityinfo_set_random2 (osip_securityinfo_t * securityinfo, char *random2)
{
  securityinfo->random2 = (char *) random2;
}

char *
osip_securityinfo_get_deviceid (osip_securityinfo_t * securityinfo)
{
  return securityinfo->deviceid;
}

void
osip_securityinfo_set_deviceid (osip_securityinfo_t * securityinfo, char *deviceid)
{
  securityinfo->deviceid = (char *) deviceid;
}

char *
osip_securityinfo_get_serverid (osip_securityinfo_t * securityinfo)
{
  return securityinfo->serverid;
}

void
osip_securityinfo_set_serverid (osip_securityinfo_t * securityinfo, char *serverid)
{
  securityinfo->serverid = (char *) serverid;
}

char *
osip_securityinfo_get_sign1 (osip_securityinfo_t * securityinfo)
{
  return securityinfo->sign1;
}

void
osip_securityinfo_set_sign1 (osip_securityinfo_t * securityinfo, char *sign1)
{
  securityinfo->sign1 = (char *) sign1;
}

char *
osip_securityinfo_get_keyversion (osip_securityinfo_t * securityinfo)
{
  return securityinfo->keyversion;
}

void
osip_securityinfo_set_keyversion (osip_securityinfo_t * securityinfo, char *keyversion)
{
  securityinfo->keyversion = (char *) keyversion;
}

char *
osip_securityinfo_get_cryptkey (osip_securityinfo_t * securityinfo)
{
  return securityinfo->cryptkey;
}

void
osip_securityinfo_set_cryptkey (osip_securityinfo_t * securityinfo, char *cryptkey)
{
  securityinfo->cryptkey = (char *) cryptkey;
}

char *
osip_securityinfo_get_sign2 (osip_securityinfo_t * securityinfo)
{
  return securityinfo->sign2;
}

void
osip_securityinfo_set_sign2 (osip_securityinfo_t * securityinfo, char *sign2)
{
  securityinfo->sign2 = (char *) sign2;
}


/* returns the securityinfo header as a string.          */
/* INPUT : osip_securityinfo_t *securityinfo | securityinfo header.  */
/* returns null on error. */
int
osip_securityinfo_to_str (const osip_securityinfo_t * secu, char **dest)
{
  size_t len;
  char *tmp;
  int first = 1;

  *dest = NULL;
  /* DO NOT REALLY KNOW THE LIST OF MANDATORY PARAMETER: Please HELP! */
#if 0
  if ((secu == NULL) || (secu->auth_type == NULL) || (secu->realm == NULL)
      || (secu->nonce == NULL))
    return OSIP_BADPARAMETER;
#else
  /* IMS requirement: send securityinfo like in:
     Digest uri="sip:sip.antisip.com", username="joe", response=""
   */
  if ((secu == NULL) || (secu->auth_type == NULL))
    return OSIP_BADPARAMETER;
#endif

  len = strlen (secu->auth_type) + 1;
  if (secu->username != NULL)
    len = len + 10 + strlen (secu->username);
  if (secu->realm != NULL)
    len = len + 8 + strlen (secu->realm);
  if (secu->nonce != NULL)
    len = len + 8 + strlen (secu->nonce);
  if (secu->uri != NULL)
    len = len + 6 + strlen (secu->uri);
  if (secu->response != NULL)
    len = len + 11 + strlen (secu->response);
  len = len + 2;
  if (secu->digest != NULL)
    len = len + strlen (secu->digest) + 9;
  if (secu->algorithm != NULL)
    len = len + strlen (secu->algorithm) + 12;
  if (secu->cnonce != NULL)
    len = len + strlen (secu->cnonce) + 9;
  if (secu->opaque != NULL)
    len = len + 9 + strlen (secu->opaque);
  if (secu->nonce_count != NULL)
    len = len + strlen (secu->nonce_count) + 5;
  if (secu->message_qop != NULL)
    len = len + strlen (secu->message_qop) + 6;
  if (secu->version != NULL)
    len = len + strlen (secu->version) + 10;
  if (secu->targetname != NULL)
    len = len + strlen (secu->targetname) + 13;
  if (secu->gssapi_data != NULL)
    len = len + strlen (secu->gssapi_data) + 14;
  if (secu->crand != NULL)
    len = len + strlen (secu->crand) + 8;
  if (secu->cnum != NULL)
    len = len + strlen (secu->cnum) + 7;
  if (secu->random1 != NULL)
    len = len + 10 + strlen (secu->random1);
  if (secu->random2 != NULL)
    len = len + 10 + strlen (secu->random2);
  if (secu->deviceid != NULL)
    len = len + 11 + strlen (secu->deviceid);
  if (secu->serverid != NULL)
    len = len + 11 + strlen (secu->serverid);
  if (secu->sign1 != NULL)
    len = len + 8 + strlen (secu->sign1);
  if (secu->keyversion != NULL)
    len = len + 13 + strlen (secu->keyversion);
  if (secu->cryptkey != NULL)
    len = len + 11 + strlen (secu->cryptkey);
  if (secu->sign2 != NULL)
    len = len + 8 + strlen (secu->sign2);

  tmp = (char *) osip_malloc (len);
  if (tmp == NULL)
    return OSIP_NOMEM;
  *dest = tmp;

  tmp = osip_str_append (tmp, secu->auth_type);

  if (secu->username != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " username=", 10);
    /* !! username-value must be a quoted string !! */
    tmp = osip_str_append (tmp, secu->username);
  }

  if (secu->realm != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " realm=", 7);
    /* !! realm-value must be a quoted string !! */
    tmp = osip_str_append (tmp, secu->realm);
  }
  if (secu->nonce != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " nonce=", 7);
    /* !! nonce-value must be a quoted string !! */
    tmp = osip_str_append (tmp, secu->nonce);
  }

  if (secu->uri != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " uri=", 5);
    /* !! domain-value must be a list of URI in a quoted string !! */
    tmp = osip_str_append (tmp, secu->uri);
  }
  if (secu->response != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " response=", 10);
    /* !! domain-value must be a list of URI in a quoted string !! */
    tmp = osip_str_append (tmp, secu->response);
  }

  if (secu->digest != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " digest=", 8);
    /* !! domain-value must be a list of URI in a quoted string !! */
    tmp = osip_str_append (tmp, secu->digest);
  }
  if (secu->algorithm != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " algorithm=", 11);
    tmp = osip_str_append (tmp, secu->algorithm);
  }
  if (secu->cnonce != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " cnonce=", 8);
    tmp = osip_str_append (tmp, secu->cnonce);
  }
  if (secu->opaque != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " opaque=", 8);
    tmp = osip_str_append (tmp, secu->opaque);
  }
  if (secu->message_qop != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " qop=", 5);
    tmp = osip_str_append (tmp, secu->message_qop);
  }
  if (secu->nonce_count != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " nc=", 4);
    tmp = osip_str_append (tmp, secu->nonce_count);
  }
  if (secu->version != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " version=", 9);
    tmp = osip_str_append (tmp, secu->version);
  }
  if (secu->targetname != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " targetname=", 12);
    tmp = osip_str_append (tmp, secu->targetname);
  }
  if (secu->gssapi_data != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " gssapi-data=", 13);
    tmp = osip_str_append (tmp, secu->gssapi_data);
  }
  if (secu->crand != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " crand=", 7);
    tmp = osip_str_append (tmp, secu->crand);
  }
  if (secu->cnum != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " cnum=", 6);
    tmp = osip_str_append (tmp, secu->cnum);
  }
  if (secu->random1 != NULL) {
    tmp = osip_strn_append (tmp, ", random1=", 10);
    tmp = osip_str_append (tmp, secu->random1);
  }
  if (secu->random2 != NULL) {
    tmp = osip_strn_append (tmp, ", random2=", 10);
    tmp = osip_str_append (tmp, secu->random2);
  }
  if (secu->deviceid != NULL) {
    tmp = osip_strn_append (tmp, ", deviceid=", 11);
    tmp = osip_str_append (tmp, secu->deviceid);
  }
  if (secu->serverid != NULL) {
    tmp = osip_strn_append (tmp, ", serverid=", 11);
    tmp = osip_str_append (tmp, secu->serverid);
  }
  if (secu->sign1 != NULL) {
    tmp = osip_strn_append (tmp, ", sign1=", 8);
    tmp = osip_str_append (tmp, secu->sign1);
  }
  if (secu->keyversion != NULL) {
    tmp = osip_strn_append (tmp, ", keyversion=", 13);
    tmp = osip_str_append (tmp, secu->keyversion);
  }
  if (secu->cryptkey != NULL) {
    tmp = osip_strn_append (tmp, ", cryptkey=", 11);
    tmp = osip_str_append (tmp, secu->cryptkey);
  }
  if (secu->sign2 != NULL) {
    tmp = osip_strn_append (tmp, ", sign2=", 8);
    tmp = osip_str_append (tmp, secu->sign2);
  }
  
  return OSIP_SUCCESS;
}

/* deallocates a osip_securityinfo_t structure.  */
/* INPUT : osip_securityinfo_t *securityinfo | securityinfo. */
void
osip_securityinfo_free (osip_securityinfo_t * securityinfo)
{
  if (securityinfo == NULL)
    return;
  osip_free (securityinfo->auth_type);
  osip_free (securityinfo->username);
  osip_free (securityinfo->realm);
  osip_free (securityinfo->nonce);
  osip_free (securityinfo->uri);
  osip_free (securityinfo->response);
  osip_free (securityinfo->digest);
  osip_free (securityinfo->algorithm);
  osip_free (securityinfo->cnonce);
  osip_free (securityinfo->opaque);
  osip_free (securityinfo->message_qop);
  osip_free (securityinfo->nonce_count);
  osip_free (securityinfo->version);
  osip_free (securityinfo->targetname);
  osip_free (securityinfo->gssapi_data);
  osip_free (securityinfo->crand);
  osip_free (securityinfo->cnum);
  osip_free (securityinfo);
  osip_free (securityinfo->random1);
  osip_free (securityinfo->random2);
  osip_free (securityinfo->deviceid);
  osip_free (securityinfo->serverid);
  osip_free (securityinfo->sign1);
  osip_free (securityinfo->keyversion);
  osip_free (securityinfo->cryptkey);
  osip_free (securityinfo->sign2);
}

int
osip_securityinfo_clone (const osip_securityinfo_t * secu, osip_securityinfo_t ** dest)
{
  int i;
  osip_securityinfo_t *au;

  *dest = NULL;
  if (secu == NULL)
    return OSIP_BADPARAMETER;
  /* to be removed?
     if (secu->auth_type==NULL) return -1;
     if (secu->username==NULL) return -1;
     if (secu->realm==NULL) return -1;
     if (secu->nonce==NULL) return -1;
     if (secu->uri==NULL) return -1;
     if (secu->response==NULL) return -1;
     if (secu->opaque==NULL) return -1;
   */

  i = osip_securityinfo_init (&au);
  if (i != 0)                   /* allocation failed */
    return i;
  if (secu->auth_type != NULL) {
    au->auth_type = osip_strdup (secu->auth_type);
    if (au->auth_type == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->username != NULL) {
    au->username = osip_strdup (secu->username);
    if (au->username == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->realm != NULL) {
    au->realm = osip_strdup (secu->realm);
    if (secu->realm == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->nonce != NULL) {
    au->nonce = osip_strdup (secu->nonce);
    if (secu->nonce == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->uri != NULL) {
    au->uri = osip_strdup (secu->uri);
    if (au->uri == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->response != NULL) {
    au->response = osip_strdup (secu->response);
    if (secu->response == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->digest != NULL) {
    au->digest = osip_strdup (secu->digest);
    if (au->digest == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->algorithm != NULL) {
    au->algorithm = osip_strdup (secu->algorithm);
    if (secu->algorithm == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->cnonce != NULL) {
    au->cnonce = osip_strdup (secu->cnonce);
    if (au->cnonce == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->opaque != NULL) {
    au->opaque = osip_strdup (secu->opaque);
    if (secu->opaque == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->message_qop != NULL) {
    au->message_qop = osip_strdup (secu->message_qop);
    if (secu->message_qop == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->nonce_count != NULL) {
    au->nonce_count = osip_strdup (secu->nonce_count);
    if (secu->nonce_count == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }

  if (secu->version != NULL) {
    au->version = osip_strdup (secu->version);
    if (secu->version == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->targetname != NULL) {
    au->targetname = osip_strdup (secu->targetname);
    if (secu->targetname == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->gssapi_data != NULL) {
    au->gssapi_data = osip_strdup (secu->gssapi_data);
    if (secu->gssapi_data == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->crand != NULL) {
    au->crand = osip_strdup (secu->crand);
    if (secu->crand == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->cnum != NULL) {
    au->cnum = osip_strdup (secu->cnum);
    if (secu->cnum == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->random1 != NULL) {
    au->random1 = osip_strdup (secu->random1);
    if (secu->random1 == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->random2 != NULL) {
    au->random2 = osip_strdup (secu->random2);
    if (secu->random2 == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->deviceid != NULL) {
    au->deviceid = osip_strdup (secu->deviceid);
    if (secu->deviceid == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->serverid != NULL) {
    au->serverid = osip_strdup (secu->serverid);
    if (secu->serverid == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->sign1 != NULL) {
    au->sign1 = osip_strdup (secu->sign1);
    if (secu->sign1 == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->keyversion != NULL) {
    au->keyversion = osip_strdup (secu->keyversion);
    if (secu->keyversion == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->cryptkey != NULL) {
    au->cryptkey = osip_strdup (secu->cryptkey);
    if (secu->cryptkey == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }
  if (secu->sign2 != NULL) {
    au->sign2 = osip_strdup (secu->sign2);
    if (secu->sign2 == NULL) {
      osip_securityinfo_free (au);
      return OSIP_NOMEM;
    }
  }

  *dest = au;
  return OSIP_SUCCESS;
}
