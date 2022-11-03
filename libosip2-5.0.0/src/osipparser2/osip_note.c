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
osip_note_init (osip_note_t ** dest)
{
  *dest = (osip_note_t *) osip_malloc (sizeof (osip_note_t));
  if (*dest == NULL)
    return OSIP_NOMEM;
  memset (*dest, 0, sizeof (osip_note_t));
  return OSIP_SUCCESS;
}

/* fills the www-note header of message.               */
/* INPUT :  char *hvalue | value of header.   */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
int
osip_message_set_note (osip_message_t * sip, const char *hvalue)
{
  osip_note_t *note;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return OSIP_SUCCESS;

  if (sip == NULL)
    return OSIP_BADPARAMETER;
  i = osip_note_init (&note);
  if (i != 0)
    return i;
  i = osip_note_parse (note, hvalue);
  if (i != 0) {
    osip_note_free (note);
    return i;
  }
  sip->message_property = 2;
  osip_list_add (&sip->notes, note, -1);
  return OSIP_SUCCESS;
}

/* fills the www-note structure.           */
/* INPUT : char *hvalue | value of header.         */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
/* TODO:
   digest-challenge tken has no order preference??
   verify many situations (extra SP....)
*/
int
osip_note_parse (osip_note_t * note, const char *hvalue)
{
  const char *space;
  const char *next = NULL;
  int i;

  space = strchr (hvalue, ' '); /* SEARCH FOR SPACE */
  if (space == NULL)
    return OSIP_SYNTAXERROR;

  if (space - hvalue < 1)
    return OSIP_SYNTAXERROR;
  note->auth_type = (char *) osip_malloc (space - hvalue + 1);
  if (note->auth_type == NULL)
    return OSIP_NOMEM;
  osip_strncpy (note->auth_type, hvalue, space - hvalue);

  for (;;) {
    int parse_ok = 0;

    i = __osip_quoted_string_set ("username", space, &(note->username), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("realm", space, &(note->realm), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("nonce", space, &(note->nonce), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("uri", space, &(note->uri), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("response", space, &(note->response), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("digest", space, &(note->digest), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_token_set ("algorithm", space, &(note->algorithm), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("cnonce", space, &(note->cnonce), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("opaque", space, &(note->opaque), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_token_set ("qop", space, &(note->message_qop), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_token_set ("nc", space, &(note->nonce_count), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_token_set ("version", space, &(note->version), &next);
    if (i!=0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;               /* end of header detected! */
    else if (next != space) {
        space = next;
        parse_ok++;
    }
    i = __osip_quoted_string_set ("targetname", space, &(note->targetname), &next);
    if (i!=0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;               /* end of header detected! */
    else if (next != space) {
        space = next;
        parse_ok++;
    }
    i = __osip_quoted_string_set ("gssapi-data", space, &(note->gssapi_data), &next);
    if (i!=0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;               /* end of header detected! */
    else if (next != space) {
        space = next;
        parse_ok++;
    }
    i = __osip_quoted_string_set ("crand", space, &(note->crand), &next);
    if (i!=0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;               /* end of header detected! */
    else if (next != space) {
        space = next;
        parse_ok++;
    }
    i = __osip_quoted_string_set ("cnum", space, &(note->cnum), &next);
    if (i!=0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;               /* end of header detected! */
    else if (next != space) {
        space = next;
        parse_ok++;
    }
    i = __osip_quoted_string_set ("random1", space, &(note->random1), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("random2", space, &(note->random2), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("deviceid", space, &(note->deviceid), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("serverid", space, &(note->serverid), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("sign1", space, &(note->sign1), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("keyversion", space, &(note->keyversion), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("cryptkey", space, &(note->cryptkey), &next);
    if (i != 0)
      return i;
    if (next == NULL)
      return OSIP_SUCCESS;      /* end of header detected! */
    else if (next != space) {
      space = next;
      parse_ok++;
    }
    i = __osip_quoted_string_set ("sign2", space, &(note->sign2), &next);
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
/* returns the note header.   */
/* INPUT : osip_message_t *sip | sip message.   */
/* returns null on error. */
int
osip_message_get_note (const osip_message_t * sip, int pos, osip_note_t ** dest)
{
  osip_note_t *note;

  *dest = NULL;
  if (osip_list_size (&sip->notes) <= pos)
    return OSIP_UNDEFINED_ERROR;        /* does not exist */
  note = (osip_note_t *) osip_list_get (&sip->notes, pos);
  *dest = note;
  return pos;
}
#endif

char *
osip_note_get_auth_type (const osip_note_t * note)
{
  return note->auth_type;
}

void
osip_note_set_auth_type (osip_note_t * note, char *auth_type)
{
  note->auth_type = (char *) auth_type;
}

char *
osip_note_get_username (osip_note_t * note)
{
  return note->username;
}

void
osip_note_set_username (osip_note_t * note, char *username)
{
  note->username = (char *) username;
}

char *
osip_note_get_realm (osip_note_t * note)
{
  return note->realm;
}

void
osip_note_set_realm (osip_note_t * note, char *realm)
{
  note->realm = (char *) realm;
}

char *
osip_note_get_nonce (osip_note_t * note)
{
  return note->nonce;
}

void
osip_note_set_nonce (osip_note_t * note, char *nonce)
{
  note->nonce = (char *) nonce;
}

char *
osip_note_get_uri (osip_note_t * note)
{
  return note->uri;
}

void
osip_note_set_uri (osip_note_t * note, char *uri)
{
  note->uri = (char *) uri;
}

char *
osip_note_get_response (osip_note_t * note)
{
  return note->response;
}

void
osip_note_set_response (osip_note_t * note, char *response)
{
  note->response = (char *) response;
}

char *
osip_note_get_digest (osip_note_t * note)
{
  return note->digest;
}

void
osip_note_set_digest (osip_note_t * note, char *digest)
{
  note->digest = (char *) digest;
}

char *
osip_note_get_algorithm (osip_note_t * note)
{
  return note->algorithm;
}

void
osip_note_set_algorithm (osip_note_t * note, char *algorithm)
{
  note->algorithm = (char *) algorithm;
}

char *
osip_note_get_cnonce (osip_note_t * note)
{
  return note->cnonce;
}

void
osip_note_set_cnonce (osip_note_t * note, char *cnonce)
{
  note->cnonce = (char *) cnonce;
}

char *
osip_note_get_opaque (osip_note_t * note)
{
  return note->opaque;
}

void
osip_note_set_opaque (osip_note_t * note, char *opaque)
{
  note->opaque = (char *) opaque;
}

char *
osip_note_get_message_qop (osip_note_t * note)
{
  return note->message_qop;
}

void
osip_note_set_message_qop (osip_note_t * note, char *message_qop)
{
  note->message_qop = (char *) message_qop;
}

char *
osip_note_get_nonce_count (osip_note_t * note)
{
  return note->nonce_count;
}

void
osip_note_set_nonce_count (osip_note_t * note, char *nonce_count)
{
  note->nonce_count = (char *) nonce_count;
}

char *
osip_note_get_version (osip_note_t * note)
{
  return note->version;
}

void
osip_note_set_version (osip_note_t * note,
				char *version)
{
  note->version = (char *) version;
}

char *
osip_note_get_targetname (osip_note_t * note)
{
  return note->targetname;
}

void
osip_note_set_targetname (osip_note_t * note,
				   char *targetname)
{
  note->targetname = (char *) targetname;
}

char *
osip_note_get_gssapi_data (osip_note_t * note)
{
  return note->gssapi_data;
}

void
osip_note_set_gssapi_data (osip_note_t * note,
                                    char *gssapi_data)
{
  note->gssapi_data = (char *) gssapi_data;
}

char *
osip_note_get_crand (osip_note_t * note)
{
  return note->crand;
}

void
osip_note_set_crand (osip_note_t * note,
			      char *crand)
{
  note->crand = (char *) crand;
}

char *
osip_note_get_cnum (osip_note_t * note)
{
  return note->cnum;
}

void
osip_note_set_cnum (osip_note_t * note,
			     char *cnum)
{
  note->cnum = (char *) cnum;
}

char *
osip_note_get_random1 (osip_note_t * note)
{
  return note->random1;
}

void
osip_note_set_random1 (osip_note_t * note, char *random1)
{
  note->random1 = (char *) random1;
}

char *
osip_note_get_random2 (osip_note_t * note)
{
  return note->random2;
}

void
osip_note_set_random2 (osip_note_t * note, char *random2)
{
  note->random2 = (char *) random2;
}

char *
osip_note_get_deviceid (osip_note_t * note)
{
  return note->deviceid;
}

void
osip_note_set_deviceid (osip_note_t * note, char *deviceid)
{
  note->deviceid = (char *) deviceid;
}

char *
osip_note_get_serverid (osip_note_t * note)
{
  return note->serverid;
}

void
osip_note_set_serverid (osip_note_t * note, char *serverid)
{
  note->serverid = (char *) serverid;
}

char *
osip_note_get_sign1 (osip_note_t * note)
{
  return note->sign1;
}

void
osip_note_set_sign1 (osip_note_t * note, char *sign1)
{
  note->sign1 = (char *) sign1;
}

char *
osip_note_get_keyversion (osip_note_t * note)
{
  return note->keyversion;
}

void
osip_note_set_keyversion (osip_note_t * note, char *keyversion)
{
  note->keyversion = (char *) keyversion;
}

char *
osip_note_get_cryptkey (osip_note_t * note)
{
  return note->cryptkey;
}

void
osip_note_set_cryptkey (osip_note_t * note, char *cryptkey)
{
  note->cryptkey = (char *) cryptkey;
}

char *
osip_note_get_sign2 (osip_note_t * note)
{
  return note->sign2;
}

void
osip_note_set_sign2 (osip_note_t * note, char *sign2)
{
  note->sign2 = (char *) sign2;
}


/* returns the note header as a string.          */
/* INPUT : osip_note_t *note | note header.  */
/* returns null on error. */
int
osip_note_to_str (const osip_note_t * note, char **dest)
{
  size_t len;
  char *tmp;
  int first = 1;

  *dest = NULL;
  /* DO NOT REALLY KNOW THE LIST OF MANDATORY PARAMETER: Please HELP! */
#if 0
  if ((note == NULL) || (note->auth_type == NULL) || (note->realm == NULL)
      || (note->nonce == NULL))
    return OSIP_BADPARAMETER;
#else
  /* IMS requirement: send note like in:
     Digest uri="sip:sip.antisip.com", username="joe", response=""
   */
  if ((note == NULL) || (note->auth_type == NULL))
    return OSIP_BADPARAMETER;
#endif

  len = strlen (note->auth_type) + 1;
  if (note->username != NULL)
    len = len + 10 + strlen (note->username);
  if (note->realm != NULL)
    len = len + 8 + strlen (note->realm);
  if (note->nonce != NULL)
    len = len + 8 + strlen (note->nonce);
  if (note->uri != NULL)
    len = len + 6 + strlen (note->uri);
  if (note->response != NULL)
    len = len + 11 + strlen (note->response);
  len = len + 2;
  if (note->digest != NULL)
    len = len + strlen (note->digest) + 9;
  if (note->algorithm != NULL)
    len = len + strlen (note->algorithm) + 12;
  if (note->cnonce != NULL)
    len = len + strlen (note->cnonce) + 9;
  if (note->opaque != NULL)
    len = len + 9 + strlen (note->opaque);
  if (note->nonce_count != NULL)
    len = len + strlen (note->nonce_count) + 5;
  if (note->message_qop != NULL)
    len = len + strlen (note->message_qop) + 6;
  if (note->version != NULL)
    len = len + strlen (note->version) + 10;
  if (note->targetname != NULL)
    len = len + strlen (note->targetname) + 13;
  if (note->gssapi_data != NULL)
    len = len + strlen (note->gssapi_data) + 14;
  if (note->crand != NULL)
    len = len + strlen (note->crand) + 8;
  if (note->cnum != NULL)
    len = len + strlen (note->cnum) + 7;
  if (note->random1 != NULL)
    len = len + 10 + strlen (note->random1);
  if (note->random2 != NULL)
    len = len + 10 + strlen (note->random2);
  if (note->deviceid != NULL)
    len = len + 11 + strlen (note->deviceid);
  if (note->serverid != NULL)
    len = len + 11 + strlen (note->serverid);
  if (note->sign1 != NULL)
    len = len + 8 + strlen (note->sign1);
  if (note->keyversion != NULL)
    len = len + 13 + strlen (note->keyversion);
  if (note->cryptkey != NULL)
    len = len + 11 + strlen (note->cryptkey);
  if (note->sign2 != NULL)
    len = len + 8 + strlen (note->sign2);

  tmp = (char *) osip_malloc (len);
  if (tmp == NULL)
    return OSIP_NOMEM;
  *dest = tmp;

  tmp = osip_str_append (tmp, note->auth_type);

  if (note->username != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " username=", 10);
    /* !! username-value must be a quoted string !! */
    tmp = osip_str_append (tmp, note->username);
  }

  if (note->realm != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " realm=", 7);
    /* !! realm-value must be a quoted string !! */
    tmp = osip_str_append (tmp, note->realm);
  }
  if (note->nonce != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " nonce=", 7);
    /* !! nonce-value must be a quoted string !! */
    tmp = osip_str_append (tmp, note->nonce);
  }

  if (note->uri != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " uri=", 5);
    /* !! domain-value must be a list of URI in a quoted string !! */
    tmp = osip_str_append (tmp, note->uri);
  }
  if (note->response != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " response=", 10);
    /* !! domain-value must be a list of URI in a quoted string !! */
    tmp = osip_str_append (tmp, note->response);
  }

  if (note->digest != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " digest=", 8);
    /* !! domain-value must be a list of URI in a quoted string !! */
    tmp = osip_str_append (tmp, note->digest);
  }
  if (note->algorithm != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " algorithm=", 11);
    tmp = osip_str_append (tmp, note->algorithm);
  }
  if (note->cnonce != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " cnonce=", 8);
    tmp = osip_str_append (tmp, note->cnonce);
  }
  if (note->opaque != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " opaque=", 8);
    tmp = osip_str_append (tmp, note->opaque);
  }
  if (note->message_qop != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " qop=", 5);
    tmp = osip_str_append (tmp, note->message_qop);
  }
  if (note->nonce_count != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " nc=", 4);
    tmp = osip_str_append (tmp, note->nonce_count);
  }
  if (note->version != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " version=", 9);
    tmp = osip_str_append (tmp, note->version);
  }
  if (note->targetname != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " targetname=", 12);
    tmp = osip_str_append (tmp, note->targetname);
  }
  if (note->gssapi_data != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " gssapi-data=", 13);
    tmp = osip_str_append (tmp, note->gssapi_data);
  }
  if (note->crand != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " crand=", 7);
    tmp = osip_str_append (tmp, note->crand);
  }
  if (note->cnum != NULL) {
    if(!first)
      tmp = osip_strn_append (tmp, ",", 1);
    first = 0;
    tmp = osip_strn_append (tmp, " cnum=", 6);
    tmp = osip_str_append (tmp, note->cnum);
  }
  if (note->random1 != NULL) {
    tmp = osip_strn_append (tmp, ", random1=", 10);
    tmp = osip_str_append (tmp, note->random1);
  }
  if (note->random2 != NULL) {
    tmp = osip_strn_append (tmp, ", random2=", 10);
    tmp = osip_str_append (tmp, note->random2);
  }
  if (note->deviceid != NULL) {
    tmp = osip_strn_append (tmp, ", deviceid=", 11);
    tmp = osip_str_append (tmp, note->deviceid);
  }
  if (note->serverid != NULL) {
    tmp = osip_strn_append (tmp, ", serverid=", 11);
    tmp = osip_str_append (tmp, note->serverid);
  }
  if (note->sign1 != NULL) {
    tmp = osip_strn_append (tmp, ", sign1=", 8);
    tmp = osip_str_append (tmp, note->sign1);
  }
  if (note->keyversion != NULL) {
    tmp = osip_strn_append (tmp, ", keyversion=", 13);
    tmp = osip_str_append (tmp, note->keyversion);
  }
  if (note->cryptkey != NULL) {
    tmp = osip_strn_append (tmp, ", cryptkey=", 11);
    tmp = osip_str_append (tmp, note->cryptkey);
  }
  if (note->sign2 != NULL) {
    tmp = osip_strn_append (tmp, ", sign2=", 8);
    tmp = osip_str_append (tmp, note->sign2);
  }
  
  return OSIP_SUCCESS;
}

/* deallocates a osip_note_t structure.  */
/* INPUT : osip_note_t *note | note. */
void
osip_note_free (osip_note_t * note)
{
  if (note == NULL)
    return;
  osip_free (note->auth_type);
  osip_free (note->username);
  osip_free (note->realm);
  osip_free (note->nonce);
  osip_free (note->uri);
  osip_free (note->response);
  osip_free (note->digest);
  osip_free (note->algorithm);
  osip_free (note->cnonce);
  osip_free (note->opaque);
  osip_free (note->message_qop);
  osip_free (note->nonce_count);
  osip_free (note->version);
  osip_free (note->targetname);
  osip_free (note->gssapi_data);
  osip_free (note->crand);
  osip_free (note->cnum);
  osip_free (note);
  osip_free (note->random1);
  osip_free (note->random2);
  osip_free (note->deviceid);
  osip_free (note->serverid);
  osip_free (note->sign1);
  osip_free (note->keyversion);
  osip_free (note->cryptkey);
  osip_free (note->sign2);
}

int
osip_note_clone (const osip_note_t * note, osip_note_t ** dest)
{
  int i;
  osip_note_t *au;

  *dest = NULL;
  if (note == NULL)
    return OSIP_BADPARAMETER;
  /* to be removed?
     if (note->auth_type==NULL) return -1;
     if (note->username==NULL) return -1;
     if (note->realm==NULL) return -1;
     if (note->nonce==NULL) return -1;
     if (note->uri==NULL) return -1;
     if (note->response==NULL) return -1;
     if (note->opaque==NULL) return -1;
   */

  i = osip_note_init (&au);
  if (i != 0)                   /* allocation failed */
    return i;
  if (note->auth_type != NULL) {
    au->auth_type = osip_strdup (note->auth_type);
    if (au->auth_type == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->username != NULL) {
    au->username = osip_strdup (note->username);
    if (au->username == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->realm != NULL) {
    au->realm = osip_strdup (note->realm);
    if (note->realm == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->nonce != NULL) {
    au->nonce = osip_strdup (note->nonce);
    if (note->nonce == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->uri != NULL) {
    au->uri = osip_strdup (note->uri);
    if (au->uri == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->response != NULL) {
    au->response = osip_strdup (note->response);
    if (note->response == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->digest != NULL) {
    au->digest = osip_strdup (note->digest);
    if (au->digest == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->algorithm != NULL) {
    au->algorithm = osip_strdup (note->algorithm);
    if (note->algorithm == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->cnonce != NULL) {
    au->cnonce = osip_strdup (note->cnonce);
    if (au->cnonce == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->opaque != NULL) {
    au->opaque = osip_strdup (note->opaque);
    if (note->opaque == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->message_qop != NULL) {
    au->message_qop = osip_strdup (note->message_qop);
    if (note->message_qop == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->nonce_count != NULL) {
    au->nonce_count = osip_strdup (note->nonce_count);
    if (note->nonce_count == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }

  if (note->version != NULL) {
    au->version = osip_strdup (note->version);
    if (note->version == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->targetname != NULL) {
    au->targetname = osip_strdup (note->targetname);
    if (note->targetname == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->gssapi_data != NULL) {
    au->gssapi_data = osip_strdup (note->gssapi_data);
    if (note->gssapi_data == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->crand != NULL) {
    au->crand = osip_strdup (note->crand);
    if (note->crand == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->cnum != NULL) {
    au->cnum = osip_strdup (note->cnum);
    if (note->cnum == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->random1 != NULL) {
    au->random1 = osip_strdup (note->random1);
    if (note->random1 == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->random2 != NULL) {
    au->random2 = osip_strdup (note->random2);
    if (note->random2 == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->deviceid != NULL) {
    au->deviceid = osip_strdup (note->deviceid);
    if (note->deviceid == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->serverid != NULL) {
    au->serverid = osip_strdup (note->serverid);
    if (note->serverid == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->sign1 != NULL) {
    au->sign1 = osip_strdup (note->sign1);
    if (note->sign1 == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->keyversion != NULL) {
    au->keyversion = osip_strdup (note->keyversion);
    if (note->keyversion == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->cryptkey != NULL) {
    au->cryptkey = osip_strdup (note->cryptkey);
    if (note->cryptkey == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }
  if (note->sign2 != NULL) {
    au->sign2 = osip_strdup (note->sign2);
    if (note->sign2 == NULL) {
      osip_note_free (au);
      return OSIP_NOMEM;
    }
  }

  *dest = au;
  return OSIP_SUCCESS;
}


