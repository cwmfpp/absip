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


#ifndef _OSIP_NOTE_H_
#define _OSIP_NOTE_H_


/**
 * @file osip_note.h
 * @brief oSIP osip_note header definition.
 */

/**
 * @defgroup oSIP_AUTHORIZATION oSIP authorization header definition.
 * @ingroup oSIP_HEADERS
 * @{
 */

/**
 * Structure for SecurityInfo headers.
 * @var osip_note_t
 */
  typedef struct osip_note osip_note_t;

/**
 * Definition of the SecurityInfo header.
 * @struct osip_note
 */
  struct osip_note
  {
    char *auth_type;		/**< Authentication Type (Basic or Digest) */
    char *username;		/**< login */
    char *realm;		/**< realm (as a quoted-string) */
    char *nonce;		/**< nonce */
    char *uri;  		/**< uri */
    char *response;		/**< response */
    char *digest;		/**< digest */
    char *algorithm;		/**< algorithm (optionnal) */
    char *cnonce;		/**< cnonce (optionnal) */
    char *opaque;		/**< opaque (optionnal) */
    char *message_qop;		/**< message_qop (optionnal) */
    char *nonce_count;		/**< nonce_count (optionnal) */
    char *version;		/**< version (optional - NTLM) */
    char *targetname;		/**< targetname (optional - NTLM) */
    char *gssapi_data;		/**< gssapi-data (optional - NTLM) */
    char *crand;
	  char *cnum;
    char *auth_param;		/**< other parameters (optionnal) */
    char *random1;		/**add by chenwenmin, for GB35114 */
    char *random2;		/**add by chenwenmin, for GB35114 */
    char *deviceid;		/**add by chenwenmin, for GB35114 */
    char *serverid;		/**add by chenwenmin, for GB35114 */
    char *sign1;		/**add by chenwenmin, for GB35114 */
    char *keyversion;		/**add by chenwenmin, for GB35114 */
    char *cryptkey;		/**add by chenwenmin, for GB35114 */
    char *sign2;		/**add by chenwenmin, for GB35114 */
  };


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Allocate a SecurityInfo element.
 * @param header The element to work on.
 */
  int osip_note_init (osip_note_t ** header);
/**
 * Parse a SecurityInfo element.
 * @param header The element to work on.
 * @param hvalue The string to parse.
 */
  int osip_note_parse (osip_note_t * header, const char *hvalue);
/**
 * Get a string representation of a SecurityInfo element.
 * @param header The element to work on.
 * @param dest A pointer on the new allocated string.
 */
  int osip_note_to_str (const osip_note_t * header, char **dest);
/**
 * Free a SecurityInfo element.
 * @param header The element to work on.
 */
  void osip_note_free (osip_note_t * header);
/**
 * Clone a SecurityInfo element.
 * @param header The element to work on.
 * @param dest A pointer on the copy of the element.
 */
  int osip_note_clone (const osip_note_t * header,
  			   osip_note_t ** dest);

/**
 * Get value of the auth_type parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_auth_type (const osip_note_t * header);
/**
 * Add the auth_type parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_auth_type (osip_note_t * header, char *value);
/**
 * Get value of the username parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_username (osip_note_t * header);
/**
 * Add the username parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_username (osip_note_t * header, char *value);
/**
 * Get value of the realm parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_realm (osip_note_t * header);
/**
 * Add the realm parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_realm (osip_note_t * header, char *value);
/**
 * Get value of the nonce parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_nonce (osip_note_t * header);
/**
 * Add the nonce parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_nonce (osip_note_t * header, char *value);
/**
 * Get value of the uri parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_uri (osip_note_t * header);
/**
 * Add the uri parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_uri (osip_note_t * header, char *value);
/**
 * Get value of the response parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_response (osip_note_t * header);
/**
 * Add the response parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_response (osip_note_t * header, char *value);
/**
 * Get value of the digest parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_digest (osip_note_t * header);
/**
 * Add the digest parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_digest (osip_note_t * header, char *value);
/**
 * Get value of the algorithm parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_algorithm (osip_note_t * header);
/**
 * Add the algorithm parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_algorithm (osip_note_t * header, char *value);
/**
 * Get value of the cnonce parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_cnonce (osip_note_t * header);
/**
 * Add the cnonce parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_cnonce (osip_note_t * header, char *value);
/**
 * Get value of the opaque parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_opaque (osip_note_t * header);
/**
 * Add the opaque parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_opaque (osip_note_t * header, char *value);
/**
 * Get value of the message_qop parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_message_qop (osip_note_t * header);
/**
 * Add the message_qop parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_message_qop (osip_note_t * header, char *value);
/**
 * Get value of the nonce_count parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_nonce_count (osip_note_t * header);
/**
 * Add the nonce_count parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_nonce_count (osip_note_t * header, char *value);
/**
 * Get value of the version parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_version (osip_note_t * header);
/**
 * Add the version parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_version (osip_note_t * header,
					char *value);
/**
 * Get value of the targetname parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_targetname (osip_note_t * header);
/**
 * Add the targetname parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_targetname (osip_note_t * header,
					char *value);
/**
 * Get value of the gssapi_data parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_gssapi_data (osip_note_t * header);
/**
 * Add the gssapi_data parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_gssapi_data (osip_note_t * header,
					char *value);
/**
 * Get value of the crand parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_crand (osip_note_t * header);
/**
 * Add the crand parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_crand (osip_note_t * header,
				     char *value);
/**
 * Get value of the cnum parameter from a SecurityInfo element.
 * @param header The element to work on.
 */
  char *osip_note_get_cnum (osip_note_t * header);
/**
 * Add the gssapi_data parameter from a SecurityInfo element.
 * @param header The element to work on.
 * @param value The value of the new parameter.
 */
  void osip_note_set_cnum (osip_note_t * header,
				    char *value);

char *osip_note_get_random1 (osip_note_t * header);
void osip_note_set_random1 (osip_note_t * header, char *value);

char *osip_note_get_random2 (osip_note_t * header);
void osip_note_set_random2 (osip_note_t * header, char *value);

char *osip_note_get_deviceid (osip_note_t * header);
void osip_note_set_deviceid (osip_note_t * header, char *value);

char *osip_note_get_serverid (osip_note_t * header);
void osip_note_set_serverid (osip_note_t * header, char *value);

char *osip_note_get_sign1 (osip_note_t * header);
void osip_note_set_sign1 (osip_note_t * header, char *value);

char *osip_note_get_keyversion (osip_note_t * header);
void osip_note_set_keyversion (osip_note_t * header, char *value);

char *osip_note_get_cryptkey (osip_note_t * header);
void osip_note_set_cryptkey (osip_note_t * header, char *value);

char *osip_note_get_sign2 (osip_note_t * header);
void osip_note_set_sign2 (osip_note_t * header, char *value);



#ifdef __cplusplus
}
#endif

/** @} */

#endif


