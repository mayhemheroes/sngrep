/**************************************************************************
 **
 ** sngrep - SIP Messages flow viewer
 **
 ** Copyright (C) 2013-2015 Ivan Alonso (Kaian)
 ** Copyright (C) 2013-2015 Irontec SL. All rights reserved.
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **
 ****************************************************************************/
/**
 * @file media.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in media.h
 */

#include "config.h"
#include <string.h>
#include <stdlib.h>
#include "media.h"
#include "rtp.h"

sdp_media_t *
media_create(struct sip_msg *msg)
{
    sdp_media_t *media;;

    // Allocate memory for this media structure
    if (!(media = malloc(sizeof(sdp_media_t))))
        return NULL;

    // Initialize all fields
    memset(media, 0, sizeof(sdp_media_t));
    media->msg = msg;
    return media;
}

void
media_set_port(sdp_media_t *media, u_short port)
{
    media->port = port;
}

void
media_set_type(sdp_media_t *media, const char *type)
{
    strcpy(media->type, type);
}

void
media_set_address(sdp_media_t *media, const char *address)
{
    strcpy(media->address, address);
}

void
media_set_format(sdp_media_t *media, const char *format)
{
    strcpy(media->format, format);
}

void
media_set_format_code(sdp_media_t *media, int code)
{
    media->fmtcode = code;
}

const char *
media_get_address(sdp_media_t *media)
{
    return media->address;
}

u_short
media_get_port(sdp_media_t *media)
{
    return media->port;
}

const char *
media_get_type(sdp_media_t *media)
{
    return media->type;
}

const char *
media_get_format(sdp_media_t *media)
{
    return rtp_get_codec(media->fmtcode, media->format);
}

int
media_get_format_code(sdp_media_t *media)
{
    return media->fmtcode;
}


