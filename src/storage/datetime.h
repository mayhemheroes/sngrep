/**************************************************************************
 **
 ** sngrep - SIP Messages flow viewer
 **
 ** Copyright (C) 2013-2019 Ivan Alonso (Kaian)
 ** Copyright (C) 2013-2019 Irontec SL. All rights reserved.
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
 * @file timeval.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions for working with timestamps
 *
 */
#ifndef __SNGREP_TIMEVAL_H
#define __SNGREP_TIMEVAL_H

#include <glib.h>

/**
 * @brief Convert timeval to yyyy/mm/dd format
 */
const gchar *
date_time_date_to_str(GDateTime *time, gchar *out);

/**
 * @brief Convert timeval to HH:MM:SS.mmmmmm format
 */
const gchar *
date_time_time_to_str(GDateTime *time, gchar *out);

/**
 * @brief Calculate the time difference between two timeval
 *
 * @return Human readable time difference in mm:ss format
 */
const gchar *
date_time_to_duration(GDateTime *start, GDateTime *end, gchar *out);

/**
 * @brief Convert timeval diference to +mm:ss.mmmmmm
 */
const gchar *
date_time_to_delta(GDateTime *start, GDateTime *end, gchar *out);

#endif /* __SNGREP_TIMEVAL_H */
