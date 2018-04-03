/* Copyright (C) 2017 by John Schember <john@nachtimwald.com>
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#ifndef __HNS_ANDROID_H__
#define __HNS_ANDROID_H__

#if defined(ANDROID) || defined(__ANDROID__)

char **hns_get_android_server_list(size_t max_servers, size_t *num_servers);
void hns_library_cleanup_android(void);

#endif

#endif /* __HNS_ANDROID_H__ */
