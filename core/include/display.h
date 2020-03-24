/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2021, Linaro Limited
 */

#ifndef __DISPLAY_H
#define __DISPLAY_H

#include <drivers/frame_buffer.h>

void display_init(void);
struct frame_buffer *display_get_frame_buffer(void);
void display_final(void);

#endif /* __DISPLAY_H */

