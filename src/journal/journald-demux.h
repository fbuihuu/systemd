/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-server.h"

typedef struct UserInstanceContext UserInstanceContext;

int server_open_demux_socket(Server *s, const char *demux_socket);
int server_forward_datagram_to_demux(
                const Server *s,
                int fd,
                const char *buf,
                size_t buf_len,
                const struct ucred *ucred,
                const UserInstanceContext *c);

int client_open_demux_socket(Server *s, const char *demux_socket);

UserInstanceContext* user_instance_context_free(UserInstanceContext *c);
