/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "io-util.h"
#include "journald-console.h"
#include "journald-kmsg.h"
#include "journald-demux.h"
#include "journald-server.h"
#include "journald-syslog.h"
#include "journald-wall.h"
#include "process-util.h"
#include "selinux-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "syslog-util.h"
#include "user-util.h"

struct UserInstanceContext {
        Server *server;
        int fd;

        uid_t uid;
        pid_t pid;

        char *runtime_dir;
        sd_event_source *event_source;
};

UserInstanceContext* user_instance_context_free(UserInstanceContext *c) {
        if (!c)
                return NULL;

        sd_event_source_disable_unref(c->event_source);

        free(c->runtime_dir);
        safe_close(c->fd);

        return mfree(c);
}

static int on_client_mux_io(sd_event_source *e, int fd, uint32_t revents, void *userdata) {
        Server *s = userdata;

        assert(s);

        log_warning("Received %s from mux socket , logs sent to /dev/log will be missed until system journal is started again",
                    revents & EPOLLERR ? "EPOLLERR" : "EPOLLHUP");

        s->demux_fd = safe_close(s->demux_fd);

        /* FIXME: attempt to reconnect to the system mux socket when it will appear again */

        return 0;
}

int client_open_demux_socket(Server *s, const char *demux_socket) {
        _cleanup_close_ int fd = -1;
        ssize_t n;
        size_t len;
        int r;

        assert(s->demux_fd == -1);

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        r = connect_unix_path(fd, AT_FDCWD, demux_socket);
        if (r < 0)
                return log_error_errno(r, "connect_unix_path(%s) failed: %m", demux_socket);

        (void) shutdown(fd, SHUT_RD);

        len = strlen(s->runtime_directory);

        n = send(fd, s->runtime_directory, len, MSG_NOSIGNAL);
        if (n < 0)
                return log_error_errno(errno, "Failed to send runtime directory path to system instance: %m");
        if ((size_t)n != len)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "runtime directory path not properly sent to system instance, aborting");

        r = sd_event_add_io(s->event, &s->demux_event_source, fd, 0, on_client_mux_io, s);
        if (r < 0)
                return log_error_errno(r, "Failed to watch demux socket: %m");

        s->demux_fd = TAKE_FD(fd);
        return 0;
}

int server_forward_datagram_to_demux(
                const Server *s,
                int fd,
                const char *buf,
                size_t buf_len,
                const struct ucred *ucred,
                const UserInstanceContext *c) {

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control;
        union sockaddr_union sa;
        struct msghdr msghdr;
        struct cmsghdr *cmsg;
        struct iovec iovec;
        const char *dst;
        int r;

        assert(ucred);
        assert(fd == s->syslog_fd || fd == s->native_fd);

        dst = strjoina(c->runtime_dir, "/", fd == s->syslog_fd ? "dev-log" : "socket");
        r = sockaddr_un_set_path(&sa.un, dst);
        if (r < 0)
                return log_error_errno(r, "Forwarding socket path %s too long for AF_UNIX, not forwarding: %m", dst);

        msghdr.msg_name = &sa.sa;
        msghdr.msg_namelen = r;

        zero(control);
        msghdr.msg_control = &control;
        msghdr.msg_controllen = sizeof(control);

        cmsg = CMSG_FIRSTHDR(&msghdr);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_CREDENTIALS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
        memcpy(CMSG_DATA(cmsg), ucred, sizeof(struct ucred));
        msghdr.msg_controllen = cmsg->cmsg_len;

        iovec = IOVEC_MAKE((char *) buf, buf_len);
        msghdr.msg_iov = &iovec;
        msghdr.msg_iovlen = 1;

        /* Forward the message we received to the user instance. we currently can't set the SO_TIMESTAMP
         * auxiliary data, and hence we don't. */

        if (sendmsg(fd, &msghdr, MSG_NOSIGNAL) >= 0)
                return 0;

        /* FIXME: add better error handling */

        return log_error_errno(errno, "Forwarding datagram to process " PID_FMT " failed: %m", c->pid);
}

static int server_process_user_instance_data(Server *s, int fd, UserInstanceContext *context) {
        char buf[PATH_MAX];
        ssize_t n;

        /* The user instance is supposed to send us its runtime directory path */

        n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0)
                return -errno;
        if (n == 0)
                return -EIO;
        if ((size_t) n >= sizeof(buf))
                return -ENAMETOOLONG;

        buf[n] = 0;

        context->runtime_dir = strdup(buf);
        if (!context->runtime_dir)
                return -ENOMEM;

        return 0;
}

static int on_user_instance_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        UserInstanceContext *c = userdata;
        Server *s = c->server;
        int r = 0;

        assert(s);
        assert(c);
        assert(SERVER_IS_SYSTEM(s));

        if (revents & (EPOLLHUP|EPOLLERR)) {
                log_error("User instance (pid=" PID_FMT " uid=" UID_FMT ") disconnected", c->pid, c->uid);

                hashmap_remove(s->user_instance_contexts, UID_TO_PTR(c->uid));
                goto disconnect;
        }

        if (!(revents & EPOLLIN)) {
                log_warning("Got invalid poll event %"PRIu32" from user instance (uid=" UID_FMT"), ignoring",
                            revents, c->uid);
                return 0;
        }

        r = server_process_user_instance_data(s, fd, c);
        if (r < 0) {
                log_error_errno(r, "Failed to read user instance (uid=" UID_FMT ") data, disconnecting: %m", c->uid);
                goto disconnect;
        }

        /* Register the new user instance context so the system server will start forwarding the user data to
         * the user instance. */
        r = hashmap_put(s->user_instance_contexts, UID_TO_PTR(c->uid), c);
        if (r < 0)
                goto disconnect;

        /* The user instance is not supposed to send us more messages hence don't be disturbed if it does. */
        r = sd_event_source_set_io_events(c->event_source, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to clear EPOLLIN, ignoring: %m");

        return 0;

disconnect:
        user_instance_context_free(c);
        return r;
}

static int on_server_mux_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        UserInstanceContext *c;
        _cleanup_close_ int cfd = -1;
        Server *s = userdata;
        struct ucred ucred;
        int r;

        assert(source);
        assert(s);
        assert(SERVER_IS_SYSTEM(s));

        cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (cfd < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                return log_error_errno(errno, "Failed to accept incoming socket: %m");
        }

        r = getpeercred(cfd, &ucred);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire peer credentials of incoming socket, refusing: %m");

        c = hashmap_get(s->user_instance_contexts, UID_TO_PTR(ucred.uid));
        if (c)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY),
                                       "Process " PID_FMT " is already listening system logs for user " UID_FMT ", refusing.",
                                       c->pid, c->uid);

        c = new(UserInstanceContext, 1);
        if (!c)
                return log_oom();

        *c = (UserInstanceContext) {
                .server = s,
                .fd = TAKE_FD(cfd),
                .uid = ucred.uid,
                .pid = ucred.pid,
        };

        r = sd_event_add_io(s->event, &c->event_source, c->fd, POLLIN, on_user_instance_io, c);
        if (r < 0) {
                user_instance_context_free(c);
                return log_error_errno(r, "Failed to watch connected user instance socket: %m");
        }

        log_info("Casting logs from uid=" UID_FMT " to process " PID_FMT, ucred.uid, ucred.pid);
        return 0;
}

int server_open_demux_socket(Server *s, const char *demux_socket) {
        _cleanup_close_ int fd = -1;
        union sockaddr_union sa;
        socklen_t sa_len;
        int r;

        assert(s);
        assert(SERVER_IS_SYSTEM(s));

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "SO_PASSCRED failed: %m");

        (void) shutdown(fd, SHUT_WR);

        r = sockaddr_un_set_path(&sa.un, demux_socket);
        if (r < 0)
                return r;
        sa_len = r;

        (void)  sockaddr_un_unlink(&sa.un);

        r = bind(fd, &sa.sa, sa_len);
        if (r < 0)
                return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

        (void) chmod(sa.un.sun_path, 0666);

        if (listen(fd, SOMAXCONN) < 0)
                return -errno;

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        r = sd_event_add_io(s->event, &s->demux_event_source, fd, EPOLLIN, on_server_mux_io, s);
        if (r < 0)
                return log_error_errno(r, "Failed to watch demux socket: %m");

        s->demux_fd = TAKE_FD(fd);
        return 0;
}
