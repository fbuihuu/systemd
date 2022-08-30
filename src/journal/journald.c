/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-daemon.h"
#include "sd-messages.h"

#include "format-util.h"
#include "journal-authenticate.h"
#include "journald-kmsg.h"
#include "journald-server.h"
#include "journald-syslog.h"
#include "process-util.h"
#include "sigbus.h"

bool arg_user = false;

int main(int argc, char *argv[]) {
        const char *namespace;
        LogTarget log_target;
        Server server;
        int max_argc, r;

        arg_user = streq_ptr(argv[1], "--user");
        max_argc = arg_user ? 3 : 2;

        if (argc > max_argc) {
                log_error("This program accepts '--user' option and takes one or no arguments.");
                return EXIT_FAILURE;
        }

        namespace = argc == max_argc ? empty_to_null(argv[argc - 1]) : NULL;

        log_set_facility(LOG_SYSLOG);

        if (namespace)
                /* If we run for a log namespace, then we ourselves can log to the main journald. */
                log_setup();
        else {
                /* So here's the deal if we run as the main journald: we can't be considered as regular
                 * daemon when it comes to logging hence LOG_TARGET_AUTO won't do the right thing for
                 * us. Hence explicitly log to the console if we're started from a console or to kmsg
                 * otherwise. */
                log_target = isatty(STDERR_FILENO) > 0 ? LOG_TARGET_CONSOLE : LOG_TARGET_KMSG;

                log_set_prohibit_ipc(true); /* better safe than sorry */
                log_set_target(log_target);
                log_parse_environment();
                log_open();
        }

        umask(0022);

        sigbus_install();

        r = server_init(&server, arg_user ? MODE_USER : MODE_SYSTEM, namespace);
        if (r < 0)
                goto finish;

        server_vacuum(&server, false);
        server_flush_to_var(&server, true);
        server_flush_dev_kmsg(&server);

        log_debug("systemd-journald %s instance running as PID "PID_FMT"%s.",
                  SERVER_IS_SYSTEM(&server) ? "system" : "user",
                  getpid_cached(),
                  server.namespace ? strjoina(" for namespace '", server.namespace, "'") : "");

        server_driver_message(&server, 0,
                              "MESSAGE_ID=" SD_MESSAGE_JOURNAL_START_STR,
                              LOG_MESSAGE("Journal started"),
                              NULL);

        /* Make sure to send the usage message *after* flushing the
         * journal so entries from the runtime journals are ordered
         * before this message. See #4190 for some details. */
        server_space_usage_message(&server, NULL);

        for (;;) {
                usec_t t = USEC_INFINITY, n;

                r = sd_event_get_state(server.event);
                if (r < 0) {
                        log_error_errno(r, "Failed to get event loop state: %m");
                        goto finish;
                }
                if (r == SD_EVENT_FINISHED)
                        break;

                n = now(CLOCK_REALTIME);

                if (server.max_retention_usec > 0 && server.oldest_file_usec > 0) {

                        /* The retention time is reached, so let's vacuum! */
                        if (server.oldest_file_usec + server.max_retention_usec < n) {
                                log_info("Retention time reached, rotating.");
                                server_rotate(&server);
                                server_vacuum(&server, false);
                                continue;
                        }

                        /* Calculate when to rotate the next time */
                        t = server.oldest_file_usec + server.max_retention_usec - n;
                }

#if HAVE_GCRYPT
                if (server.persistent_journal) {
                        usec_t u;

                        if (journal_file_next_evolve_usec(server.persistent_journal->file, &u)) {
                                if (n >= u)
                                        t = 0;
                                else
                                        t = MIN(t, u - n);
                        }
                }
#endif

                r = sd_event_run(server.event, t);
                if (r < 0) {
                        log_error_errno(r, "Failed to run event loop: %m");
                        goto finish;
                }

                server_maybe_append_tags(&server);
                server_maybe_warn_forward_syslog_missed(&server);
        }

        log_debug("systemd-journald %s instance stopped as PID "PID_FMT"%s.",
                  SERVER_IS_SYSTEM(&server) ? "system" : "user",
                  getpid_cached(),
                  server.namespace ? strjoina(" for namespace '", server.namespace, "'") : "");

        server_driver_message(&server, 0,
                              "MESSAGE_ID=" SD_MESSAGE_JOURNAL_STOP_STR,
                              LOG_MESSAGE("Journal stopped"),
                              NULL);

finish:
        server_done(&server);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
