/* ulogd_SYSLOGTCP.c, Version $Revision$
 *
 * ulogd output target for tcp syslog
 *
 * This target produces a syslog entries identical to the LOG target.
 *
 * (C) 2017 by InsZVA <inszva@126.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <syslog.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/statistics.h>

#ifndef SYSLOG_FACILITY_DEFAULT
#define SYSLOG_FACILITY_DEFAULT	"LOG_KERN"
#endif

#ifndef SYSLOG_LEVEL_DEFAULT 
#define SYSLOG_LEVEL_DEFAULT "LOG_NOTICE"
#endif

#ifndef SYSLOG_HOST_DEFAULT
#define SYSLOG_HOST_DEFAULT "127.0.0.1"
#endif

#ifndef SYSLOG_PORT_DEFAULT
#define SYSLOG_PORT_DEFAULT "514"
#endif


#ifndef HOST_NAME_MAX
#warning this libc does not define HOST_NAME_MAX
#define HOST_NAME_MAX	(255+1)
#endif

static char hostname[HOST_NAME_MAX+1];


static struct ulogd_key syslogtcp_inp[] = {
	{
		.type = ULOGD_RET_STRING,
		.name = "print",
	},
};

static struct config_keyset syslogtcp_kset = { 
	.num_ces = 6,
	.ces = {
		{
		.key = "facility", 
		.type = CONFIG_TYPE_STRING, 
		.options = CONFIG_OPT_NONE, 
		.u = { .string = SYSLOG_FACILITY_DEFAULT } 
		},
		{ 
		.key = "level", 
		.type = CONFIG_TYPE_STRING,
		.options = CONFIG_OPT_NONE, 
		.u = { .string = SYSLOG_LEVEL_DEFAULT }
		},
		{
		.key = "host",
		.type = CONFIG_TYPE_STRING,
		.options = CONFIG_OPT_NONE,
		.u = { .string = SYSLOG_HOST_DEFAULT }
		},
		{
		.key = "port",
		.type = CONFIG_TYPE_STRING,
		.options = CONFIG_OPT_NONE,
		.u = { .string = SYSLOG_PORT_DEFAULT }
		},
		{
		.key = "buffer",
		.type = CONFIG_TYPE_INT,
		.options = CONFIG_OPT_NONE,
		.u = { .value = 4 * 1024 * 1024 }
		},
		{
		.key = "flush",
		.type = CONFIG_TYPE_INT,
		.options = CONFIG_OPT_NONE,
		.u = { .value = 3 * 1024 * 1024 }
		}
		
	},
};

struct syslogtcp_instance {
	int syslog_level;
	int syslog_facility;
	char* host;
	char* port;
	int buffer_size;
	int buffer_flush_size;
	int sfd;
	void* buffer;
	int pbuffer;
	int nsend;
};

static inline void _buffer_flush(struct syslogtcp_instance * li) {
	send(li->sfd, li->buffer, li->pbuffer, MSG_NOSIGNAL);
	li->pbuffer = 0;
}

static void _buffered_send(struct syslogtcp_instance * li, void* data, int len) {
	li->nsend++;
	if (li->pbuffer > li->buffer_flush_size) {
		_buffer_flush(li);
	}
	memcpy(li->buffer + li->pbuffer, data, len);
	li->pbuffer += len;
}

static int _output_syslogtcp(struct ulogd_pluginstance *upi)
{
	struct syslogtcp_instance *li = (struct syslogtcp_instance *) &upi->private;
	struct ulogd_key *res = upi->input.keys;

	// TODO: memory?
	char buffer[1024];
	
	if (res[0].u.source->flags & ULOGD_RETF_VALID) {
		char *timestr;
		char *tmp;
		time_t now;

		now = time(NULL);
		timestr = ctime(&now) + 4;
		
		if ((tmp = strchr(timestr, '\n')))
			*tmp = '\0';
		//int msglen = sprintf(buffer, "%.15s %s %s", timestr, "ulogd2",
				//(char *) res[0].u.source->u.value.ptr);
		char * pbuf = buffer;
		appendStr(&pbuf, timestr);
		appendStr(&pbuf, " ");
		appendStr(&pbuf, hostname);
		appendStr(&pbuf, (char *) res[0].u.source->u.value.ptr);
		int msglen = pbuf - buffer;
		
		if (msglen == -1) {
			ulogd_log(ULOGD_ERROR, "Could not create message\n");
			return ULOGD_IRET_ERR;
		}

		// 4~8us no buffer
		// 0us buffered
		/*
		int ret = send(li->sfd, buffer, msglen, MSG_NOSIGNAL);
		if (ret <= 0) {
			ulogd_log(ULOGD_ERROR, "Failure sending message\n");
			if (ret == -1) {
				return ULOGD_IRET_ERR;
			}
		}*/
		_buffered_send(li, buffer, msglen);
		
	}

	return ULOGD_IRET_OK;
}
		
static int syslogtcp_configure(struct ulogd_pluginstance *pi,
			    struct ulogd_pluginstance_stack *stack)
{
	int syslog_facility, syslog_level;
	char *facility, *level;
	struct syslogtcp_instance *li = (struct syslogtcp_instance *) &pi->private;

	/* FIXME: error handling */
	config_parse_file(pi->id, pi->config_kset);

	facility = pi->config_kset->ces[0].u.string;
	level = pi->config_kset->ces[1].u.string;
	li->host = pi->config_kset->ces[2].u.string;
	li->port = pi->config_kset->ces[3].u.string;
	li->buffer_size = pi->config_kset->ces[4].u.value;
	li->buffer_flush_size = pi->config_kset->ces[5].u.value;

	if (!strcmp(facility, "LOG_DAEMON"))
		syslog_facility = LOG_DAEMON;
	else if (!strcmp(facility, "LOG_KERN"))
		syslog_facility = LOG_KERN;
	else if (!strcmp(facility, "LOG_LOCAL0"))
		syslog_facility = LOG_LOCAL0;
	else if (!strcmp(facility, "LOG_LOCAL1"))
		syslog_facility = LOG_LOCAL1;
	else if (!strcmp(facility, "LOG_LOCAL2"))
		syslog_facility = LOG_LOCAL2;
	else if (!strcmp(facility, "LOG_LOCAL3"))
		syslog_facility = LOG_LOCAL3;
	else if (!strcmp(facility, "LOG_LOCAL4"))
		syslog_facility = LOG_LOCAL4;
	else if (!strcmp(facility, "LOG_LOCAL5"))
		syslog_facility = LOG_LOCAL5;
	else if (!strcmp(facility, "LOG_LOCAL6"))
		syslog_facility = LOG_LOCAL6;
	else if (!strcmp(facility, "LOG_LOCAL7"))
		syslog_facility = LOG_LOCAL7;
	else if (!strcmp(facility, "LOG_USER"))
		syslog_facility = LOG_USER;
	else {
		ulogd_log(ULOGD_FATAL, "unknown facility '%s'\n",
			  facility);
		return -EINVAL;
	}

	if (!strcmp(level, "LOG_EMERG"))
		syslog_level = LOG_EMERG;
	else if (!strcmp(level, "LOG_ALERT"))
		syslog_level = LOG_ALERT;
	else if (!strcmp(level, "LOG_CRIT"))
		syslog_level = LOG_CRIT;
	else if (!strcmp(level, "LOG_ERR"))
		syslog_level = LOG_ERR;
	else if (!strcmp(level, "LOG_WARNING"))
		syslog_level = LOG_WARNING;
	else if (!strcmp(level, "LOG_NOTICE"))
		syslog_level = LOG_NOTICE;
	else if (!strcmp(level, "LOG_INFO"))
		syslog_level = LOG_INFO;
	else if (!strcmp(level, "LOG_DEBUG"))
		syslog_level = LOG_DEBUG;
	else {
		ulogd_log(ULOGD_FATAL, "unknown level '%s'\n",
			  level);
		return -EINVAL;
	}

	li->syslog_level = syslog_level;
	li->syslog_facility = syslog_facility;

	return 0;
}

static int syslogtcp_fini(struct ulogd_pluginstance *pi)
{
	struct syslogtcp_instance *li = (struct syslogtcp_instance *) &pi->private;
	_buffer_flush(li);
	if (li->sfd != -1)
		close(li->sfd);
	ulogd_log(ULOGD_NOTICE, "syslog_tcp total send:%d\n", li->nsend);
	free(li->buffer);
	
	return 0;
}

static int syslogtcp_start(struct ulogd_pluginstance *pi)
{
	struct syslogtcp_instance *li = (struct syslogtcp_instance *) &pi->private;
	struct addrinfo hints;
    struct addrinfo *result, *rp;
	int s;
	char* tmp;

	if (gethostname(hostname, sizeof(hostname)) < 0) {
		ulogd_log(ULOGD_FATAL, "can't gethostname(): %s\n",
			  strerror(errno));
		return -EINVAL;
	}

	/* truncate hostname */
	if ((tmp = strchr(hostname, '.')))
		*tmp = '\0';

	li->pbuffer = 0;
	li->nsend = 0;
	// allocate 4M buffer
	li->buffer = malloc(li->buffer_size);

	li->sfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;   
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

	s = getaddrinfo(li->host, li->port, &hints, &result);
    if (s != 0) {
       ulogd_log(ULOGD_FATAL, "getaddrinfo: %s\n", gai_strerror(s));
       return -EINVAL;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
       li->sfd = socket(rp->ai_family, rp->ai_socktype,
                    rp->ai_protocol);
       if (li->sfd == -1)
           continue;

       if (connect(li->sfd, rp->ai_addr, rp->ai_addrlen) != -1)
           break;

       close(li->sfd);
    }
	freeaddrinfo(result);

    if (rp == NULL) {
       ulogd_log(ULOGD_FATAL, "Could not connect\n");
       return -EINVAL;
    }

	return 0;
}

static struct ulogd_plugin syslogtcp_plugin = {
	.name = "SYSLOGTCP",
	.input = {
		.keys = syslogtcp_inp,
		.num_keys = ARRAY_SIZE(syslogtcp_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset	= &syslogtcp_kset,
	.priv_size	= sizeof(struct syslogtcp_instance),
	
	.configure	= &syslogtcp_configure,
	.start		= &syslogtcp_start,
	.stop		= &syslogtcp_fini,
	.interp		= &_output_syslogtcp,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&syslogtcp_plugin);
}

