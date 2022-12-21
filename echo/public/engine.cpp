
#include <cstdlib>
#include <cassert>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <climits>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <event2/thread.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/util.h>

#include <openssl/ssl.h>

#include <lsquic.h>

#include "engine.h"

#define CLOSE_SOCKET close
#define CHAR_CAST

class OpenSSLInitializer
{
public:
	OpenSSLInitializer()
	{
		::SSL_library_init();
		::ERR_load_crypto_strings();
		::SSL_load_error_strings();
		::OpenSSL_add_all_algorithms();
	}
};

static OpenSSLInitializer openssl_initializer;

///////////////////////////////////////////////////////////////////////////////////////////////////////////

class LsQuicInitializer
{
public:
	LsQuicInitializer()
	{
		if (0 != ::lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER))
		{
			::exit(EXIT_FAILURE);
		}
	}
	~LsQuicInitializer()
	{
		::lsquic_global_cleanup();
		::exit(EXIT_FAILURE);
	}
};

static LsQuicInitializer lsquic_initializer;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

const char* Engine::s_keylog_dir = nullptr;

const char* Engine::s_sess_resume_file = nullptr;

Engine::Engine(bool is_server, bool is_http)
{
	_engine_flags = 0;
	if (is_server) _engine_flags |= LSENG_SERVER;
	if (is_http) _engine_flags |= LSENG_HTTP;

	_engine_settings = new ::lsquic_engine_settings;
	_engine_api = new ::lsquic_engine_api;
	_header_api = new ::lsquic_hset_if;
	_stream_api = new ::lsquic_stream_if;
}

Engine::~Engine()
{
	stopEventLoop();
	stopThread();

	delete _engine_settings;
	delete _engine_api;
	delete _header_api;
	delete _stream_api;
}

bool Engine::start()
{
	startThread();
	return true;
}

bool Engine::stop()
{
	stopEventLoop();
	stopThread();
	return true;
}

void Engine::startThread()
{
	if (_thread != nullptr)
	{
		return;
	}

	_thread = std::make_shared<std::thread>([this]()
	{
		startEventLoop();

		startQuicEngine();

		add_event_timer();

		init_ssl_ctx();

		_evThreadStarted.set();

		::event_base_loop(_base, EVLOOP_NO_EXIT_ON_EMPTY);

		stopEventLoop();
	});
	assert(_thread);

	_evThreadStarted.wait();
}

void Engine::stopThread()
{
	if (_thread == nullptr)
	{
		return;
	}

	_thread->join();
	_thread.reset();
	_thread = nullptr;
}

bool Engine::startEventLoop()
{
	::evthread_use_pthreads();

	auto cfg = ::event_config_new();
	if (::event_config_set_flag(cfg, EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST) < 0)
	{
		return false;
	}

	_base = ::event_base_new_with_config(cfg);

	::event_config_free(cfg);

	assert(_base);

	return true;
}

bool Engine::stopEventLoop()
{
	if (_base != nullptr)
	{
		::event_base_loopbreak(_base);
		::event_base_free(_base);
		_base = nullptr;
	}
	return true;
}

int Engine::add_event_socket()
{
	_evSocket = ::event_new(_base, _sockfd, EV_READ | EV_PERSIST, Engine::on_ev_read, this);
	if (_evSocket)
	{
		::event_add(_evSocket, nullptr);
		return 0;
	}
	else
	{
		return -1;
	}
}

void Engine::remove_event_socket()
{
	if (_evSocket != nullptr)
	{
		::event_del(_evSocket);
		::event_free(_evSocket);
		_evSocket = nullptr;
	}
}

void Engine::add_event_timer()
{
	_evTimer = ::event_new(_base, -1, 0, Engine::on_ev_timer, this);
}

void Engine::remove_event_timer()
{
	if (_evTimer != nullptr)
	{
		::event_del(_evTimer);
		::event_free(_evTimer);
		_evTimer = nullptr;
	}
}

bool Engine::startQuicEngine()
{
	if (_engine_flags & LSENG_SERVER)
	{
		return startQuicServer();
	}
	else
	{
		return startQuicClient();
	}
}

bool Engine::startQuicServer()
{
	initQuicEngine(LSENG_SERVER);

	struct sockaddr_in serv_addr{};
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = ::htons(_port);
	serv_addr.sin_addr.s_addr = ::inet_addr(_address.c_str());

	int sockfd = ::socket(PF_INET, SOCK_DGRAM, 0);
	if (-1 == sockfd)
	{
		CLOSE_SOCKET(sockfd);
		return false;
	}

	if (0 != ::bind(sockfd, (sockaddr*)&serv_addr, sizeof(serv_addr)))
	{
		CLOSE_SOCKET(sockfd);
		return false;
	}

	int flags = ::fcntl(sockfd, F_GETFL);
	if (-1 == flags)
	{
		CLOSE_SOCKET(sockfd);
		return false;
	}
	flags |= O_NONBLOCK;
	if (0 != ::fcntl(sockfd, F_SETFL, flags))
	{
		CLOSE_SOCKET(sockfd);
		return false;
	}

	SOCKOPT_VAL on{ 1 };

	int s;
	if (AF_INET == serv_addr.sin_family)
	{
		s = ::setsockopt(sockfd, IPPROTO_IP, IP_RECVORIGDSTADDR, CHAR_CAST &on, sizeof(on));
	}
	else
	{
		s = ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
	}
	if (0 != s)
	{
		CLOSE_SOCKET(sockfd);
		return false;
	}

	if (AF_INET == serv_addr.sin_family)
	{
		on = 1;
		s = ::setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, CHAR_CAST &on, sizeof(on));
		if (0 != s)
		{
			CLOSE_SOCKET(sockfd);
			return false;
		}
	}

	on = 1;
	s = ::setsockopt(sockfd, SOL_SOCKET, SO_RXQ_OVFL, &on, sizeof(on));
	if (0 != s)
	{
		CLOSE_SOCKET(sockfd);
		return false;
	}

	if (!(_sp_flags & SPORT_FRAGMENT_OK))
	{
		if (AF_INET == serv_addr.sin_family)
		{
			on = IP_PMTUDISC_PROBE;
			s = ::setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &on, sizeof(on));
			if (0 != s)
			{
				CLOSE_SOCKET(sockfd);
				return false;
			}
		}
		else if (AF_INET6 == serv_addr.sin_family)
		{
			int on_ = IP_PMTUDISC_PROBE;
			s = ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &on_, sizeof(on_));
		}
	}

	if (_sp_flags & SPORT_SET_SNDBUF)
	{
		s = ::setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, CHAR_CAST &_sndbuf, sizeof(_sndbuf));
		if (0 != s)
		{
			CLOSE_SOCKET(sockfd);
			return false;
		}
	}

	if (_sp_flags & SPORT_SET_RCVBUF)
	{
		s = ::setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, CHAR_CAST &_rcvbuf, sizeof(_rcvbuf));
		if (0 != s)
		{
			CLOSE_SOCKET(sockfd);
			return false;
		}
	}

//	socklen_t socklen;
//	if (0 != ::getsockname(sockfd, serv_addr.sin_addr, &socklen))
//	{
//		CLOSE_SOCKET(sockfd);
//		return false;
//	}

	_sockfd = sockfd;
	_sp_flags |= SPORT_SERVER;

	add_event_socket();

	return true;
}

bool Engine::startQuicClient()
{
	initQuicEngine(0);

	return true;
}

void Engine::initQuicEngine(uint32_t engineFlags)
{
	initQuicSetting(engineFlags);

	_engine = ::lsquic_engine_new(engineFlags, _engine_api);
}

bool Engine::initQuicSetting(uint32_t engineFlags)
{
	make_stream_api();

	_engine_api->ea_packets_out = Engine::api_send_packets;
	_engine_api->ea_packets_out_ctx = this;
	_engine_api->ea_stream_if = _stream_api;
	_engine_api->ea_stream_if_ctx = this;
	_engine_api->ea_get_ssl_ctx = Engine::api_peer_ssl_ctx;
	if (engineFlags & LSENG_HTTP)
	{
		make_header_api();
		_engine_api->ea_hsi_if = _header_api;
		_engine_api->ea_hsi_ctx = this;
	}

	::lsquic_engine_init_settings(_engine_settings, engineFlags);

	_engine_settings->es_versions = (1 << LSQVER_I001); // RFC version only

	char errBuf[256];
	int r = ::lsquic_engine_check_settings(_engine_settings, engineFlags, errBuf, sizeof(errBuf));
	if (r == -1)
	{
		return false;
	}

	_engine_settings->es_delay_onclose = 1;
	_engine_api->ea_settings = _engine_settings;

	return true;
}

void Engine::on_ev_connect(SOCKET_TYPE sockfd, short event, void* arg)
{
}

void Engine::on_ev_read(SOCKET_TYPE sockfd, short event, void* arg)
{

}

void Engine::on_ev_timer(SOCKET_TYPE sockfd, short event, void* arg)
{
	auto engine_ = reinterpret_cast<Engine*>(arg);
	assert(engine_);
	engine_->onProcessConnect();
}

void Engine::onProcessConnect()
{
	int diff;
	struct timeval timeout{};

	::lsquic_engine_process_conns(_engine);

	if (::lsquic_engine_earliest_adv_tick(_engine, &diff))
	{
		if (diff < 0
			|| (unsigned)diff < _engine_settings->es_clock_granularity)
		{
			timeout.tv_sec = 0;
			timeout.tv_usec = _engine_settings->es_clock_granularity;
		}
		else
		{
			timeout.tv_sec = (unsigned)diff / 1000000;
			timeout.tv_usec = (unsigned)diff % 1000000;
		}

		if (!_running)
		{
			::event_add(_evTimer, &timeout);
		}
	}
}

void Engine::make_stream_api()
{
	_stream_api->on_new_conn = Engine::on_new_conn;
	_stream_api->on_conn_closed = Engine::on_conn_closed;
	_stream_api->on_new_stream = Engine::on_new_stream;
	_stream_api->on_read = Engine::on_read;
	_stream_api->on_write = Engine::on_write;
	_stream_api->on_close = Engine::on_close;
	_stream_api->on_hsk_done = Engine::on_hsk_done;
	_stream_api->on_goaway_received = Engine::on_goaway_received;
	_stream_api->on_conncloseframe_received = Engine::on_conncloseframe_received;
}

lsquic_conn_ctx_t* Engine::on_new_conn(void* ectx, lsquic_conn_t* conn)
{
	return nullptr;
}

lsquic_stream_ctx_t* Engine::on_new_stream(void* ectx, lsquic_stream_t* stream)
{
	return nullptr;
}

void Engine::on_read(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{

}

void Engine::on_write(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{

}

void Engine::on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{

}

void Engine::on_conn_closed(lsquic_conn_t* conn)
{

}

void Engine::on_hsk_done(lsquic_conn_t* conn, lsquic_hsk_status s)
{

}

void Engine::on_goaway_received(lsquic_conn_t* conn)
{

}

void Engine::on_conncloseframe_received(lsquic_conn_t* conn,
	int app_error, uint64_t code, const char* reason, int reason_len)
{

}

void Engine::make_header_api()
{
	_header_api->hsi_create_header_set = Engine::header_set_create;
	_header_api->hsi_prepare_decode = Engine::header_set_prepare;
	_header_api->hsi_process_header = Engine::header_set_process;
	_header_api->hsi_discard_header_set = Engine::header_set_discard;
}

void* Engine::header_set_create(void* ctx, lsquic_stream_t* stream, int is_push_promise)
{
	return nullptr;
}

lsxpack_header* Engine::header_set_prepare(void* hset, lsxpack_header* hdr, size_t space)
{
	return nullptr;
}

int Engine::header_set_process(void* hset, lsxpack_header* hdr)
{
	return 0;
}

void Engine::header_set_discard(void* hset)
{

}

int Engine::api_send_packets(void* ectx, const lsquic_out_spec* specs, unsigned int n_specs)
{
	return 0;
}

ssl_ctx_st* Engine::api_peer_ssl_ctx(void* peer_ctx, const sockaddr* local)
{
	return nullptr;
}

bool Engine::init_ssl_ctx()
{
	unsigned char ticket_keys[48];

	_ssl_ctx = ::SSL_CTX_new(::TLS_method());
	if (!_ssl_ctx)
	{
		return false;
	}

	::SSL_CTX_set_min_proto_version(_ssl_ctx, TLS1_3_VERSION);
	::SSL_CTX_set_max_proto_version(_ssl_ctx, TLS1_3_VERSION);
	::SSL_CTX_set_default_verify_paths(_ssl_ctx);

	/* This is obviously test code: the key is just an array of NUL bytes */
	memset(ticket_keys, 0, sizeof(ticket_keys));
	if (1 != ::SSL_CTX_set_tlsext_ticket_keys(_ssl_ctx, ticket_keys, sizeof(ticket_keys)))
	{
		return false;
	}

	if (s_keylog_dir)
	{
		::SSL_CTX_set_keylog_callback(_ssl_ctx, Engine::keylog_log_line);
	}

	if (s_sess_resume_file)
	{
		::SSL_CTX_set_session_cache_mode(_ssl_ctx, SSL_SESS_CACHE_CLIENT);
		::SSL_CTX_set_early_data_enabled(_ssl_ctx, 1);
		::SSL_CTX_sess_set_new_cb(_ssl_ctx, Engine::on_ssl_new_session);
	}

	return true;
}

FILE* Engine::keylog_open_file(const SSL* ssl)
{
	const lsquic_conn_t* conn;
	const lsquic_cid_t* cid;
	FILE* fh;
	int sz;
	unsigned i;
	char id_str[MAX_CID_LEN * 2 + 1];
	char path[PATH_MAX];
	static const char b2c[17] = "0123456789ABCDEF";

	conn = ::lsquic_ssl_to_conn(ssl);
	cid = ::lsquic_conn_id(conn);
	for (i = 0; i < cid->len; ++i)
	{
		id_str[i * 2 + 0] = b2c[cid->idbuf[i] >> 4];
		id_str[i * 2 + 1] = b2c[cid->idbuf[i] & 0xF];
	}
	id_str[i * 2] = '\0';
	sz = snprintf(path, sizeof(path), "%s/%s.keys", s_keylog_dir, id_str);
	if ((size_t)sz >= sizeof(path))
	{
		return nullptr;
	}
	fh = fopen(path, "ab");
	if (!fh)
	{

	}
	return fh;
}

void Engine::keylog_log_line(const SSL* ssl, const char* line)
{
	FILE* file;

	file = keylog_open_file(ssl);
	if (file)
	{
		::fputs(line, file);
		::fputs("\n", file);
		::fclose(file);
	}
}

int Engine::on_ssl_new_session(SSL* ssl, SSL_SESSION* session)
{
	/* Our client is rather limited: only one file and only one ticket
	 * can be saved.  A more flexible client implementation would call
	 * lsquic_ssl_to_conn() and maybe save more tickets based on its
	 * own configuration.
	 */
	if (!s_sess_resume_file)
	{
		return 0;
	}

	unsigned char* buf;
	size_t bufsz, nw;
	FILE* file;

	if (0 != ::lsquic_ssl_sess_to_resume_info(ssl, session, &buf, &bufsz))
	{
		return 0;
	}

	file = ::fopen(s_sess_resume_file, "wb");
	if (!file)
	{
		::free(buf);
		return 0;
	}

	nw = ::fwrite(buf, 1, bufsz, file);
	if (nw == bufsz)
	{
		s_sess_resume_file = nullptr;  /* Save just one ticket */
	}
	else
	{

	}

	::fclose(file);
	::free(buf);

	return 0;
}
