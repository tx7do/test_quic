#pragma once

#include <string>
#include <atomic>
#include <mutex>
#include <thread>

#include <lsquic.h>

#include "event_ex.h"

struct event_base;
struct event;

struct lsquic_engine;
struct lsquic_engine_settings;
struct lsquic_engine_api;
struct lsquic_hset_if;
struct lsquic_stream_if;
struct lsquic_stream;

struct ssl_ctx_st;
struct ssl_st;
struct ssl_session_st;

#define SOCKOPT_VAL int
#define SOCKET_TYPE int

enum sport_flags : std::int32_t
{
	SPORT_FRAGMENT_OK = (1 << 0),
	SPORT_SET_SNDBUF = (1 << 1), /* SO_SNDBUF */
	SPORT_SET_RCVBUF = (1 << 2), /* SO_RCVBUF */
	SPORT_SERVER = (1 << 3),
	SPORT_CONNECT = (1 << 4),
};

class Engine
{
public:
	explicit Engine(bool is_server = true, bool is_http = false);
	~Engine();

public:
	bool start();

	bool stop();

private:
	bool startEventLoop();
	bool stopEventLoop();

	int add_event_socket();
	void remove_event_socket();

	void add_event_timer();
	void remove_event_timer();

private:
	void startThread();

	void stopThread();

private:
	bool startQuicEngine();

	bool startQuicServer();

	bool startQuicClient();

	void initQuicEngine(uint32_t engineFlags);

	bool initQuicSetting(uint32_t engineFlags);

private:
	bool init_ssl_ctx();

	static const char* s_keylog_dir;
	static const char* s_sess_resume_file;

	static FILE* keylog_open_file(const ssl_st* ssl);
	static void keylog_log_line(const ssl_st* ssl, const char* line);
	static int on_ssl_new_session(ssl_st* ssl, ssl_session_st* session);

private:
	static void on_ev_connect(SOCKET_TYPE sockfd, short event, void* arg);
	static void on_ev_read(SOCKET_TYPE sockfd, short event, void* arg);
	static void on_ev_timer(SOCKET_TYPE sockfd, short event, void* arg);

private:
	void onProcessConnect();

private:
	static int api_send_packets(void* ectx, const lsquic_out_spec* specs, unsigned n_specs);
	static ssl_ctx_st* api_peer_ssl_ctx(void* peer_ctx, const sockaddr* local);

private:
	void make_stream_api();

	static lsquic_conn_ctx_t* on_new_conn(void* ectx, lsquic_conn_t* conn);
	static lsquic_stream_ctx_t* on_new_stream(void* ectx, lsquic_stream* stream);
	static void on_read(lsquic_stream* stream, lsquic_stream_ctx_t* sctx);
	static void on_write(lsquic_stream* stream, lsquic_stream_ctx_t* sctx);
	static void on_close(lsquic_stream* stream, lsquic_stream_ctx_t* sctx);
	static void on_conn_closed(lsquic_conn_t* conn);
	static void on_hsk_done(lsquic_conn_t* conn, lsquic_hsk_status s);
	static void on_goaway_received(lsquic_conn_t* conn);
	static void
	on_conncloseframe_received(lsquic_conn_t* conn, int app_error, uint64_t code, const char* reason, int reason_len);

private:
	void make_header_api();

	static void* header_set_create(void* ctx, lsquic_stream_t* stream, int is_push_promise);
	static lsxpack_header* header_set_prepare(void* hset, lsxpack_header* hdr, size_t space);
	static int header_set_process(void* hset, lsxpack_header* hdr);
	static void header_set_discard(void* hset);

private:
	struct event_base* _base{ nullptr };

	struct event* _evSocket{ nullptr };
	struct event* _evTimer{ nullptr };

private:
	SOCKET_TYPE _sockfd{ -1 };

	SOCKOPT_VAL _sndbuf{ -1 };   /* If SPORT_SET_SNDBUF is set */
	SOCKOPT_VAL _rcvbuf{ -1 };   /* If SPORT_SET_RCVBUF is set */

private:
	struct lsquic_engine_settings* _engine_settings{ nullptr };
	struct lsquic_engine_api* _engine_api{ nullptr };
	struct lsquic_hset_if* _header_api{ nullptr };
	struct lsquic_stream_if* _stream_api{ nullptr };
	struct lsquic_engine* _engine{ nullptr };

	struct ssl_ctx_st* _ssl_ctx{ nullptr };

	uint32_t _engine_flags{ 0 };

	std::atomic_bool _is_http{ false };

private:
	std::string _address;
	int _port{ 9000 };

	int _sp_flags{ 0 };

private:
	std::atomic_bool _running{ false };

	std::shared_ptr<std::thread> _thread;
	mutable std::mutex _mutex;
	CEvent _evThreadStarted;
};
