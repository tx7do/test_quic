#include <lsquic.h>
#include <lsxpack_header.h>

#include "connection_impl.h"
#include "engine_impl.h"
#include "socket_impl.h"
#include "stream_impl.h"

#include "recv_header_set.h"

namespace quic::detail
{

	void engine_deleter::operator()(lsquic_engine* e) const
	{
		::lsquic_engine_destroy(e);
	}

	engine_impl::~engine_impl()
	{
		close();
	}

	stream_impl* engine_impl::on_new_stream(connection_impl& c, lsquic_stream_t* stream)
	{
		const auto id = ::lsquic_stream_id(stream);
		const int server = !client;
		if ((id & 1) == server)
		{
			return c.on_connect(stream);
		}
		else
		{
			return c.on_accept(stream);
		}
	}

	void engine_impl::close()
	{
		auto lock = std::unique_lock{ mutex };
		::lsquic_engine_cooldown(handle.get());
		process(lock);
	}

	void engine_impl::process(std::unique_lock<std::mutex>& lock)
	{
		::lsquic_engine_process_conns(handle.get());
		reschedule(lock);
	}

	void engine_impl::reschedule(std::unique_lock<std::mutex>& lock)
	{
		int micros = 0;
		if (!::lsquic_engine_earliest_adv_tick(handle.get(), &micros))
		{
			if (client && client->receiving)
			{
				client->receiving = false;
				client->socket.cancel();
			}
			timer.cancel();
			return;
		}
		if (micros <= 0)
		{
			process(lock);
			return;
		}
		const auto dur = std::chrono::microseconds{ micros };
		timer.expires_after(dur);
		timer.async_wait([this](error_code ec)
		{
			if (!ec)
			{
				on_timer();
			}
		});
	}

	void engine_impl::on_timer()
	{
		auto lock = std::unique_lock{ mutex };
		process(lock);
	}

	int engine_impl::send_packets(const lsquic_out_spec* specs, unsigned n_specs)
	{
		auto p = specs;
		const auto end = std::next(p, n_specs);
		while (p < end)
		{
			socket_impl& socket = *static_cast<socket_impl*>(p->peer_ctx);
			error_code ec;
			p = socket.send_packets(p, end, ec);
			if (ec)
			{
				break;
			}
		}
		return std::distance(specs, p);
	}

	static lsquic_conn_ctx_t* on_new_conn(void* ectx, lsquic_conn_t* conn)
	{
		auto estate = static_cast<engine_impl*>(ectx);
		auto cctx = ::lsquic_conn_get_ctx(conn);

		if (cctx)
		{
			auto c = reinterpret_cast<connection_impl*>(cctx);
			c->socket.on_connect(*c, conn);
			return cctx;
		}

		const sockaddr* local = nullptr;
		const sockaddr* peer = nullptr;
		int r = ::lsquic_conn_get_sockaddr(conn, &local, &peer);
		if (r != 0)
		{
			return nullptr;
		}

		auto peer_ctx = ::lsquic_conn_get_peer_ctx(conn, local);
		assert(peer_ctx);
		auto& socket = *static_cast<socket_impl*>(peer_ctx);
		return reinterpret_cast<lsquic_conn_ctx*>(socket.on_accept(conn));
	}

	static lsquic_stream_ctx_t* on_new_stream(void* ectx, lsquic_stream_t* stream)
	{
		auto estate = static_cast<engine_impl*>(ectx);
		if (stream == nullptr)
		{
			return nullptr;
		}
		auto conn = ::lsquic_stream_conn(stream);
		auto ctx = reinterpret_cast<connection_context*>(::lsquic_conn_get_ctx(conn));
		assert(ctx);
		if (ctx->incoming)
		{
			auto c = static_cast<incoming_connection*>(ctx);
			assert(!c->incoming_streams.full());
			c->incoming_streams.push_back(stream);
			return nullptr;
		}
		else
		{
			auto c = static_cast<connection_impl*>(ctx);
			auto s = estate->on_new_stream(*c, stream);
			return reinterpret_cast<lsquic_stream_ctx_t*>(s);
		}
	}

	static void on_read(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
	{
		auto s = reinterpret_cast<stream_impl*>(sctx);
		s->on_read();
	}

	static void on_write(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
	{
		auto s = reinterpret_cast<stream_impl*>(sctx);
		s->on_write();
	}

	static void on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
	{
		auto s = reinterpret_cast<stream_impl*>(sctx);
		if (s)
		{
			s->on_close();
		}
	}

	static void on_conn_closed(lsquic_conn_t* conn)
	{
		auto cctx = ::lsquic_conn_get_ctx(conn);
		if (!cctx)
		{
			return;
		}
		auto c = reinterpret_cast<connection_impl*>(cctx);
		c->on_close();
	}

	static void on_hsk_done(lsquic_conn_t* conn, lsquic_hsk_status s)
	{
		auto cctx = ::lsquic_conn_get_ctx(conn);
		if (!cctx)
		{
			return;
		}
		auto c = reinterpret_cast<connection_impl*>(cctx);
		c->on_handshake(s);
	}

	void on_goaway_received(lsquic_conn_t* conn)
	{
		auto cctx = ::lsquic_conn_get_ctx(conn);
		if (!cctx)
		{
			return;
		}
		auto c = reinterpret_cast<connection_impl*>(cctx);
		c->on_remote_goaway();
	}

	void
	on_conncloseframe_received(lsquic_conn_t* conn, int app_error, uint64_t code, const char* reason, int reason_len)
	{
		auto ctx = reinterpret_cast<connection_context*>(::lsquic_conn_get_ctx(conn));
		if (!ctx)
		{
			return;
		}
		assert(!ctx->incoming);
		auto c = reinterpret_cast<connection_impl*>(ctx);
		c->on_remote_close(app_error, code);
	}

	static constexpr lsquic_stream_if make_stream_api()
	{
		lsquic_stream_if api = {};
		api.on_new_conn = on_new_conn;
		api.on_conn_closed = on_conn_closed;
		api.on_new_stream = on_new_stream;
		api.on_read = on_read;
		api.on_write = on_write;
		api.on_close = on_close;
		api.on_hsk_done = on_hsk_done;
		api.on_goaway_received = on_goaway_received;
		api.on_conncloseframe_received = on_conncloseframe_received;
		return api;
	}

	static void* header_set_create(void* ctx, lsquic_stream_t* stream, int is_push_promise)
	{
		// TODO: store this in stream_impl to avoid allocation?
		return new recv_header_set(is_push_promise);
	}

	static lsxpack_header* header_set_prepare(void* hset, lsxpack_header* hdr, size_t space)
	{
		auto headers = reinterpret_cast<recv_header_set*>(hset);
		auto& header = headers->header;
		auto& buf = headers->buffer;
		buf.resize(space);
		if (hdr)
		{
			header.buf = buf.data();
			header.val_len = space;
		}
		else
		{
			lsxpack_header_prepare_decode(&header, buf.data(), 0, space);
		}
		return &header;
	}

	static int header_set_process(void* hset, lsxpack_header* hdr)
	{
		if (hdr)
		{
			auto headers = reinterpret_cast<recv_header_set*>(hset);
			auto name = std::string_view{ hdr->buf + hdr->name_offset, hdr->name_len };
			auto value = std::string_view{ hdr->buf + hdr->val_offset, hdr->val_len };
			const bool never_index = hdr->flags & LSXPACK_NEVER_INDEX;
			auto f = headers->fields.insert(name, value, never_index);
		}
		return 0;
	}

	static void header_set_discard(void* hset)
	{
		delete reinterpret_cast<recv_header_set*>(hset);
	}

	static constexpr lsquic_hset_if make_header_api()
	{
		lsquic_hset_if api = {};
		api.hsi_create_header_set = header_set_create;
		api.hsi_prepare_decode = header_set_prepare;
		api.hsi_process_header = header_set_process;
		api.hsi_discard_header_set = header_set_discard;
		return api;
	}

	static int api_send_packets(void* ectx, const lsquic_out_spec* specs, unsigned n_specs)
	{
		auto estate = static_cast<engine_impl*>(ectx);
		return estate->send_packets(specs, n_specs);
	}

	ssl_ctx_st* api_peer_ssl_ctx(void* peer_ctx, const sockaddr* local)
	{
		auto& socket = *static_cast<socket_impl*>(peer_ctx);
		return socket.ssl.native_handle();
	}

	engine_impl::engine_impl(const boost::asio::any_io_executor& ex,
		socket_impl* client,
		const settings* s,
		unsigned flags)
		: ex(ex), timer(ex), client(client), is_http(flags & LSENG_HTTP)
	{
		lsquic_engine_api api = {};
		api.ea_packets_out = api_send_packets;
		api.ea_packets_out_ctx = this;
		static const lsquic_stream_if stream_api = make_stream_api();
		api.ea_stream_if = &stream_api;
		api.ea_stream_if_ctx = this;
		api.ea_get_ssl_ctx = api_peer_ssl_ctx;
		if (flags & LSENG_HTTP)
		{
			static const lsquic_hset_if header_api = make_header_api();
			api.ea_hsi_if = &header_api;
			api.ea_hsi_ctx = this;
		}

		lsquic_engine_settings es;
		::lsquic_engine_init_settings(&es, flags);
		if (s)
		{
			write_settings(*s, es);
		}
		es.es_versions = (1 << LSQVER_I001); // RFC version only
		char errbuf[256];
		int r = ::lsquic_engine_check_settings(&es, flags, errbuf, sizeof(errbuf));
		if (r == -1)
		{
			throw bad_setting(errbuf);
		}
		es.es_delay_onclose = 1;
		api.ea_settings = &es;

		max_streams_per_connection = es.es_init_max_streams_bidi;

		handle.reset(::lsquic_engine_new(flags, &api));
	}

} // namespace quic::detail
