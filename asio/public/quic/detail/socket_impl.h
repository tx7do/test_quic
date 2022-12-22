#pragma once

#include <boost/intrusive/list.hpp>
#include <boost/circular_buffer.hpp>

#include "../../asio_ssl.h"
#include "connection_impl.h"

struct lsquic_conn;
struct lsquic_out_spec;

namespace quic::detail
{

	struct engine_impl;
	struct connection_impl;

	union sockaddr_union
	{
		sockaddr_storage storage;
		sockaddr addr;
		sockaddr_in addr4;
		sockaddr_in6 addr6;
	};

	using connection_list = boost::intrusive::list<connection_impl>;

	inline void list_erase(connection_impl& s, connection_list& from)
	{
		from.erase(from.iterator_to(s));
	}

	inline void list_transfer(connection_impl& s, connection_list& from, connection_list& to)
	{
		from.erase(from.iterator_to(s));
		to.push_back(s);
	}

	struct socket_impl : boost::intrusive::list_base_hook<>
	{
		engine_impl& engine;
		udp::socket socket;
		ssl::context& ssl;
		udp::endpoint local_addr; // socket's bound address
		boost::circular_buffer<incoming_connection> incoming_connections;
		connection_list accepting_connections;
		connection_list open_connections;
		bool receiving = false;

		socket_impl(engine_impl& engine, udp::socket&& socket, ssl::context& ssl);
		socket_impl(engine_impl& engine, const udp::endpoint& endpoint, bool is_server, ssl::context& ssl);
		~socket_impl()
		{
			close();
		}

		using executor_type = boost::asio::any_io_executor;
		executor_type get_executor() const;

		udp::endpoint local_endpoint() const
		{
			return local_addr;
		}

		void listen(int backlog);

		void connect(connection_impl& c, const udp::endpoint& endpoint, const char* hostname);
		void on_connect(connection_impl& c, lsquic_conn* conn);

		void accept(connection_impl& c, accept_operation& op);
		connection_context* on_accept(lsquic_conn* conn);

		template<typename Connection, typename CompletionToken>
		decltype(auto) async_accept(Connection& conn, CompletionToken&& token)
		{
			auto& c = conn.impl;
			return boost::asio::async_initiate<CompletionToken, void(error_code)>(
				[this, &c](auto h)
				{
					using Handler = std::decay_t<decltype(h)>;
					using op_type = accept_async<Handler, executor_type>;
					auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
					auto op = handler_ptr<op_type, Handler>{ p, &p->handler };
					accept(c, *op);
					op.release(); // release ownership
				}, token);
		}

		void close();

		void abort_connections(error_code ec);

		void start_recv();
		void on_readable();
		void on_writeable();

		const lsquic_out_spec* send_packets(const lsquic_out_spec* begin, const lsquic_out_spec* end, error_code& ec);

		size_t recv_packet(iovec iov, udp::endpoint& peer, sockaddr_union& self, int& ecn, error_code& ec);
	};

} // namespace quic::detail
