#pragma once

#include "../asio_udp.h"
#include "../asio_ssl.h"

#include "detail/engine_impl.h"
#include "detail/socket_impl.h"

namespace quic
{

	class acceptor;
	class connection;


	class server
	{
		friend class acceptor;
		detail::engine_impl engine;
	public:
		using executor_type = detail::engine_impl::executor_type;

		explicit server(const executor_type& ex);

		server(const executor_type& ex, const settings& s);

		executor_type get_executor() const;

		void close();
	};


	class acceptor
	{
		friend class connection;
		detail::socket_impl impl;
	public:
		using executor_type = detail::socket_impl::executor_type;

		acceptor(server& s, udp::socket&& socket, ssl::context& ctx);

		acceptor(server& s, const udp::endpoint& endpoint, ssl::context& ctx);

		executor_type get_executor() const;

		udp::endpoint local_endpoint() const;

		void listen(int backlog);

		template<typename CompletionToken>
		decltype(auto) async_accept(connection& conn, CompletionToken&& token)
		{
			return impl.async_accept(conn, std::forward<CompletionToken>(token));
		}

		void accept(connection& conn, error_code& ec);
		void accept(connection& conn);

		void close();
	};

} // namespace quic
