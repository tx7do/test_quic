#pragma once

#include "../asio_ssl.h"
#include "../asio_udp.h"
#include "../quic/quic_server.h"

namespace h3
{

	class acceptor;
	class server_connection;
	class stream;

	class server
	{
		friend class acceptor;
		quic::detail::engine_impl engine;
	public:
		using executor_type = quic::detail::engine_impl::executor_type;

		explicit server(const executor_type& ex);
		server(const executor_type& ex, const quic::settings& s);

		executor_type get_executor() const;

		void close();
	};

	class acceptor
	{
		friend class server_connection;
		quic::detail::socket_impl impl;
	public:
		using executor_type = quic::detail::socket_impl::executor_type;

		acceptor(server& s, udp::socket&& socket, ssl::context& ctx);
		acceptor(server& s, const udp::endpoint& endpoint, ssl::context& ctx);

		executor_type get_executor() const;

		udp::endpoint local_endpoint() const;

		void listen(int backlog);

		template<typename CompletionToken>
		decltype(auto) async_accept(server_connection& conn,
			CompletionToken&& token)
		{
			return impl.async_accept(conn, std::forward<CompletionToken>(token));
		}

		void accept(server_connection& conn, error_code& ec);
		void accept(server_connection& conn);

		void close();
	};

	class server_connection
	{
		friend class acceptor;
		friend class stream;
		friend class quic::detail::socket_impl;
		quic::detail::connection_impl impl;
	public:
		using executor_type = quic::detail::connection_impl::executor_type;

		explicit server_connection(acceptor& a)
			: impl(a.impl)
		{
		}

		executor_type get_executor() const;

		bool is_open() const;

		quic::connection_id id(error_code& ec) const;
		quic::connection_id id() const;

		udp::endpoint remote_endpoint(error_code& ec) const;
		udp::endpoint remote_endpoint() const;

		template<typename CompletionToken>
		decltype(auto) async_accept(stream& s, CompletionToken&& token)
		{
			return impl.async_accept<stream>(s, std::forward<CompletionToken>(token));
		}

		void accept(stream& s, error_code& ec);
		void accept(stream& s);

		void go_away(error_code& ec);
		void go_away();

		void close(error_code& ec);
		void close();
	};

} // namespace h3
