#pragma once

#include "../asio_ssl.h"
#include "../asio_udp.h"
#include "../quic/quic_client.h"

namespace h3
{

	class client_connection;
	class stream;

	class client
	{
		friend class client_connection;
		quic::detail::engine_impl engine;
		quic::detail::socket_impl socket;
	public:
		using executor_type = quic::detail::engine_impl::executor_type;

		client(udp::socket&& socket, ssl::context& ctx);

		client(udp::socket&& socket, ssl::context& ctx, const quic::settings& s);

		client(const executor_type& ex, const udp::endpoint& endpoint, ssl::context& ctx);

		client(const executor_type& ex, const udp::endpoint& endpoint, ssl::context& ctx, const quic::settings& s);

		executor_type get_executor() const;

		udp::endpoint local_endpoint() const;

		void connect(client_connection& conn, const udp::endpoint& endpoint, const char* hostname);

		void close(error_code& ec);

		void close();
	};

	class client_connection
	{
		friend class client;
		friend class stream;
		quic::detail::connection_impl impl;
	public:
		using executor_type = quic::detail::connection_impl::executor_type;

		explicit client_connection(client& c)
			: impl(c.socket)
		{
		}

		client_connection(client& c, const udp::endpoint& endpoint,
			const char* hostname)
			: impl(c.socket)
		{
			c.connect(*this, endpoint, hostname);
		}

		executor_type get_executor() const;

		bool is_open() const;

		quic::connection_id id(error_code& ec) const;
		quic::connection_id id() const;

		udp::endpoint remote_endpoint(error_code& ec) const;
		udp::endpoint remote_endpoint() const;

		template<typename CompletionToken>
		decltype(auto) async_connect(stream& s, CompletionToken&& token)
		{
			return impl.async_connect<stream>(s, std::forward<CompletionToken>(token));
		}

		void connect(stream& s, error_code& ec);
		void connect(stream& s);

		void go_away(error_code& ec);
		void go_away();

		void close(error_code& ec);
		void close();
	};

} // namespace h3
