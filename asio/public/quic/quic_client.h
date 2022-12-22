#pragma once

#include "../asio_udp.h"
#include "../asio_ssl.h"

#include "detail/engine_impl.h"
#include "detail/socket_impl.h"

namespace quic
{

	class connection;
	class stream;

	class client
	{
		friend class connection;
		detail::engine_impl engine;
		detail::socket_impl socket;
	public:
		using executor_type = detail::engine_impl::executor_type;

		client(udp::socket&& socket, ssl::context& ctx); // TODO: noexcept
		client(udp::socket&& socket, ssl::context& ctx, const settings& s); // TODO: noexcept
		client(const executor_type& ex, const udp::endpoint& endpoint, ssl::context& ctx);
		client(const executor_type& ex, const udp::endpoint& endpoint, ssl::context& ctx, const settings& s);

		executor_type get_executor() const;

		udp::endpoint local_endpoint() const;

		void connect(connection& conn, const udp::endpoint& endpoint, const char* hostname);

		void close(error_code& ec);
		void close();
	};

} // namespace quic
