#pragma once

#include "quic_connection_id.h"
#include "detail/connection_impl.h"

namespace quic
{

	class acceptor;
	class client;
	class stream;

	class connection
	{
		friend class acceptor;
		friend class client;
		friend class stream;
		friend class detail::socket_impl;
		detail::connection_impl impl;
	public:
		using executor_type = detail::connection_impl::executor_type;

		explicit connection(acceptor& a);
		explicit connection(client& c);
		connection(client& c, const udp::endpoint& endpoint, const char* hostname);

		executor_type get_executor() const;

		bool is_open() const;

		connection_id id(error_code& ec) const;
		connection_id id() const;

		udp::endpoint remote_endpoint(error_code& ec) const;
		udp::endpoint remote_endpoint() const;

		template<typename CompletionToken>
		decltype(auto) async_connect(stream& s, CompletionToken&& token)
		{
			return impl.async_connect<stream>(s, std::forward<CompletionToken>(token));
		}

		void connect(stream& s, error_code& ec);
		void connect(stream& s);

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

} // namespace quic
