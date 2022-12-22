#pragma once

#include "../quic/quic_stream.h"
#include "h3_fields.h"

namespace h3
{

	class client_connection;
	class server_connection;

	class stream : public quic::stream
	{
		friend class client_connection;
		friend class server_connection;
		using quic::stream::stream;
	public:
		explicit stream(client_connection& conn);
		explicit stream(server_connection& conn);

		template<typename CompletionToken>
		decltype(auto) async_read_headers(fields& f, CompletionToken&& token)
		{
			return impl.async_read_headers(f, std::forward<CompletionToken>(token));
		}

		void read_headers(fields& f, error_code& ec);
		void read_headers(fields& f);

		template<typename CompletionToken>
		decltype(auto) async_write_headers(const fields& f, CompletionToken&& token)
		{
			return impl.async_write_headers(f, std::forward<CompletionToken>(token));
		}

		void write_headers(const fields& f, error_code& ec);
		void write_headers(const fields& f);
	};

} // namespace h3
