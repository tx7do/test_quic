#include <lsquic.h>

#include "h3_server.h"
#include "h3_client.h"
#include "h3_stream.h"

namespace h3
{

	stream::stream(client_connection& conn)
		: quic::stream(conn.impl)
	{
	}
	stream::stream(server_connection& conn)
		: quic::stream(conn.impl)
	{
	}

	void stream::read_headers(fields& f, error_code& ec)
	{
		auto op = quic::detail::stream_header_read_sync{ f };
		impl.read_headers(op);
		op.wait();
		ec = std::get<0>(*op.result);
	}
	void stream::read_headers(fields& f)
	{
		error_code ec;
		read_headers(f, ec);
		if (ec)
		{
			throw system_error(ec);
		}
	}

	void stream::write_headers(const fields& f, error_code& ec)
	{
		auto op = quic::detail::stream_header_write_sync{ f };
		impl.write_headers(op);
		op.wait();
		ec = std::get<0>(*op.result);
	}
	void stream::write_headers(const fields& f)
	{
		error_code ec;
		write_headers(f, ec);
		if (ec)
		{
			throw system_error(ec);
		}
	}

} // namespace h3
