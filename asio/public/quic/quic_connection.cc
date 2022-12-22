#include "quic_connection.h"
#include "quic_client.h"
#include "quic_server.h"
#include "quic_stream.h"

namespace quic
{

	connection::connection(acceptor& a)
		: impl(a.impl)
	{
	}
	connection::connection(client& c)
		: impl(c.socket)
	{
	}

	connection::connection(client& c, const udp::endpoint& endpoint, const char* hostname)
		: impl(c.socket)
	{
		c.connect(*this, endpoint, hostname);
	}

	connection::executor_type connection::get_executor() const
	{
		return impl.get_executor();
	}

	bool connection::is_open() const
	{
		return impl.is_open();
	}

	connection_id connection::id(error_code& ec) const
	{
		return impl.id(ec);
	}

	connection_id connection::id() const
	{
		error_code ec;
		auto i = impl.id(ec);
		if (ec)
		{
			throw system_error(ec);
		}
		return i;
	}

	udp::endpoint connection::remote_endpoint(error_code& ec) const
	{
		return impl.remote_endpoint(ec);
	}

	udp::endpoint connection::remote_endpoint() const
	{
		error_code ec;
		auto e = impl.remote_endpoint(ec);
		if (ec)
		{
			throw system_error(ec);
		}
		return e;
	}

	void connection::connect(stream& s, error_code& ec)
	{
		auto op = detail::stream_connect_sync{ s.impl };
		impl.connect(op);
		op.wait();
		ec = std::get<0>(*op.result);
	}

	void connection::connect(stream& s)
	{
		error_code ec;
		connect(s, ec);
		if (ec)
		{
			throw system_error(ec);
		}
	}

	void connection::accept(stream& s, error_code& ec)
	{
		auto op = detail::stream_accept_sync{ s.impl };
		impl.accept(op);
		op.wait();
		ec = std::get<0>(*op.result);
	}

	void connection::accept(stream& s)
	{
		error_code ec;
		accept(s, ec);
		if (ec)
		{
			throw system_error(ec);
		}
	}

	void connection::go_away(error_code& ec)
	{
		impl.go_away(ec);
	}

	void connection::go_away()
	{
		error_code ec;
		impl.go_away(ec);
		if (ec)
		{
			throw system_error(ec);
		}
	}

	void connection::close(error_code& ec)
	{
		impl.close(ec);
	}

	void connection::close()
	{
		error_code ec;
		close(ec);
		if (ec)
		{
			throw system_error(ec);
		}
	}
}