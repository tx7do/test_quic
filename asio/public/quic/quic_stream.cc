#include <lsquic.h>

#include "quic_connection.h"
#include "quic_stream.h"
#include "detail/connection_impl.h"

namespace quic
{
	stream::stream(connection& conn)
		: stream(conn.impl)
	{
	}
	stream::stream(detail::connection_impl& conn)
		: impl(conn)
	{
	}

	stream::~stream()
	{
		impl.reset();
	}

	stream::executor_type stream::get_executor() const
	{
		return impl.get_executor();
	}

	bool stream::is_open() const
	{
		return impl.is_open();
	}

	stream_id stream::id(error_code& ec) const
	{
		return impl.id(ec);
	}

	stream_id stream::id() const
	{
		error_code ec;
		auto sid = id(ec);
		if (ec)
		{
			throw system_error(ec);
		}
		return sid;
	}

	void stream::flush(error_code& ec)
	{
		impl.flush(ec);
	}

	void stream::flush()
	{
		error_code ec;
		flush(ec);
		if (ec)
		{
			throw system_error(ec);
		}
	}

	void stream::shutdown(int how, error_code& ec)
	{
		impl.shutdown(how, ec);
	}

	void stream::shutdown(int how)
	{
		error_code ec;
		shutdown(how, ec);
		if (ec)
		{
			throw system_error(ec);
		}
	}

	void stream::close(error_code& ec)
	{
		detail::stream_close_sync op;
		impl.close(op);
		op.wait();
		ec = std::get<0>(*op.result);
	}

	void stream::close()
	{
		error_code ec;
		close(ec);
		if (ec)
		{
			throw system_error(ec);
		}
	}

	void stream::reset()
	{
		impl.reset();
	}

} // namespace quic
