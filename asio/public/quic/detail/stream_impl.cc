#include <lsquic.h>

#include "engine_impl.h"
#include "stream_impl.h"
#include "socket_impl.h"
#include "connection_impl.h"

namespace quic::detail
{

	stream_impl::stream_impl(connection_impl& conn)
		: engine(conn.socket.engine),
		  svc(boost::asio::use_service<service<stream_impl >>
			  (
				  boost::asio::query(engine.get_executor(), boost::asio::execution::context)
			  )
		  ),
		  conn(conn),
		  state(stream_state::closed{})
	{
		svc.add(*this);
	}

	stream_impl::~stream_impl()
	{
		svc.remove(*this);
	}

	void stream_impl::service_shutdown()
	{
		stream_state::destroy(state);
	}

	stream_impl::executor_type stream_impl::get_executor() const
	{
		return engine.get_executor();
	}

	bool stream_impl::is_open() const
	{
		auto lock = std::unique_lock{ engine.mutex };
		return stream_state::is_open(state);
	}

	stream_id stream_impl::id(error_code& ec) const
	{
		auto lock = std::unique_lock{ engine.mutex };
		return stream_state::id(state, ec);
	}

	void stream_impl::read_headers(stream_header_read_operation& op)
	{
		auto lock = std::unique_lock{ engine.mutex };
		if (stream_state::read_headers(state, op))
		{
			engine.process(lock);
		}
	}

	void stream_impl::read_some(stream_data_operation& op)
	{
		auto lock = std::unique_lock{ engine.mutex };
		if (stream_state::read(state, op))
		{
			engine.process(lock);
		}
	}

	void stream_impl::on_read()
	{
		stream_state::on_read(state);
	}

	void stream_impl::write_some(stream_data_operation& op)
	{
		auto lock = std::unique_lock{ engine.mutex };
		if (stream_state::write(state, op))
		{
			engine.process(lock);
		}
	}

	void stream_impl::write_headers(stream_header_write_operation& op)
	{
		auto lock = std::unique_lock{ engine.mutex };
		if (stream_state::write_headers(state, op))
		{
			engine.process(lock);
		}
	}

	void stream_impl::on_write()
	{
		stream_state::on_write(state);
	}

	void stream_impl::flush(error_code& ec)
	{
		auto lock = std::unique_lock{ engine.mutex };
		stream_state::flush(state, ec);
		if (!ec)
		{
			engine.process(lock);
		}
	}

	void stream_impl::shutdown(int how, error_code& ec)
	{
		auto lock = std::unique_lock{ engine.mutex };
		stream_state::shutdown(state, how, ec);
		if (!ec)
		{
			engine.process(lock);
		}
	}

	void stream_impl::close(stream_close_operation& op)
	{
		auto lock = std::unique_lock{ engine.mutex };
		const auto t = stream_state::close(state, op);
		if (t == stream_state::transition::open_to_closing)
		{
			conn.on_open_stream_closing(*this);
			engine.process(lock);
		}
	}

	void stream_impl::on_close()
	{
		const auto t = stream_state::on_close(state);
		switch (t)
		{
		case stream_state::transition::closing_to_closed:
			conn.on_closing_stream_closed(*this);
			break;
		case stream_state::transition::open_to_closed:
		case stream_state::transition::open_to_error:
			conn.on_open_stream_closed(*this);
			break;
		default:
			break;
		}
	}

	void stream_impl::reset()
	{
		auto lock = std::unique_lock{ engine.mutex };
		const auto t = stream_state::reset(state);
		switch (t)
		{
		case stream_state::transition::accepting_to_closed:
			conn.on_accepting_stream_closed(*this);
			break;
		case stream_state::transition::connecting_to_closed:
			conn.on_connecting_stream_closed(*this);
			break;
		case stream_state::transition::closing_to_closed:
			conn.on_closing_stream_closed(*this);
			break;
		case stream_state::transition::open_to_closed:
			conn.on_open_stream_closed(*this);
			break;
		default:
			return;
		}
		engine.process(lock);
	}

} // namespace quic
