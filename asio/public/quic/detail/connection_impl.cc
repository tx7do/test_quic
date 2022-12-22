#include "connection_impl.h"
#include "../quic_client.h"

#include <lsquic.h>

namespace quic
{
	namespace detail
	{

		connection_impl::connection_impl(socket_impl& socket)
			: connection_context(false),
			  svc(boost::asio::use_service<service<connection_impl>>(
					  boost::asio::query(socket.get_executor(), boost::asio::execution::context)
				  )
			  ),
			  socket(socket),
			  state(connection_state::closed{})
		{
			svc.add(*this);
		}

		connection_impl::~connection_impl()
		{
			error_code ec_ignored;
			close(ec_ignored);
			svc.remove(*this);
		}

		void connection_impl::service_shutdown()
		{
			connection_state::destroy(state);
		}

		connection_impl::executor_type connection_impl::get_executor() const
		{
			return socket.get_executor();
		}

		bool connection_impl::is_open() const
		{
			auto lock = std::unique_lock{ socket.engine.mutex };
			return connection_state::is_open(state);
		}

		connection_id connection_impl::id(error_code& ec) const
		{
			auto lock = std::unique_lock{ socket.engine.mutex };
			return connection_state::id(state, ec);
		}

		udp::endpoint connection_impl::remote_endpoint(error_code& ec) const
		{
			auto lock = std::unique_lock{ socket.engine.mutex };
			return connection_state::remote_endpoint(state, ec);
		}

		void connection_impl::connect(stream_connect_operation& op)
		{
			auto lock = std::unique_lock{ socket.engine.mutex };
			if (connection_state::stream_connect(state, op))
			{
				socket.engine.process(lock);
			}
		}

		stream_impl* connection_impl::on_connect(lsquic_stream_t* stream)
		{
			return connection_state::on_stream_connect(state, stream, socket.engine.is_http);
		}

		void connection_impl::accept(stream_accept_operation& op)
		{
			auto lock = std::unique_lock{ socket.engine.mutex };
			connection_state::stream_accept(state, op, socket.engine.is_http);
		}

		stream_impl* connection_impl::on_accept(lsquic_stream* stream)
		{
			return connection_state::on_stream_accept(state, stream, socket.engine.is_http);
		}

		void connection_impl::go_away(error_code& ec)
		{
			auto lock = std::unique_lock{ socket.engine.mutex };
			const auto t = connection_state::goaway(state, ec);
			if (t == connection_state::transition::open_to_going_away)
			{
				socket.engine.process(lock);
			}
		}

		void connection_impl::close(error_code& ec)
		{
			auto lock = std::unique_lock{ socket.engine.mutex };
			const auto t = connection_state::close(state, ec);
			switch (t)
			{
			case connection_state::transition::accepting_to_closed:
				list_erase(*this, socket.accepting_connections);
				break;
			case connection_state::transition::open_to_closed:
			case connection_state::transition::going_away_to_closed:
				list_erase(*this, socket.open_connections);
				socket.engine.process(lock);
				break;
			default:
				break;
			}
		}

		void connection_impl::on_close()
		{
			const auto t = connection_state::on_close(state);
			switch (t)
			{
			case connection_state::transition::open_to_error:
			case connection_state::transition::open_to_closed:
			case connection_state::transition::going_away_to_error:
			case connection_state::transition::going_away_to_closed:
				list_erase(*this, socket.open_connections);
				break;
			default:
				break;
			}
		}

		void connection_impl::on_handshake(int status)
		{
			connection_state::on_handshake(state, status);
		}

		void connection_impl::on_remote_goaway()
		{
			connection_state::on_remote_goaway(state);
		}

		void connection_impl::on_remote_close(int app_error, uint64_t code)
		{
			error_code ec;
			if (app_error == -1)
			{
				ec = make_error_code(connection_error::reset);
			}
			else if (app_error)
			{
				ec.assign(code, application_category());
			}
			else if ((code & 0xffff'ffff'ffff'ff00) == 0x0100)
			{
				// CRYPTO_ERROR 0x0100-0x01ff
				ec.assign(code & 0xff, tls_category());
			}
			else
			{
				ec.assign(code, transport_category());
			}

			const auto t = connection_state::on_remote_close(state, ec);
			switch (t)
			{
			case connection_state::transition::open_to_error:
			case connection_state::transition::open_to_closed:
			case connection_state::transition::going_away_to_error:
			case connection_state::transition::going_away_to_closed:
				list_erase(*this, socket.open_connections);
				break;
			default:
				break;
			}
		}

		void connection_impl::on_accepting_stream_closed(stream_impl& s)
		{
			if (std::holds_alternative<connection_state::open>(state))
			{
				auto& o = *std::get_if<connection_state::open>(&state);
				list_erase(s, o.accepting_streams);
			}
		}

		void connection_impl::on_connecting_stream_closed(stream_impl& s)
		{
			if (std::holds_alternative<connection_state::open>(state))
			{
				auto& o = *std::get_if<connection_state::open>(&state);
				list_erase(s, o.connecting_streams);
			}
		}

		void connection_impl::on_open_stream_closing(stream_impl& s)
		{
			if (std::holds_alternative<connection_state::open>(state))
			{
				auto& o = *std::get_if<connection_state::open>(&state);
				list_transfer(s, o.open_streams, o.closing_streams);
			}
		}

		void connection_impl::on_open_stream_closed(stream_impl& s)
		{
			if (std::holds_alternative<connection_state::open>(state))
			{
				auto& o = *std::get_if<connection_state::open>(&state);
				list_erase(s, o.open_streams);
			}
			else if (std::holds_alternative<connection_state::going_away>(state))
			{
				auto& g = *std::get_if<connection_state::going_away>(&state);
				list_erase(s, g.open_streams);
			}
		}

		void connection_impl::on_closing_stream_closed(stream_impl& s)
		{
			if (std::holds_alternative<connection_state::open>(state))
			{
				auto& o = *std::get_if<connection_state::open>(&state);
				list_erase(s, o.closing_streams);
			}
			else if (std::holds_alternative<connection_state::going_away>(state))
			{
				auto& g = *std::get_if<connection_state::going_away>(&state);
				list_erase(s, g.closing_streams);
			}
		}

	} // namespace detail

} // namespace quic
