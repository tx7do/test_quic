#pragma once

#include <variant>
#include <boost/circular_buffer.hpp>
#include <boost/intrusive/list.hpp>

#include "../../asio_udp.h"
#include "../quic_connection_id.h"
#include "stream_impl.h"

struct lsquic_conn;

namespace quic::detail
{

	struct accept_operation;
	struct stream_accept_operation;
	struct stream_connect_operation;

	using stream_list = boost::intrusive::list<stream_impl>;

	inline void list_erase(stream_impl& s, stream_list& from)
	{
		from.erase(from.iterator_to(s));
	}

	inline void list_transfer(stream_impl& s, stream_list& from, stream_list& to)
	{
		from.erase(from.iterator_to(s));
		to.push_back(s);
	}

	struct connection_context
	{
		bool incoming;
		explicit connection_context(bool incoming) noexcept
			: incoming(incoming)
		{
		}
	};

	struct incoming_connection : connection_context
	{
		lsquic_conn* handle;
		boost::circular_buffer<lsquic_stream*> incoming_streams; // TODO: allocator

		incoming_connection(lsquic_conn* handle, uint32_t max_streams)
			: connection_context(true),
			  handle(handle),
			  incoming_streams(max_streams)
		{
		}
	};

	namespace connection_state
	{

		struct accepting
		{
			accept_operation* op = nullptr;
		};

		struct open
		{
			lsquic_conn& handle;
			boost::circular_buffer<lsquic_stream*> incoming_streams;
			stream_list connecting_streams;
			stream_list accepting_streams;
			stream_list open_streams;
			stream_list closing_streams;
			error_code ec;

			explicit open(lsquic_conn& handle) noexcept
				: handle(handle)
			{
			}
		};

		struct going_away
		{
			lsquic_conn& handle;
			stream_list open_streams;
			stream_list closing_streams;
			error_code ec;

			explicit going_away(lsquic_conn& handle) noexcept
				: handle(handle)
			{
			}
		};

		struct error
		{
			error_code ec;
		};

		struct closed
		{
		};

		using variant = std::variant<accepting, open, going_away, error, closed>;

		enum class transition
		{
			none,
			accepting_to_closed,
			open_to_going_away,
			open_to_closed,
			open_to_error,
			going_away_to_closed,
			going_away_to_error,
			error_to_closed,
		};

		bool is_open(const variant& state);
		connection_id id(const variant& state, error_code& ec);
		udp::endpoint remote_endpoint(const variant& state, error_code& ec);

		void on_connect(variant& state, lsquic_conn* handle);
		void on_handshake(variant& state, int status);
		void accept(variant& state, accept_operation& op);
		void accept_incoming(variant& state, incoming_connection&& incoming);
		void on_accept(variant& state, lsquic_conn* handle);

		bool stream_connect(variant& state, stream_connect_operation& op);
		stream_impl* on_stream_connect(variant& state, lsquic_stream* handle, bool is_http);

		void stream_accept(variant& state, stream_accept_operation& op, bool is_http);
		stream_impl* on_stream_accept(variant& state, lsquic_stream* handle, bool is_http);

		transition goaway(variant& state, error_code& ec);
		transition on_remote_goaway(variant& state);
		transition reset(variant& state, error_code ec);
		transition close(variant& state, error_code& ec);
		transition on_close(variant& state);
		transition on_remote_close(variant& state, error_code ec);
		void destroy(variant& state);

	} // namespace connection_state

} // namespace quic::detail
