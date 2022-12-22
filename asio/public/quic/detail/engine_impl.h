#pragma once

#include <memory>
#include <mutex>

#include <boost/asio/steady_timer.hpp>

#include "../quic_settings.h"

struct lsquic_engine;
struct lsquic_conn;
struct lsquic_stream;
struct lsquic_out_spec;

namespace quic::detail
{

	struct connection_impl;
	struct stream_impl;
	struct socket_impl;

	struct engine_deleter
	{
		void operator()(lsquic_engine* e) const;
	};
	using lsquic_engine_ptr = std::unique_ptr<lsquic_engine, engine_deleter>;

	struct engine_impl
	{
		mutable std::mutex mutex;
		boost::asio::any_io_executor ex;
		boost::asio::steady_timer timer;
		lsquic_engine_ptr handle;
		socket_impl* client;
		uint32_t max_streams_per_connection;
		bool is_http;

		void process(std::unique_lock<std::mutex>& lock);
		void reschedule(std::unique_lock<std::mutex>& lock);
		void on_timer();

		engine_impl(const boost::asio::any_io_executor& ex, socket_impl* client, const settings* s, unsigned flags);
		~engine_impl();

		using executor_type = boost::asio::any_io_executor;
		executor_type get_executor() const
		{
			return ex;
		}

		void close();

		int send_packets(const lsquic_out_spec* specs, unsigned n_specs);

		stream_impl* on_new_stream(connection_impl& c, lsquic_stream* stream);
	};

} // namespace quic::detail
