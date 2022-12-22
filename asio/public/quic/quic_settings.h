#pragma once

#include <chrono>
#include <stdexcept>

struct lsquic_engine_settings;

namespace quic
{

	struct bad_setting : std::runtime_error
	{
		using runtime_error::runtime_error;
	};

	struct settings
	{
		std::chrono::seconds handshake_timeout;

		std::chrono::seconds idle_timeout;

		uint32_t max_streams_per_connection;

		uint32_t connection_flow_control_window;

		uint32_t incoming_stream_flow_control_window;

		uint32_t outgoing_stream_flow_control_window;
	};

	settings default_client_settings();
	settings default_server_settings();

	bool check_client_settings(const settings& s, std::string* message);
	bool check_server_settings(const settings& s, std::string* message);

	namespace detail
	{

		void read_settings(settings& out, const lsquic_engine_settings& in);
		void write_settings(const settings& in, lsquic_engine_settings& out);

	} // namespace detail

} // namespace quic
