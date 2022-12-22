#pragma once

#include "../asio_error_code.h"

namespace quic
{

	enum class connection_error
	{
		aborted = 1,
		handshake_failed,
		timed_out,
		reset,
		going_away,
		peer_going_away,
	};

	const error_category& connection_category();

	inline error_code make_error_code(connection_error e)
	{
		return { static_cast<int>(e), connection_category() };
	}
	inline error_condition make_error_condition(connection_error e)
	{
		return { static_cast<int>(e), connection_category() };
	}

	enum class stream_error
	{
		eof = 1,
		busy,
		aborted,
		reset,
	};

	const error_category& stream_category();

	inline error_code make_error_code(stream_error e)
	{
		return { static_cast<int>(e), stream_category() };
	}
	inline error_condition make_error_condition(stream_error e)
	{
		return { static_cast<int>(e), stream_category() };
	}

	enum class transport_error
	{
		no_error = 0x0,
		internal_error = 0x1,
		connection_refused = 0x2,
		flow_control_error = 0x3,
		stream_limit_error = 0x4,
		stream_state_error = 0x5,
		final_size_error = 0x6,
		frame_encoding_error = 0x7,
		transport_parameter_error = 0x8,
		connection_id_limit_error = 0x9,
		protocol_violation = 0xa,
		invalid_token = 0xb,
		application_error = 0xc,
		crypto_buffer_exceeded = 0xd,
		key_update_error = 0xe,
		aead_limit_reached = 0xf,
		no_viable_path = 0x10,
	};

	const error_category& transport_category();

	inline error_code make_error_code(transport_error e)
	{
		return { static_cast<int>(e), transport_category() };
	}
	inline error_condition make_error_condition(transport_error e)
	{
		return { static_cast<int>(e), transport_category() };
	}

	enum class tls_alert : uint8_t
	{
		close_notify = 0,
		unexpected_message = 10,
		bad_record_mac = 20,
		record_overflow = 22,
		handshake_failure = 40,
		bad_certificate = 42,
		unsupported_certificate = 43,
		certificate_revoked = 44,
		certificate_expired = 45,
		certificate_unknown = 46,
		illegal_parameter = 47,
		unknown_ca = 48,
		access_denied = 49,
		decode_error = 50,
		decrypt_error = 51,
		protocol_version = 70,
		insufficient_security = 71,
		internal_error = 80,
		inappropriate_fallback = 86,
		user_canceled = 90,
		missing_extension = 109,
		unsupported_extension = 110,
		unrecognized_name = 112,
		bad_certificate_status_response = 113,
		unknown_psk_identity = 115,
		certificate_required = 116,
		no_application_protocol = 120,
	};

	const error_category& tls_category();

	inline error_code make_error_code(tls_alert e)
	{
		return { static_cast<int>(e), tls_category() };
	}
	inline error_condition make_error_condition(tls_alert e)
	{
		return { static_cast<int>(e), tls_category() };
	}

	const error_category& application_category();

} // namespace quic

namespace SYSTEM_ERROR_NAMESPACE
{

	template<>
	struct is_error_code_enum<quic::connection_error> : public std::true_type
	{
	};
	template<>
	struct is_error_code_enum<quic::stream_error> : public std::true_type
	{
	};
	template<>
	struct is_error_code_enum<quic::transport_error> : public std::true_type
	{
	};
	template<>
	struct is_error_code_enum<quic::tls_alert> : public std::true_type
	{
	};

} // namespace SYSTEM_ERROR_NAMESPACE
