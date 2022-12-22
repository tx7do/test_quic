#pragma once

#include "../asio_error_code.h"

namespace h3
{

	enum class error
	{
		no_error = 0x100,
		general_protocol_error = 0x101,
		internal_error = 0x102,
		stream_creation_error = 0x103,
		closed_critical_stream = 0x104,
		frame_unexpected = 0x105,
		frame_error = 0x106,
		excessive_load = 0x107,
		id_error = 0x108,
		settings_error = 0x109,
		missing_settings = 0x10a,
		request_rejected = 0x10b,
		request_cancelled = 0x10c,
		request_incomplete = 0x10d,
		message_error = 0x10e,
		connect_error = 0x10f,
		version_fallback = 0x110,
		qpack_decompression_failed = 0x200,
		qpack_encoder_stream_error = 0x201,
		qpack_decoder_stream_error = 0x202,
	};

	const error_category& h3_category();

	inline error_code make_error_code(error e)
	{
		return { static_cast<int>(e), h3_category() };
	}

	inline error_condition make_error_condition(error e)
	{
		return { static_cast<int>(e), h3_category() };
	}

} // namespace quic

namespace SYSTEM_ERROR_NAMESPACE
{

	template<>
	struct is_error_code_enum<h3::error> : public std::true_type
	{
	};

} // namespace SYSTEM_ERROR_NAMESPACE
