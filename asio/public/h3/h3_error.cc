#include "h3_error.h"

namespace h3
{

	const error_category& quic_category()
	{
		struct category : public error_category
		{
			const char* name() const noexcept override
			{
				return "quic";
			}

			std::string message(int ev) const override
			{
				switch (static_cast<error>(ev))
				{
				case error::no_error:
					return "no error";
				case error::general_protocol_error:
					return "general protocol error";
				case error::internal_error:
					return "internal error";
				case error::stream_creation_error:
					return "stream creation error";
				case error::closed_critical_stream:
					return "closed critical stream";
				case error::frame_unexpected:
					return "frame unexpected";
				case error::frame_error:
					return "frame error";
				case error::excessive_load:
					return "excessive load";
				case error::id_error:
					return "id error";
				case error::settings_error:
					return "settings error";
				case error::missing_settings:
					return "missing settings";
				case error::request_rejected:
					return "request rejected";
				case error::request_cancelled:
					return "request cancelled";
				case error::request_incomplete:
					return "request incomplete";
				case error::message_error:
					return "message error";
				case error::connect_error:
					return "connect error";
				case error::version_fallback:
					return "version fallback";
				case error::qpack_decompression_failed:
					return "qpack decompression failed";
				case error::qpack_encoder_stream_error:
					return "qpack encoder stream error";
				case error::qpack_decoder_stream_error:
					return "qpack decoder stream error";
				default:
					return "unknown";
				}
			}
		};
		static category instance;
		return instance;
	}

} // namespace h3
