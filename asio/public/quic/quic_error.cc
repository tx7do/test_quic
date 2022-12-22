#include "quic_error.h"
#include <openssl/ssl.h>

namespace quic
{

	const error_category& connection_category()
	{
		struct category : public error_category
		{
			const char* name() const noexcept override
			{
				return "quic::connection";
			}

			std::string message(int ev) const override
			{
				switch (static_cast<connection_error>(ev))
				{
				case connection_error::aborted:
					return "connection aborted";
				case connection_error::handshake_failed:
					return "connection handshake failed";
				case connection_error::timed_out:
					return "connection timed out";
				case connection_error::reset:
					return "connection reset by peer";
				case connection_error::going_away:
					return "connection is going away";
				case connection_error::peer_going_away:
					return "peer is going away";
				default:
					return "unknown";
				}
			}

			error_condition default_error_condition(int code) const noexcept override
			{
				switch (static_cast<connection_error>(code))
				{
				case connection_error::aborted:
					return errc::connection_aborted;

				case connection_error::timed_out:
					return errc::timed_out;

				case connection_error::reset:
					return errc::connection_reset;

				default:
					return { code, category() };
				}
			}
		};
		static category instance;
		return instance;
	}

	const error_category& stream_category()
	{
		struct category : public error_category
		{
			const char* name() const noexcept override
			{
				return "quic::stream";
			}

			std::string message(int ev) const override
			{
				switch (static_cast<stream_error>(ev))
				{
				case stream_error::eof:
					return "end of stream";
				case stream_error::busy:
					return "stream busy";
				case stream_error::aborted:
					return "stream aborted";
				case stream_error::reset:
					return "stream reset by peer";
				default:
					return "unknown";
				}
			}

			error_condition default_error_condition(int code) const noexcept override
			{
				switch (static_cast<stream_error>(code))
				{
				case stream_error::busy:
					return errc::device_or_resource_busy;

				case stream_error::aborted:
					return errc::connection_aborted;

				case stream_error::reset:
					return errc::connection_reset;

				default:
					return { code, category() };
				}
			}
		};
		static category instance;
		return instance;
	}

	const error_category& application_category()
	{
		struct category : public error_category
		{
			const char* name() const noexcept override
			{
				return "quic::application";
			}
			std::string message(int ev) const override
			{
				return "unknown";
			}
		};
		static category instance;
		return instance;
	}

	const error_category& transport_category()
	{
		struct category : public error_category
		{
			const char* name() const noexcept override
			{
				return "quic::transport";
			}

			std::string message(int ev) const override
			{
				switch (static_cast<transport_error>(ev))
				{
				case transport_error::no_error:
					return "no error";
				case transport_error::internal_error:
					return "internal error";
				case transport_error::connection_refused:
					return "connection refused";
				case transport_error::flow_control_error:
					return "flow control error";
				case transport_error::stream_limit_error:
					return "stream limit error";
				case transport_error::stream_state_error:
					return "stream state error";
				case transport_error::final_size_error:
					return "final size error";
				case transport_error::frame_encoding_error:
					return "frame encoding error";
				case transport_error::transport_parameter_error:
					return "transport parameter error";
				case transport_error::connection_id_limit_error:
					return "connection id limit error";
				case transport_error::protocol_violation:
					return "protocol violation";
				case transport_error::invalid_token:
					return "invalid token";
				case transport_error::application_error:
					return "application error";
				case transport_error::crypto_buffer_exceeded:
					return "crypto buffer exceeded";
				case transport_error::key_update_error:
					return "key update error";
				case transport_error::aead_limit_reached:
					return "aead limit reached";
				case transport_error::no_viable_path:
					return "no viable path";
				default:
					return "unknown";
				}
			}
		};
		static category instance;
		return instance;
	}

	const error_category& tls_category()
	{
		struct category : public error_category
		{
			const char* name() const noexcept override
			{
				return "quic::tls";
			}
			std::string message(int ev) const override
			{
				return ::SSL_alert_desc_string_long(ev);
			}
		};
		static category instance;
		return instance;
	}

} // namespace quic
