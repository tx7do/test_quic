#pragma once

#include "../asio_error_code.h"
#include "quic_stream_id.h"
#include "detail/stream_impl.h"

namespace quic
{

	namespace detail
	{

		struct connection_impl;

		template<typename Stream>
		struct stream_factory;

	} // namespace detail

	class connection;

	class stream
	{
	protected:
		friend class connection;
		friend class detail::connection_impl;
		detail::stream_impl impl;
		explicit stream(detail::connection_impl& impl);
	public:
		explicit stream(connection& conn);

		~stream();

		stream(const stream&) = delete;
		stream& operator=(const stream&) = delete;
		stream(stream&&) = delete;
		stream& operator=(stream&&) = delete;

		using executor_type = detail::stream_impl::executor_type;

		executor_type get_executor() const;

		bool is_open() const;

		stream_id id(error_code& ec) const;
		stream_id id() const;

		template<typename MutableBufferSequence, typename CompletionToken>
		decltype(auto) async_read_some(const MutableBufferSequence& buffers, CompletionToken&& token)
		{
			return impl.async_read_some(buffers, std::forward<CompletionToken>(token));
		}

		template<typename MutableBufferSequence>
		size_t read_some(const MutableBufferSequence& buffers, error_code& ec)
		{
			return impl.read_some(buffers, ec);
		}

		template<typename MutableBufferSequence>
		size_t read_some(const MutableBufferSequence& buffers)
		{
			error_code ec;
			const size_t bytes = impl.read_some(buffers, ec);
			if (ec)
			{
				throw system_error(ec);
			}
			return bytes;
		}

		template<typename ConstBufferSequence, typename CompletionToken>
		decltype(auto) async_write_some(const ConstBufferSequence& buffers, CompletionToken&& token)
		{
			return impl.async_write_some(buffers, std::forward<CompletionToken>(token));
		}

		template<typename ConstBufferSequence>
		size_t write_some(const ConstBufferSequence& buffers, error_code& ec)
		{
			return impl.write_some(buffers, ec);
		}
		template<typename ConstBufferSequence>
		size_t write_some(const ConstBufferSequence& buffers)
		{
			error_code ec;
			const size_t bytes = impl.write_some(buffers, ec);
			if (ec)
			{
				throw system_error(ec);
			}
			return bytes;
		}

		void flush(error_code& ec);
		void flush();

		void shutdown(int how, error_code& ec);
		void shutdown(int how);

		template<typename CompletionToken>
		decltype(auto) async_close(CompletionToken&& token)
		{
			return impl.async_close(std::forward<CompletionToken>(token));
		}

		void close(error_code& ec);
		void close();

		void reset();
	};

} // namespace quic
