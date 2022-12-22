#pragma once

#include <memory>
#include <boost/asio/associated_allocator.hpp>
#include <boost/asio/associated_executor.hpp>

#include "../../asio_error_code.h"

namespace quic::detail
{

	struct stream_impl;

	template<typename Stream>
	struct stream_factory
	{
		static Stream create(std::unique_ptr<stream_impl> s)
		{
			return s;
		}
	};

	template<typename Stream, typename Handler>
	struct stream_open_handler
	{
		Handler handler;
		explicit stream_open_handler(Handler&& handler)
			: handler(std::move(handler))
		{
		}
		void operator()(error_code ec, std::unique_ptr<stream_impl> s)&
		{
			handler(ec, stream_factory<Stream>::create(std::move(s)));
		}
		void operator()(error_code ec, std::unique_ptr<stream_impl> s)&&
		{
			std::move(handler)(ec, stream_factory<Stream>::create(std::move(s)));
		}

		using allocator_type = boost::asio::associated_allocator_t<Handler>;
		allocator_type get_allocator() const noexcept
		{
			return boost::asio::get_associated_allocator(handler);
		}
	};

} // namespace quic::detail

namespace boost::asio
{
	template<typename Stream, typename Handler, typename Executor>
	struct associated_executor<quic::detail::stream_open_handler < Stream, Handler>, Executor>
{
	using type = associated_executor_t<Handler, Executor>;

	static type
	get(const quic::detail::stream_open_handler<Stream, Handler>& handler, const Executor& ex = Executor()) noexcept
	{
		return get_associated_executor(handler.handler, ex);
	}
};

} // namespace boost::asio
