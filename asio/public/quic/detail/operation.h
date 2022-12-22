#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <sys/uio.h>
#include <boost/asio/associated_executor.hpp>

#include "../../asio_error_code.h"
#include "../../h3/h3_fields.h"
#include "handler_ptr.h"

namespace quic::detail
{

	struct stream_impl;

	enum class completion_type
	{
		post, defer, dispatch, destroy
	};

	template<typename ...Args>
	struct operation
	{
		using operation_type = operation<Args...>;
		using tuple_type = std::tuple<Args...>;

		using complete_fn = void (*)(completion_type, operation_type*, tuple_type&&);
		complete_fn complete_;

		explicit operation(complete_fn complete) noexcept
			: complete_(complete)
		{
		}

		template<typename ...UArgs>
		void post(UArgs&& ...args)
		{
			complete_(completion_type::post, this, tuple_type{ std::forward<UArgs>(args)... });
		}
		template<typename ...UArgs>
		void defer(UArgs&& ...args)
		{
			complete_(completion_type::defer, this, tuple_type{ std::forward<UArgs>(args)... });
		}
		template<typename ...UArgs>
		void dispatch(UArgs&& ...args)
		{
			complete_(completion_type::dispatch, this, tuple_type{ std::forward<UArgs>(args)... });
		}
		template<typename ...UArgs>
		void destroy(UArgs&& ...args)
		{
			complete_(completion_type::destroy, this, tuple_type{ std::forward<UArgs>(args)... });
		}
	};

	template<typename Operation>
	struct sync_operation : Operation
	{
		std::mutex mutex;
		std::condition_variable cond;
		using operation_type = typename Operation::operation_type;
		using tuple_type = typename Operation::tuple_type;
		std::optional<tuple_type> result;

		template<typename ...Args>
		explicit sync_operation(Args&& ...args)
			: Operation(do_complete, std::forward<Args>(args)...)
		{
		}

		static void do_complete(completion_type type, operation_type* op,
			tuple_type&& result)
		{
			auto self = static_cast<sync_operation*>(op);
			if (type != completion_type::destroy)
			{
				auto lock = std::scoped_lock{ self->mutex };
				self->result = std::move(result);
				self->cond.notify_one();
			}
		}
		void wait()
		{
			auto lock = std::unique_lock{ mutex };
			cond.wait(lock, [this]
			{ return result.has_value(); });
		}
	};

	template<typename Operation, typename Handler, typename IoExecutor>
	struct async_operation : Operation
	{
		using operation_type = typename Operation::operation_type;
		using tuple_type = typename Operation::tuple_type;

		using Executor = boost::asio::associated_executor_t<Handler, IoExecutor>;
		using Work = typename boost::asio::prefer_result<Executor,
														 boost::asio::execution::outstanding_work_t::tracked_t>::type;
		using IoWork = typename boost::asio::prefer_result<IoExecutor,
														   boost::asio::execution::outstanding_work_t::tracked_t>::type;
		Handler handler;
		std::pair<Work, IoWork> ex;

		template<typename ...Args>
		async_operation(Handler&& handler, const IoExecutor& io_ex, Args&& ...args)
			: Operation(do_complete, std::forward<Args>(args)...),
			  handler(std::move(handler)),
			  ex(boost::asio::prefer(get_associated_executor(this->handler, io_ex),
					  boost::asio::execution::outstanding_work.tracked),
				  boost::asio::prefer(io_ex,
					  boost::asio::execution::outstanding_work.tracked))
		{
		}

		static void do_complete(completion_type type, operation_type* op, tuple_type&& args)
		{
			auto self = static_cast<async_operation*>(op);
			auto p = handler_ptr<async_operation, Handler>{ self, &self->handler };

			auto handler = std::move(self->handler); // may throw
			p.get_deleter().handler = &handler; // update deleter

			auto alloc = boost::asio::get_associated_allocator(handler);
			auto f = [handler = std::move(handler), args = std::move(args)]() mutable
			{
				std::apply(std::move(handler), std::move(args));
			}; // may throw

			auto ex = std::move(self->ex.first);
			p.reset(); // delete 'self'

			switch (type)
			{
			case completion_type::post:
				boost::asio::execution::execute(
					boost::asio::require(
						boost::asio::prefer(ex,
							boost::asio::execution::relationship.fork,
							boost::asio::execution::allocator(alloc)),
						boost::asio::execution::blocking.never),
					std::move(f));
				break;
			case completion_type::defer:
				boost::asio::execution::execute(
					boost::asio::require(
						boost::asio::prefer(ex,
							boost::asio::execution::relationship.continuation,
							boost::asio::execution::allocator(alloc)),
						boost::asio::execution::blocking.never),
					std::move(f));
				break;
			case completion_type::dispatch:
				boost::asio::execution::execute(
					boost::asio::prefer(ex,
						boost::asio::execution::blocking.possibly,
						boost::asio::execution::allocator(alloc)),
					std::move(f));
				break;
			case completion_type::destroy: // handled above
				break;
			}
		}
	};

	struct accept_operation : operation<error_code>
	{
		explicit accept_operation(complete_fn complete) noexcept
			: operation(complete)
		{
		}
	};
	using accept_sync = sync_operation<accept_operation>;

	template<typename Handler, typename IoExecutor>
	using accept_async = async_operation<accept_operation, Handler, IoExecutor>;

	struct stream_connect_operation : operation<error_code>
	{
		stream_impl& stream;

		explicit stream_connect_operation(complete_fn complete, stream_impl& stream) noexcept
			: operation(complete), stream(stream)
		{
		}
	};
	using stream_connect_sync = sync_operation<stream_connect_operation>;

	template<typename Handler, typename IoExecutor>
	using stream_connect_async = async_operation<stream_connect_operation, Handler, IoExecutor>;


// stream accept
	struct stream_accept_operation : operation<error_code>
	{
		stream_impl& stream;

		explicit stream_accept_operation(complete_fn complete, stream_impl& stream) noexcept
			: operation(complete), stream(stream)
		{
		}
	};
	using stream_accept_sync = sync_operation<stream_accept_operation>;

	template<typename Handler, typename IoExecutor>
	using stream_accept_async = async_operation<stream_accept_operation, Handler, IoExecutor>;


	struct stream_data_operation : operation<error_code, size_t>
	{
		static constexpr uint16_t max_iovs = 128;
		iovec iovs[max_iovs];
		uint16_t num_iovs = 0;
		size_t bytes_transferred = 0;

		explicit stream_data_operation(complete_fn complete) noexcept
			: operation(complete)
		{
		}
	};
	using stream_data_sync = sync_operation<stream_data_operation>;

	template<typename Handler, typename IoExecutor>
	using stream_data_async = async_operation<stream_data_operation, Handler, IoExecutor>;


// stream header reads
	struct stream_header_read_operation : operation<error_code>
	{
		h3::fields& fields;

		stream_header_read_operation(complete_fn complete, h3::fields& fields) noexcept
			: operation(complete), fields(fields)
		{
		}
	};
	using stream_header_read_sync = sync_operation<stream_header_read_operation>;

	template<typename Handler, typename IoExecutor>
	using stream_header_read_async = async_operation<stream_header_read_operation, Handler, IoExecutor>;


// stream header writes
	struct stream_header_write_operation : operation<error_code>
	{
		const h3::fields& fields;

		stream_header_write_operation(complete_fn complete, const h3::fields& fields) noexcept
			: operation(complete), fields(fields)
		{
		}
	};

	using stream_header_write_sync = sync_operation<stream_header_write_operation>;

	template<typename Handler, typename IoExecutor>
	using stream_header_write_async = async_operation<stream_header_write_operation, Handler, IoExecutor>;


// stream close
	struct stream_close_operation : operation<error_code>
	{
		explicit stream_close_operation(complete_fn complete) noexcept
			: operation(complete)
		{
		}
	};

	using stream_close_sync = sync_operation<stream_close_operation>;

	template<typename Handler, typename IoExecutor>
	using stream_close_async = async_operation<stream_close_operation, Handler, IoExecutor>;

} // namespace quic::detail
