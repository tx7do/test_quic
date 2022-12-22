#pragma once

#include <utility>

#include "global_error.h"


namespace global
{

	class context;

	namespace detail
	{

		context init(int flags, error_code& ec);

	} // namespace detail

	class context
	{
		friend context detail::init(int flags, error_code& ec);
		using cleanup_fn = void (*)();
		cleanup_fn cleanup;
		context(cleanup_fn cleanup) noexcept
			: cleanup(cleanup)
		{
		}
	public:
		context() noexcept
			: cleanup(nullptr)
		{
		}

		context(context&& o) noexcept
			: cleanup(std::exchange(o.cleanup, nullptr))
		{
		}

		context& operator=(context&& o) noexcept
		{
			std::swap(cleanup, o.cleanup);
			return *this;
		}

		~context()
		{
			if (cleanup)
			{
				shutdown();
			}
		}

		operator bool() const
		{
			return cleanup;
		}

		void log_to_stderr(const char* level);

		void shutdown()
		{
			cleanup();
		}
	};

} // namespace global
