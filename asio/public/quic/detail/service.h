#pragma once

#include <mutex>
#include <boost/asio/execution_context.hpp>
#include <boost/intrusive/list.hpp>

namespace quic::detail
{

	struct service_tag
	{
	};
	using service_list_base_hook = boost::intrusive::list_base_hook<boost::intrusive::tag<service_tag>>;


	template<typename IoObject>
	class service : public boost::asio::execution_context::service
	{
		using base_hook = boost::intrusive::base_hook<service_list_base_hook>;
		boost::intrusive::list<IoObject, base_hook> entries;
		std::mutex mutex;

		void shutdown() override
		{
			while (!entries.empty())
			{
				auto& entry = entries.front();
				entries.pop_front();
				entry.service_shutdown();
			}
		}
	public:
		using key_type = service;
		static inline boost::asio::execution_context::id id;

		explicit service(boost::asio::execution_context& ctx)
			: boost::asio::execution_context::service(ctx)
		{
		}

		void add(IoObject& entry)
		{
			auto lock = std::scoped_lock{ mutex };
			entries.push_back(entry);
		}

		void remove(IoObject& entry)
		{
			auto lock = std::scoped_lock{ mutex };
			if (entries.empty())
			{
				// already shut down
			}
			else
			{
				entries.erase(entries.iterator_to(entry));
			}
		}
	};

} // namespace quic::detail
