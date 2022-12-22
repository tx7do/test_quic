#pragma once

#include <cstdint>

namespace quic
{

	using stream_id = uint64_t;

	inline bool client_initiated(stream_id id)
	{
		return (id & 0x1) == 0;
	}

	inline bool server_initiated(stream_id id)
	{
		return (id & 0x1);
	}

} // namespace quic
