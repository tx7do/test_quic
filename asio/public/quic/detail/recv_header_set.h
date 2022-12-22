#pragma once

#include <vector>
#include <lsxpack_header.h>

#include "../include/h3/h3_fields.h"


namespace quic::detail
{

	struct recv_header_set
	{
		h3::fields fields;
		int is_push_promise;
		lsxpack_header header;
		std::vector<char> buffer;

		recv_header_set(int is_push_promise)
			: is_push_promise(is_push_promise)
		{
		}
	};

} // namespace quic::detail
