#pragma once


#include "../asio_error_code.h"
#include "../asio_udp.h"

namespace quic
{

	void prepare_socket(udp::socket& sock, bool is_server, error_code& ec);

} // namespace quic
