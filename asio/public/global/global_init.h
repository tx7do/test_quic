#pragma once

#include "global_context.h"

namespace global
{
	context init_client(error_code& ec);

	context init_client();

	context init_server(error_code& ec);

	context init_server();

	context init_client_server(error_code& ec);

	context init_client_server();

} // namespace global
