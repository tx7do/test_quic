#include "quic_client.h"
#include "quic_connection.h"

#include <lsquic.h>

namespace quic
{

	client::client(const executor_type& ex, const udp::endpoint& endpoint, ssl::context& ctx)
		: engine(ex, &socket, nullptr, 0),
		  socket(engine, endpoint, false, ctx)
	{
	}

	client::client(const executor_type& ex, const udp::endpoint& endpoint, ssl::context& ctx, const settings& s)
		: engine(ex, &socket, &s, 0),
		  socket(engine, endpoint, false, ctx)
	{
	}

	client::client(udp::socket&& socket, ssl::context& ctx)
		: engine(socket.get_executor(), &this->socket, nullptr, 0),
		  socket(engine, std::move(socket), ctx)
	{
	}

	client::client(udp::socket&& socket, ssl::context& ctx, const settings& s)
		: engine(socket.get_executor(), &this->socket, &s, 0),
		  socket(engine, std::move(socket), ctx)
	{
	}

	client::executor_type client::get_executor() const
	{
		return engine.get_executor();
	}

	udp::endpoint client::local_endpoint() const
	{
		return socket.local_endpoint();
	}

	void client::connect(connection& conn,
		const udp::endpoint& endpoint,
		const char* hostname)
	{
		socket.connect(conn.impl, endpoint, hostname);
	}

	void client::close()
	{
		engine.close();
		socket.close();
	}

} // namespace quic
