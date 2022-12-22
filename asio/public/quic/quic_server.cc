#include "quic_server.h"
#include "quic_connection.h"
#include "../asio_udp.h"
#include <lsquic.h>

namespace quic
{

	server::server(const executor_type& ex)
		: engine(ex, nullptr, nullptr, LSENG_SERVER)
	{
	}

	server::server(const executor_type& ex, const settings& s)
		: engine(ex, nullptr, &s, LSENG_SERVER)
	{
	}

	server::executor_type server::get_executor() const
	{
		return engine.get_executor();
	}

	void server::close()
	{
		engine.close();
	}

	acceptor::acceptor(server& s, udp::socket&& socket, ssl::context& ctx)
		: impl(s.engine, std::move(socket), ctx)
	{
	}

	acceptor::acceptor(server& s, const udp::endpoint& endpoint,
		ssl::context& ctx)
		: impl(s.engine, endpoint, true, ctx)
	{
	}

	acceptor::executor_type acceptor::get_executor() const
	{
		return impl.get_executor();
	}

	udp::endpoint acceptor::local_endpoint() const
	{
		return impl.local_endpoint();
	}

	void acceptor::listen(int backlog)
	{
		return impl.listen(backlog);
	}

	void acceptor::accept(connection& conn, error_code& ec)
	{
		detail::accept_sync op;
		impl.accept(conn.impl, op);
		op.wait();
		ec = std::get<0>(*op.result);
	}

	void acceptor::accept(connection& conn)
	{
		error_code ec;
		accept(conn, ec);
		if (ec)
		{
			throw system_error(ec);
		}
	}

	void acceptor::close()
	{
		impl.close();
	}

} // namespace quic
