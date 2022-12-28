#include "quic/quic_server.h"
#include <gtest/gtest.h>
#include <optional>
#include "quic/quic_client.h"
#include "quic/quic_connection.h"
#include "global/global_init.h"

#include "certificate.h"

namespace nexus
{

	class Client : public testing::Test
	{
	protected:
		static constexpr const char* alpn = "\04quic";

		global::context global = global::init_client_server();

		ssl::context ssl = test::init_server_context(alpn);
		ssl::context sslc = test::init_client_context(alpn);

		boost::asio::io_context scontext;
		quic::server server = quic::server{ scontext.get_executor() };
		boost::asio::ip::address localhost = boost::asio::ip::make_address("127.0.0.1");
		quic::acceptor acceptor{ server, udp::endpoint{ localhost, 0 }, ssl };

		boost::asio::io_context ccontext;
		quic::client client{ ccontext.get_executor(), udp::endpoint{}, sslc };
	};

	TEST_F(Client, connection_work)
	{
		auto conn = quic::connection{ client, acceptor.local_endpoint(), "host" };

		ccontext.poll();
		ASSERT_FALSE(ccontext.stopped()); // connection maintains work

		conn.close();

		ccontext.poll();
		ASSERT_TRUE(ccontext.stopped()); // close stops work
	}

	TEST_F(Client, two_connection_work)
	{
		auto conn1 = quic::connection{ client, acceptor.local_endpoint(), "host" };

		ccontext.poll();
		ASSERT_FALSE(ccontext.stopped());

		auto conn2 = quic::connection{ client, acceptor.local_endpoint(), "host" };

		ccontext.poll();
		ASSERT_FALSE(ccontext.stopped());

		conn1.close();

		ccontext.poll();
		ASSERT_FALSE(ccontext.stopped());

		conn2.close();

		ccontext.poll();
		ASSERT_TRUE(ccontext.stopped());
	}

} // namespace nexus
