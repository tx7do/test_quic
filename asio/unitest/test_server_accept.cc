#include "quic/quic_server.h"
#include <gtest/gtest.h>
#include <optional>
#include <lsquic.h>
#include "asio_ssl.h"
#include "quic/quic_client.h"
#include "quic/quic_connection.h"
#include "quic/quic_stream.h"
#include "global/global_init.h"

#include "certificate.h"

namespace nexus
{

	namespace
	{

		const error_code ok;

		auto capture(std::optional<error_code>& out)
		{
			return [&](error_code ec)
			{ out = ec; };
		}

	} // anonymous namespace

	TEST(server, accept_wait) // accept() before a connection is received
	{
		auto context = boost::asio::io_context{};
		auto ex = context.get_executor();
		auto global = global::init_client_server();

		auto ssl = test::init_server_context("\04test");
		auto sslc = test::init_client_context("\04test");

		auto server = quic::server{ ex };
		const auto localhost = boost::asio::ip::make_address("127.0.0.1");
		auto acceptor = quic::acceptor{ server, udp::endpoint{ localhost, 0 }, ssl };
		const auto endpoint = acceptor.local_endpoint();
		acceptor.listen(16);

		std::optional<error_code> accept_ec;
		auto sconn = quic::connection{ acceptor };
		acceptor.async_accept(sconn, capture(accept_ec));

		context.poll();
		ASSERT_FALSE(context.stopped());
		EXPECT_FALSE(accept_ec);

		auto client = quic::client{ ex, udp::endpoint{}, sslc };
		auto cconn = quic::connection{ client, endpoint, "host" };

		std::optional<error_code> stream_connect_ec;
		auto cstream = quic::stream{ cconn };
		cconn.async_connect(cstream, capture(stream_connect_ec));

		context.poll();
		ASSERT_FALSE(context.stopped());
		ASSERT_TRUE(accept_ec);
		EXPECT_EQ(ok, *accept_ec);
	}

	TEST(server, accept_ready) // accept() after a connection is received
	{
		auto context = boost::asio::io_context{};
		auto ex = context.get_executor();
		auto global = global::init_client_server();

		auto ssl = test::init_server_context("\04test");
		auto sslc = test::init_client_context("\04test");

		auto server = quic::server{ ex };
		const auto localhost = boost::asio::ip::make_address("127.0.0.1");
		auto acceptor = quic::acceptor{ server, udp::endpoint{ localhost, 0 }, ssl };
		const auto endpoint = acceptor.local_endpoint();
		acceptor.listen(16);

		auto client = quic::client{ ex, udp::endpoint{}, sslc };
		auto cconn = quic::connection{ client, endpoint, "host" };

		std::optional<error_code> stream_connect_ec;
		auto cstream = quic::stream{ cconn };
		cconn.async_connect(cstream, capture(stream_connect_ec));

		context.poll();
		ASSERT_FALSE(context.stopped());
		EXPECT_TRUE(stream_connect_ec);

		std::optional<error_code> accept_ec;
		auto sconn = quic::connection{ acceptor };
		acceptor.async_accept(sconn, capture(accept_ec));

		context.poll();
		ASSERT_FALSE(context.stopped());
		ASSERT_TRUE(accept_ec);
		EXPECT_EQ(ok, *accept_ec);
	}

} // namespace nexus
