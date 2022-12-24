#include <iostream>

#include <boost/asio.hpp>

#include "global/global_init.h"
#include "h3/h3_client.h"
#include "h3/h3_stream.h"


using boost::asio::ip::udp;
using body_buffer = std::array<char, 4096>;

static void read_print_stream(h3::stream& stream, h3::client_connection& conn, body_buffer& buffer)
{
	stream.async_read_some(boost::asio::buffer(buffer),
		[&](error_code ec, size_t bytes)
		{
			if (ec)
			{
				if (ec != quic::stream_error::eof)
				{
					std::cerr << "async_read_some failed: " << ec.message() << std::endl;
				}
				conn.close();
				return;
			}
			std::cout.write(buffer.data(), bytes);
			read_print_stream(stream, conn, buffer);
		});
}

int main(int argc, char** argv)
{
	// parse argv for <hostname> <port> <path>
	if (argc < 4)
	{
		std::cerr << "Usage: " << argv[0] << " <hostname> <port> <path>" << std::endl;
		return EXIT_FAILURE;
	}
	const char* hostname = argv[1];
	const std::string_view portstr = argv[2];
	const std::string_view path = argv[3];

	auto ioc = boost::asio::io_context{};
	auto ex = ioc.get_executor();

	auto ssl = boost::asio::ssl::context{ boost::asio::ssl::context::tlsv13 };
	::SSL_CTX_set_min_proto_version(ssl.native_handle(), TLS1_3_VERSION);
	::SSL_CTX_set_max_proto_version(ssl.native_handle(), TLS1_3_VERSION);

	// resolve hostname
	const auto remote_endpoint = [&]
	{
		auto resolver = udp::resolver{ ex };
		return resolver.resolve(hostname, portstr)->endpoint();
	}();

	auto global = global::init_client();
	auto client = h3::client{ ex, udp::endpoint{}, ssl };
	auto conn = h3::client_connection{ client };
	client.connect(conn, remote_endpoint, hostname);
	auto stream = h3::stream{ conn };

	auto request = h3::fields{};
	request.insert(":method", "GET");
	request.insert(":scheme", "https");
	request.insert(":path", path);
	request.insert(":authority", hostname);
	request.insert("user-agent", "h3cli/lsquic");
	auto response = h3::fields{};
	auto buffer = body_buffer{};

	conn.async_connect(stream, [&](error_code ec)
	{
		if (ec)
		{
			std::cerr << "async_connect failed: " << ec.message() << std::endl;
			client.close();
			return;
		}
		stream.async_write_headers(request, [&](error_code ec)
		{
			if (ec)
			{
				std::cerr << "async_write_headers failed: " << ec.message() << std::endl;
				client.close();
				return;
			}
			stream.shutdown(1);
			stream.async_read_headers(response, [&](error_code ec)
			{
				if (ec)
				{
					std::cerr << "async_read_headers failed: " << ec.message() << std::endl;
					client.close();
					return;
				}
				for (const auto& f : response)
				{
					std::cout << f.c_str() << "\r\n";
				}
				std::cout << "\r\n";
				read_print_stream(stream, conn, buffer);
			});
		});
	});

	ioc.run();
	return 0;
}
