#include <iostream>
#include <fstream>

#include <boost/asio.hpp>
#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include "global/global_init.h"
#include "quic/quic_client.h"
#include "quic/quic_connection.h"
#include "quic/quic_stream.h"

namespace
{

	struct configuration
	{
		const char* hostname;
		const char* portstr;
		char** files_begin;
		char** files_end;
	};

	configuration parse_args(int argc, char** argv)
	{
		if (argc < 4)
		{
			std::cerr << "Usage: " << argv[0] << " <hostname> <port> [filenames...]\n";
			::exit(EXIT_FAILURE);
		}
		configuration config;
		config.hostname = argv[1];
		config.portstr = argv[2];
		config.files_begin = std::next(argv, 3);
		config.files_end = std::next(argv, argc);
		return config;
	}

	using boost::asio::ip::udp;

	using buffer_type = std::array<char, 256>;

	template<typename T>
	using ref_counter = boost::intrusive_ref_counter<T, boost::thread_unsafe_counter>;

	struct echo_connection : ref_counter<echo_connection>
	{
		quic::client& client;
		quic::connection conn;

		echo_connection(quic::client& client,
			const udp::endpoint& endpoint,
			const char* hostname)
			: client(client), conn(client, endpoint, hostname)
		{
		}
		~echo_connection()
		{
			client.close();
		}
	};

	using connection_ptr = boost::intrusive_ptr<echo_connection>;

	struct echo_stream : ref_counter<echo_stream>
	{
		connection_ptr conn;
		quic::stream stream;
		std::ifstream input;
		std::ostream& output;
		buffer_type readbuf;
		buffer_type writebuf;
		echo_stream(connection_ptr conn, const char* filename, std::ostream& output)
			: conn(std::move(conn)), stream(this->conn->conn),
			  input(filename), output(output)
		{
		}
	};
	using stream_ptr = boost::intrusive_ptr<echo_stream>;

	void write_file(stream_ptr stream)
	{
		// read from input
		auto& data = stream->writebuf;
		stream->input.read(data.data(), data.size());
		const auto bytes = stream->input.gcount();
		// write to stream
		auto& s = stream->stream;
		boost::asio::async_write(s, boost::asio::buffer(data.data(), bytes),
			[stream = std::move(stream)](error_code ec, size_t bytes)
			{
				if (ec)
				{
					std::cerr << "async_write failed with " << ec.message() << '\n';
				}
				else if (!stream->input)
				{ // no more input, done writing
					stream->stream.shutdown(1);
				}
				else
				{
					write_file(stream);
				}
			});
	}

	void read_file(stream_ptr stream)
	{
		// read back the echo
		auto& data = stream->readbuf;
		auto& s = stream->stream;
		s.async_read_some(boost::asio::buffer(data),
			[stream = std::move(stream)](error_code ec, size_t bytes)
			{
				if (ec)
				{
					if (ec != quic::stream_error::eof)
					{
						std::cerr << "async_read_some returned " << ec.message() << '\n';
					}
					return;
				}
				// write the output bytes then start reading more
				auto& data = stream->readbuf;
				stream->output.write(data.data(), bytes);
				read_file(stream);
			});
	}

} // anonymous namespace

int main(int argc, char** argv)
{
	const auto cfg = parse_args(argc, argv);

	auto context = boost::asio::io_context{};
	auto ex = context.get_executor();
	const auto endpoint = [&]
	{
		auto resolver = udp::resolver{ ex };
		return resolver.resolve(cfg.hostname, cfg.portstr)->endpoint();
	}();

	auto ssl = boost::asio::ssl::context{ boost::asio::ssl::context::tlsv13 };
	::SSL_CTX_set_min_proto_version(ssl.native_handle(), TLS1_3_VERSION);
	::SSL_CTX_set_max_proto_version(ssl.native_handle(), TLS1_3_VERSION);
	const unsigned char alpn[] = { 4, 'e', 'c', 'h', 'o' };
	::SSL_CTX_set_alpn_protos(ssl.native_handle(), alpn, sizeof(alpn));

	auto global = global::init_client();
	auto client = quic::client{ ex, udp::endpoint{ endpoint.protocol(), 0 }, ssl };

	auto conn = connection_ptr{ new echo_connection(client, endpoint, cfg.hostname) };

	// connect a stream for each input file
	for (auto f = cfg.files_begin; f != cfg.files_end; ++f)
	{
		auto s = stream_ptr{ new echo_stream(conn, *f, std::cout) };
		auto& stream = s->stream;
		conn->conn.async_connect(stream, [s = std::move(s)](error_code ec)
		{
			if (ec)
			{
				std::cerr << "async_connect failed with " << ec.message() << '\n';
				return;
			}
			write_file(s);
			read_file(s);
		});
	}
	conn.reset(); // let the connection close once all streams are done

	context.run();
	return 0;
}
