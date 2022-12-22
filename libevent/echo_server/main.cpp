#include "stdinc.h"
#include "../public/engine.h"

int main()
{
	Engine engine(true, false);
	engine.start();

	std::this_thread::sleep_for(std::chrono::seconds(60));

	return 0;
}
