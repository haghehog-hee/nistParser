#include "nistparser.h"

int main() {
	nistParser parser;

	parser.load("74503202L1B_000000003.int");
	parser.writeFile("lol.int");

	return 0;
}