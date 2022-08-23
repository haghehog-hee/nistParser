#include "nistparser.h"

int main() {
	nistParser parser;

	//parser.load("74503202L1B_000000003.int");
	//parser.writeFile("lol.int");
	nistParser parser2;
	parser2.load("lol3.int"); 
	parser2.writeFile("lol4.int");
	//parser2.writeFile("lol1.int");
	return 0;
}