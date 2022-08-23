#include "nistparser.h"
#include "iostream"

bool compare(const char* file1, const char* file2)
{
	FILE* f1 = fopen(file1, "r");
	FILE* f2 = fopen(file2, "r");
	fseek(f1, 0, SEEK_END);
	int end = ftell(f1);
	fseek(f1, 0, SEEK_SET);
	char * fl1 = new char[end];
	char * fl2 = new char[end];
	fread(fl1, 1, end, f1);
	fread(fl2, 1, end, f2);
	for (int i = 0; i < end; i++) {
		if (fl1[i] != fl2[i]) {
			std::cout << "mismatch at " << i << " " << fl1[i] << " " << fl2[i] << "\n";
		}
	}
	delete fl1;
	delete fl2;
	return true;
}

int main() {
	nistParser parser;

	parser.load("74503202L1B_000000003.int");
	parser.write("output.int"); 
	parser.load("output.int");
	//compare("74503202L1B_000000003.int", "output.int");
	return 0;
}