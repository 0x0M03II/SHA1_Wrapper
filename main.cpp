#include "wsha1.h"
#include <iostream>

int main(int argc, char* argv[])
{

    SHAInterface* imp = new SHA1ImplementInterface;

    imp->update("Yoda said, Do or do not. There is no try.");
    imp->resize();
    imp->finalize();

    std::string s = imp->getDigest();

    std::cout << s << std::endl;

    delete imp;

    return 0;
}