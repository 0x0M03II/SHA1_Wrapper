#ifndef COSC583_SHA1
#define COSC583_SHA1
#include "cryptopp890/sha.h"
#include <iostream>
#include <string>

class SHAInterface {

    public:
        /* virtual methods to be implemented - providing wrapper functionality */
        virtual void reset() = 0;
        virtual void resize() = 0;
        virtual void finalize() = 0;
        virtual void initialize() = 0;
        virtual const std::string& getDigest() const = 0;
        virtual void update(const std::string& input) = 0;
        virtual void shaHash(const std::string& data, int truncBits) = 0;
        
        SHAInterface() {}
};


class SHA1ImplementInterface : public SHAInterface {
private:
    std::string digest;
    CryptoPP::SHA1 hash;

public:

    void reset() override {}
    void initialize() override {}

    void update(const std::string& input) override {
        this->hash.Update((const CryptoPP::byte*)input.data(), input.size());
    }

    void resize() override {
        this->digest.resize(this->hash.DigestSize());
    }

    void finalize() override {
        hash.Final(reinterpret_cast<CryptoPP::byte*>(&digest[0]));
    }

    void shaHash(const std::string& data, int truncBits) override {
        update(data);
        resize();
        finalize();
    }

    const std::string& getDigest() const override {
        return digest;
    }

    SHA1ImplementInterface();
};

#endif