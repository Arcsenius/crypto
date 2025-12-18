#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
namespace crypto {
    using BigInt = boost::multiprecision::cpp_int;

    using Byte = std::byte;
    using Bytes = std::vector<Byte>;
}