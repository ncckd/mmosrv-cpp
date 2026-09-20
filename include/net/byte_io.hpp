#pragma once
// byte_io.hpp
// Serialisation binaire bornee, partagee par store/store_wire.hpp et
// net/login_protocol.hpp. ByteReader retourne std::nullopt des qu'il
// manque des octets -- jamais de lecture hors bornes, meme sur un buffer
// hostile.

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace netsrv {

class ByteWriter {
public:
    void u16(std::uint16_t v) { push(v); }
    void u32(std::uint32_t v) { push(v); }
    void bytes(std::span<const std::byte> b) { buf_.insert(buf_.end(), b.begin(), b.end()); }
    void str(std::string_view s) { bytes(std::as_bytes(std::span{s.data(), s.size()})); }

    std::vector<std::byte> take() { return std::move(buf_); }
    std::span<const std::byte> view() const { return buf_; }

private:
    template <typename T>
    void push(T v) {
        std::array<std::byte, sizeof(T)> tmp{};
        std::memcpy(tmp.data(), &v, sizeof(T));
        buf_.insert(buf_.end(), tmp.begin(), tmp.end());
    }
    std::vector<std::byte> buf_;
};

class ByteReader {
public:
    explicit ByteReader(std::span<const std::byte> data) : data_(data) {}

    std::optional<std::uint16_t> u16() { return pop<std::uint16_t>(); }
    std::optional<std::uint32_t> u32() { return pop<std::uint32_t>(); }

    std::optional<std::vector<std::byte>> bytes(std::size_t n) {
        if (n > remaining()) return std::nullopt;
        std::vector<std::byte> out(data_.begin(), data_.begin() + n);
        data_ = data_.subspan(n);
        return out;
    }
    std::optional<std::string> str(std::size_t n) {
        auto b = bytes(n);
        if (!b) return std::nullopt;
        return std::string(reinterpret_cast<const char*>(b->data()), b->size());
    }

    std::size_t remaining() const noexcept { return data_.size(); }

private:
    template <typename T>
    std::optional<T> pop() {
        if (sizeof(T) > remaining()) return std::nullopt;
        T v{};
        std::memcpy(&v, data_.data(), sizeof(T));
        data_ = data_.subspan(sizeof(T));
        return v;
    }
    std::span<const std::byte> data_;
};

} // namespace netsrv
