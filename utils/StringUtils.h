 #pragma once

#include <QString>
#include <array>
#include <vector>

// namespace means you can do this: StringUtils::toBase64String(data)
namespace StringUtils {

template <size_t N>
inline QString toBase64String(const std::array<uint8_t, N>& data) {
    return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
}

inline QString toBase64String(const std::vector<uint8_t>& data) {
    return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
}

} // namespace StringUtils