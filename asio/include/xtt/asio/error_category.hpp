#ifndef XTT_ASIO_ERRORCATEGORY_HPP
#define XTT_ASIO_ERRORCATEGORY_HPP
#pragma once

#include <xtt/return_codes.h>

#include <boost/system/error_code.hpp>

namespace xtt {
namespace asio {

    class error_category : public boost::system::error_category {
    public:
        const char* name() const noexcept { return "xtt"; }
        std::string message(int ev) const {
            return xtt_strerror(static_cast<xtt_return_code_type>(ev));
        }
    };

    inline
    const boost::system::error_category& get_xtt_category()
    {
        static error_category instance;
        return instance;
    }

}   // namespace asio
}   // namespace xtt

#endif

