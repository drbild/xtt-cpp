/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#ifndef XTT_CPP_GROUPPUBLICKEYCONTEXT_HPP
#define XTT_CPP_GROUPPUBLICKEYCONTEXT_HPP
#pragma once

#include <xtt/context.h>

#include <xtt/group_identity.hpp>

#include <vector>
#include <memory>

namespace xtt { class group_public_key_context; }
namespace xtt {

    class group_public_key_context {
    public:
        virtual ~group_public_key_context() = default;

        virtual std::unique_ptr<group_public_key_context> clone() const = 0;

        /*
         * Serialize to byte stream,
         *  as (GPK | basename_length(1 byte) | basename).
         */
        virtual std::vector<unsigned char> serialize() const = 0;

        /*
         * Get GPK as byte string.
         */
        virtual std::vector<unsigned char> get_gpk() const = 0;

        /*
         * Get basename as byte string.
         */
        virtual std::vector<unsigned char> get_basename() const = 0;

        /*
         * Get GPK as ASCII-encoded hexadecimal string
         */
        virtual std::string get_gpk_as_text() const = 0;

        /*
         * Get basename as ASCII-encoded hexadecimal string
         */
        virtual std::string get_basename_as_text() const = 0;

        virtual struct xtt_group_public_key_context* get() = 0;
        virtual const struct xtt_group_public_key_context* get() const = 0;
    };

    class group_public_key_context_lrsw : public group_public_key_context {
    public:
        /*
         * Build a group_public_key_context_lrsw from
         *  a single byte string,
         *  in the form (GPK | basename_length (1 byte) | basename).
         */
        static
        std::unique_ptr<group_public_key_context>
        deserialize(const std::vector<unsigned char>& serialized);

        /*
         * Build a group_public_key_context_lrsw from
         *  two separate byte strings,
         *  one for the basename and the other for the GPK.
         */
        static
        std::unique_ptr<group_public_key_context>
        from_gpk_and_basename(const std::vector<unsigned char>& gpk,
                              const std::vector<unsigned char>& basename);

        /*
         * Build a group_public_key_context_lrsw from
         *  two separate ASCII-encoded hexadecimal strings,
         *  one for the basename and the other for the GPK.
         */
        static
        std::unique_ptr<group_public_key_context>
        from_gpk_and_basename(const std::string& gpk,
                              const std::string& basename);

    public:
        group_public_key_context_lrsw();

        std::vector<unsigned char> serialize() const final;

        std::vector<unsigned char> get_gpk() const final;

        std::vector<unsigned char> get_basename() const final;

        std::string get_gpk_as_text() const final;

        std::string get_basename_as_text() const final;

        std::unique_ptr<group_public_key_context> clone() const final;

        struct xtt_group_public_key_context* get() final;
        const struct xtt_group_public_key_context* get() const final;

    private:
        xtt_group_public_key_context gpk_ctx_;
    };

    std::ostream& operator<<(std::ostream& stream, const xtt::group_public_key_context& gpk_ctx);

}   // namespace xtt

#endif

