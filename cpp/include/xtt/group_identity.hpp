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

#ifndef XTT_CPP_GROUP_IDENTITY_HPP
#define XTT_CPP_GROUP_IDENTITY_HPP
#pragma once

#include <xtt/crypto_types.h>

#include <string>
#include <vector>
#include <functional>
#include <experimental/optional>

namespace xtt { class group_identity; }
namespace std {
    template<>
    struct hash<xtt::group_identity>
    {
        std::size_t operator()(const xtt::group_identity& key) const;
    };
}

namespace xtt {

    class group_identity {
    public:
        static
        std::experimental::optional<group_identity>
        deserialize(const std::vector<unsigned char>& serialized);

        static
        std::experimental::optional<group_identity>
        deserialize(const std::string& serialized);

    public:
        group_identity() = default;

        std::size_t length() const;

        std::vector<unsigned char> serialize() const;

        std::string serialize_to_text() const;

        bool operator==(const group_identity& other) const;

        bool operator!=(const group_identity& other) const;

        const xtt_group_id* get() const;
        xtt_group_id* get();

    private:
        xtt_group_id raw_;
    };

    std::ostream& operator<<(std::ostream& stream, const xtt::group_identity& id);

}   // namespace xtt

#endif

