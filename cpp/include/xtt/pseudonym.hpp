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

#ifndef XTT_CPP_PSEUDONYM_HPP
#define XTT_CPP_PSEUDONYM_HPP
#pragma once

#include <xtt/crypto_types.h>

#include <string>
#include <vector>
#include <memory>

namespace xtt { class pseudonym; }

namespace xtt {

    class pseudonym {
    public:
        virtual ~pseudonym() = default;

        virtual std::size_t length() const = 0;

        virtual std::unique_ptr<pseudonym> clone() const = 0;

        virtual std::vector<unsigned char> serialize() const = 0;

        virtual std::string serialize_to_text() const = 0;

        virtual const xtt_daa_pseudonym_lrsw* get() const = 0;
        virtual xtt_daa_pseudonym_lrsw* get() = 0;

        bool operator==(const pseudonym& other) const;

        bool operator!=(const pseudonym& other) const;
    };

    class pseudonym_lrsw : public pseudonym {
    public:
        static
        std::unique_ptr<pseudonym>
        deserialize(const std::vector<unsigned char>& serialized);

        static
        std::unique_ptr<pseudonym>
        deserialize(const std::string& serialized);

    public:
        pseudonym_lrsw() = default;

        std::size_t length() const final;

        std::unique_ptr<pseudonym> clone() const final;

        std::vector<unsigned char> serialize() const final;

        std::string serialize_to_text() const final;

        const xtt_daa_pseudonym_lrsw* get() const final ;
        xtt_daa_pseudonym_lrsw* get() final;

    private:
        xtt_daa_pseudonym_lrsw raw_;
    };

    std::ostream& operator<<(std::ostream& stream, const xtt::pseudonym& pseud);

}   // namespace xtt

#endif

