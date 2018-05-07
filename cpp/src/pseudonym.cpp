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

#include <xtt/pseudonym.hpp>

#include "internal/text_to_binary.hpp"

#include <xtt/crypto_wrapper.h>

#include <ostream>

using namespace xtt;

std::ostream& xtt::operator<<(std::ostream& stream, const xtt::pseudonym& pseud)
{
    return stream << pseud.serialize_to_text();
}

std::unique_ptr<pseudonym>
pseudonym_lrsw::deserialize(const std::vector<unsigned char>& serialized)
{
    if (sizeof(xtt_daa_pseudonym_lrsw) != serialized.size()) {
        return {};
    }

    auto ret = std::make_unique<pseudonym_lrsw>();
    if (!ret)
        return {};

    *(ret->get()) = *reinterpret_cast<const xtt_daa_pseudonym_lrsw*>(serialized.data());

    return std::move(ret);
}

std::unique_ptr<pseudonym>
pseudonym_lrsw::deserialize(const std::string& serialized)
{
    return pseudonym_lrsw::deserialize(text_to_binary(serialized));
}

std::size_t pseudonym_lrsw::length() const
{
    return sizeof(xtt_daa_pseudonym_lrsw);
}

std::unique_ptr<pseudonym> pseudonym_lrsw::clone() const
{
    return std::make_unique<pseudonym_lrsw>(*this);
}

std::vector<unsigned char> pseudonym_lrsw::serialize() const
{
    return std::vector<unsigned char>(raw_.data, raw_.data+sizeof(xtt_daa_pseudonym_lrsw));
}

std::string pseudonym_lrsw::serialize_to_text() const
{
    return binary_to_text(raw_.data, sizeof(xtt_daa_pseudonym_lrsw));
}

const xtt_daa_pseudonym_lrsw* pseudonym_lrsw::get() const
{
    return &raw_;
}

xtt_daa_pseudonym_lrsw* pseudonym_lrsw::get()
{
    return &raw_;
}

bool pseudonym::operator==(const pseudonym& other) const
{
    if (this->length() != other.length())
        return false;

    return 0 == xtt_crypto_memcmp(this->get()->data,
                                  other.get()->data,
                                  this->length());
}

bool pseudonym::operator!=(const pseudonym& other) const
{
    return !(*this == other);
}

