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

#include <xtt/group_public_key_context.hpp>

#include <cassert>
#include <vector>
#include <algorithm>
#include <limits>

using namespace xtt;

#include "internal/text_to_binary.hpp"

const xtt_daa_group_pub_key_lrsw group_public_key_lrsw_dummy = {{0}};

std::ostream& xtt::operator<<(std::ostream& stream, const xtt::group_public_key_context& gpk_ctx)
{
    return stream << gpk_ctx.get_gpk_as_text() << " - " << gpk_ctx.get_basename_as_text();
}

std::unique_ptr<group_public_key_context>
group_public_key_context_lrsw::deserialize(const std::vector<unsigned char>& serialized)
{
    size_t gpk_len = sizeof(xtt_daa_group_pub_key_lrsw);

    if (serialized.size() < (gpk_len + 1)) {   // ensure at least enough for GPK | basename_len
        return {};
    }

    std::vector<unsigned char>::const_iterator gpk_begin{serialized.cbegin()};

    size_t basename_len = *(gpk_begin + gpk_len);
    if (basename_len > MAX_BASENAME_LENGTH) {
        return {};
    }

    if (serialized.size() < (gpk_len + 1 + basename_len)) {
        return {};
    }
    std::vector<unsigned char>::const_iterator basename_begin{serialized.cbegin() + gpk_len + 1};

    return from_gpk_and_basename(std::vector<unsigned char>(gpk_begin, gpk_begin + gpk_len),
                                 std::vector<unsigned char>(basename_begin, basename_begin + basename_len));
}

std::unique_ptr<group_public_key_context>
group_public_key_context_lrsw::from_gpk_and_basename(const std::vector<unsigned char>& gpk,
                                                     const std::vector<unsigned char>& basename)
{
    if (MAX_BASENAME_LENGTH < basename.size()) {
        return {};
    }

    if (sizeof(xtt_daa_group_pub_key_lrsw) != gpk.size()) {
        return {};
    }

    auto ret = std::make_unique<group_public_key_context_lrsw>();
    if (!ret)
        return {};

    xtt_return_code_type ctor_ret =
        xtt_initialize_group_public_key_context_lrsw(ret->get(),
                                                     basename.data(),
                                                     basename.size(),
                                                     reinterpret_cast<const xtt_daa_group_pub_key_lrsw*>(gpk.data()));
    if (XTT_RETURN_SUCCESS != ctor_ret) {
        return {};
    }

    return std::move(ret);
}

std::unique_ptr<group_public_key_context>
group_public_key_context_lrsw::from_gpk_and_basename(const std::string& gpk,
                                                     const std::string& basename)
{
    return group_public_key_context_lrsw::from_gpk_and_basename(text_to_binary(gpk),
                                                                text_to_binary(basename));
}

group_public_key_context_lrsw::group_public_key_context_lrsw()
{
    xtt_return_code_type ctor_ret =
        xtt_initialize_group_public_key_context_lrsw(&gpk_ctx_,
                                                     nullptr,
                                                     0,
                                                     &group_public_key_lrsw_dummy);
    (void)ctor_ret;
    assert(XTT_RETURN_SUCCESS == ctor_ret);
}

struct xtt_group_public_key_context* group_public_key_context_lrsw::get()
{
    return &gpk_ctx_;
}

const struct xtt_group_public_key_context* group_public_key_context_lrsw::get() const
{
    return &gpk_ctx_;
}

std::vector<unsigned char> group_public_key_context_lrsw::serialize() const
{
    std::vector<unsigned char> basename{get_basename()};
    std::vector<unsigned char> gpk{get_gpk()};

    std::vector<unsigned char> ret;
    ret.reserve(gpk.size() + 1 + basename.size());  // 1 extra for basename_length

    ret.insert(ret.end(), gpk.begin(), gpk.end());

    assert(basename.size() < std::numeric_limits<unsigned char>::max());
    ret.push_back(static_cast<unsigned char>(basename.size()));

    ret.insert(ret.end(), basename.begin(), basename.end());

    return ret;
}

std::vector<unsigned char> group_public_key_context_lrsw::get_gpk() const
{
    size_t gpk_len = sizeof(xtt_daa_group_pub_key_lrsw);
    return std::vector<unsigned char>(gpk_ctx_.gpk.lrsw.data, gpk_ctx_.gpk.lrsw.data + gpk_len);
}

std::vector<unsigned char> group_public_key_context_lrsw::get_basename() const
{
    size_t basename_len = std::min<std::size_t>(gpk_ctx_.basename_length, MAX_BASENAME_LENGTH);
    return std::vector<unsigned char>(gpk_ctx_.basename, gpk_ctx_.basename + basename_len);
}

std::string group_public_key_context_lrsw::get_gpk_as_text() const
{
    return binary_to_text(gpk_ctx_.gpk.lrsw.data, sizeof(xtt_daa_group_pub_key_lrsw));
}

std::string group_public_key_context_lrsw::get_basename_as_text() const
{
    return binary_to_text(gpk_ctx_.basename, std::min<std::size_t>(gpk_ctx_.basename_length, MAX_BASENAME_LENGTH));
}

std::unique_ptr<group_public_key_context> group_public_key_context_lrsw::clone() const
{
    return std::make_unique<group_public_key_context_lrsw>(*this);
}
