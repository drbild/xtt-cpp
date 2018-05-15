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

#include <xtt/asio/server_context.hpp>

using namespace xtt;
using namespace asio;

server_context::server_context(boost::asio::ip::tcp::socket tcp_socket,
                               server_cookie_context& cookie_ctx)
    : in_buffer_(),
      out_buffer_(),
      io_buf_(),
      handshake_ctx_(in_buffer_.data(), in_buffer_.size(), out_buffer_.data(), out_buffer_.size()),
      socket_(std::move(tcp_socket)),
      strand_(socket_.get_io_service()),
      cert_map_(),
      cert_(cert_map_.end()),
      cookie_ctx_(cookie_ctx)
{
}

void server_context::load_certificate(const std::vector<unsigned char>& certificate,
                                      const std::vector<unsigned char>& private_key,
                                      boost::system::error_code& ec)
{
    // TODO: Figure out a way to determine type(Ed25519 vs. ...) from serialized values

    auto cert = xtt::server_certificate_context_ed25519::from_certificate_and_key(certificate, private_key);
    if (!cert) {
        ec = boost::system::error_code(static_cast<int>(return_code::BAD_CERTIFICATE),
                                                        get_xtt_category());
        return;
    }

    cert_map_[suite_spec::X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512] = cert->clone();
    cert_map_[suite_spec::X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B] = cert->clone();
    cert_map_[suite_spec::X25519_LRSW_ED25519_AES256GCM_SHA512] = cert->clone();
    cert_map_[suite_spec::X25519_LRSW_ED25519_AES256GCM_BLAKE2B] = cert->clone();

    ec = boost::system::error_code();
}

const boost::asio::ip::tcp::socket& 
server_context::lowest_layer() const
{
    return socket_;
}

boost::asio::ip::tcp::socket& 
server_context::lowest_layer()
{
    return socket_;
}

std::unique_ptr<pseudonym> server_context::get_clients_pseudonym() const
{
    return handshake_ctx_.get_clients_pseudonym();
}

std::unique_ptr<longterm_key> server_context::get_clients_longterm_key() const
{
    return handshake_ctx_.get_clients_longterm_key();
}

std::experimental::optional<identity> server_context::get_clients_identity() const
{
    return handshake_ctx_.get_clients_identity();
}

