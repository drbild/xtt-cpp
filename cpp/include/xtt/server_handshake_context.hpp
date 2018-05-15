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

#ifndef XTT_CPP_SERVERHANDSHAKECONTEXT_HPP
#define XTT_CPP_SERVERHANDSHAKECONTEXT_HPP
#pragma once

#include <xtt/context.h>
#include <xtt/messages.h>

#include <xtt/pseudonym.hpp>
#include <xtt/longterm_key.hpp>
#include <xtt/identity.hpp>
#include <xtt/group_identity.hpp>
#include <xtt/group_public_key_context.hpp>
#include <xtt/types.hpp>
#include <xtt/server_certificate_context.hpp>
#include <xtt/server_cookie_context.hpp>

#include <memory>
#include <experimental/optional>

namespace xtt { class server_handshake_context; }
void swap(xtt::server_handshake_context&, xtt::server_handshake_context&);

namespace xtt {

    class server_handshake_context {
    public:
        struct io_buffer {
            unsigned char* ptr;
            uint16_t len;
        };

    public:
        server_handshake_context(const server_handshake_context&) = delete;

        server_handshake_context& operator=(server_handshake_context other);

        server_handshake_context(server_handshake_context&& other);

        server_handshake_context(unsigned char *in_buffer,
                                 uint16_t in_buffer_size,
                                 unsigned char *out_buffer,
                                 uint16_t out_buffer_size);

        std::experimental::optional<version> get_version() const;

        std::experimental::optional<suite_spec> get_suite_spec() const;

        std::unique_ptr<pseudonym> get_clients_pseudonym() const;

        std::unique_ptr<longterm_key> get_clients_longterm_key() const;

        std::experimental::optional<identity> get_clients_identity() const;

        const struct xtt_server_handshake_context* get() const;
        struct xtt_server_handshake_context* get();

        return_code handle_io(uint16_t bytes_written,
                              uint16_t bytes_read,
                              io_buffer& io_buf);

        return_code handle_connect(io_buffer& io_buf);

        return_code build_serverattest(io_buffer& io_buf,
                                       const server_certificate_context& certificate_ctx,
                                       server_cookie_context& cookie_ctx);

        return_code preparse_idclientattest(io_buffer& io_buf,
                                            identity& requested_client_id_out,
                                            group_identity& claimed_group_id_out,
                                            server_cookie_context& cookie_ctx,
                                            const server_certificate_context& certificate_ctx);

        return_code verify_groupsignature(io_buffer& io_buf,
                                          group_public_key_context& group_pub_key_ctx,
                                          const server_certificate_context& certificate_ctx);

        return_code build_idserverfinished(io_buffer& io_buf,
                                           const identity& client_id);

        return_code build_error_msg(io_buffer& io_buf);

        friend void ::swap(server_handshake_context& first, server_handshake_context& second);

    private:
        xtt_server_handshake_context handshake_ctx_;
    };

}   // namespace xtt

#endif

