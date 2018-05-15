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

#ifndef XTT_ASIO_SERVERCONTEXT_HPP
#define XTT_ASIO_SERVERCONTEXT_HPP
#pragma once

#include <xtt.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/io_context_strand.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <boost/system/error_code.hpp>

#include <memory>
#include <unordered_map>
#include <functional>
#include <tuple>

namespace xtt {
namespace asio {

    using server_certificate_map = std::unordered_map<suite_spec, std::unique_ptr<server_certificate_context>>;

    class server_context {
    public:
        server_context(boost::asio::ip::tcp::socket tcp_socket,
                       const server_certificate_map& cert_map,
                       server_cookie_context& cookie_ctx);

        const boost::asio::ip::tcp::socket& lowest_layer() const;
        boost::asio::ip::tcp::socket& lowest_layer();

        std::unique_ptr<pseudonym> get_clients_pseudonym() const;

        std::unique_ptr<longterm_key> get_clients_longterm_key() const;

        std::experimental::optional<identity> get_clients_identity() const;

        /*
         * Begin the server's end of an XTT handshake, from the very first client message.
         *
         * `async_handle_connect` WILL NOT invoke
         * `async_lookup_gpk`, `async_assign_id`, or `handler` directly.
         * Instead, it will invoke them in a manner equivalent to using
         * `boost::asio:io_context::post()`.
         *
         * Parameters:
         * - `async_lookup_gpk` must have the signature:
         *      template <typename Continuation>
         *      void async_lookup_gpk(group_identity claimed_gid, identity requested_id, Continuation continuation);
         *   -  Further, `async_lookup_gpk` MUST NOT call `continuation` itself.
         *      Instead, it must invoke the continuation in a manner equivalent to using
         *      `boost::asio:io_context::post()`.
         *
         * - `async_assign_id` must have the signature:
         *      template <typename Continuation>
         *      void async_assign_id(group_identity claimed_gid, identity requested_id, Continuation continuation);
         *   -  Further, `async_assign_id` MUST NOT call continuation itself.
         *      Instead, it must invoke the continuation in a manner equivalent to using
         *      `boost::asio:io_context::post()`.
         *
         * - `handler` must have the signature:
         *      void handler(const boost::system::error_code&);
         */
        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void async_handle_connect(GPKLookupCallback async_lookup_gpk,
                                  AssignIdCallback async_assign_id,
                                  Handler handler);

    private:
        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void
        async_run_state_machine(return_code current_rc,
                                std::tuple<GPKLookupCallback, AssignIdCallback, Handler> func_pack);

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void
        async_do_read(std::tuple<GPKLookupCallback, AssignIdCallback, Handler> func_pack);

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void
        async_do_write(std::tuple<GPKLookupCallback, AssignIdCallback, Handler> func_pack);

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void
        async_buildserverattest(std::tuple<GPKLookupCallback, AssignIdCallback, Handler> func_pack);

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void
        async_preparseidclientattest(std::tuple<GPKLookupCallback, AssignIdCallback, Handler> func_pack);

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void
        async_found_gpk_callback(boost::system::error_code ec,
                                 std::unique_ptr<group_public_key_context> gpk_ctx,
                                 std::tuple<GPKLookupCallback, AssignIdCallback, Handler> func_pack);

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void
        async_assigned_id_callback(boost::system::error_code ec,
                                   identity assigned_id,
                                   std::tuple<GPKLookupCallback, AssignIdCallback, Handler> func_pack);

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void
        async_verifygroupsignature(std::tuple<GPKLookupCallback, AssignIdCallback, Handler> func_pack);

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void
        async_buildidserverfinished(std::tuple<GPKLookupCallback, AssignIdCallback, Handler> func_pack);

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        void
        async_send_error_msg(std::tuple<GPKLookupCallback, AssignIdCallback, Handler> func_pack);

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename Handler>
        bool set_cert(std::tuple<GPKLookupCallback, AssignIdCallback, Handler>& func_pack);

    private:
        std::array<unsigned char, MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH> in_buffer_;
        std::array<unsigned char, MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH> out_buffer_;
        server_handshake_context::io_buffer io_buf_;
        server_handshake_context handshake_ctx_;

        boost::asio::ip::tcp::socket socket_;
        boost::asio::io_context::strand strand_;

        xtt::identity requested_client_id_;
        xtt::group_identity claimed_group_id_;
        const server_certificate_map& cert_map_;
        server_certificate_map::const_iterator cert_;
        server_cookie_context& cookie_ctx_;

        boost::system::error_code ec_;
    };

}   // namespace asio
}   // namespace xtt

#include "server_context.inl"

#endif

