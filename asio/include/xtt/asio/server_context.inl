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

#include <xtt/asio/error_category.hpp>

namespace xtt {
namespace asio {

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename Handler>
    void
    server_context::async_do_read(server_handshake_context::io_buffer io_buf,
                                  GPKLookupCallback async_lookup_gpk_callback,
                                  AssignIdCallback async_assign_id_callback,
                                  Handler handler)
    {
        boost::asio::async_read(socket_,
                                boost::asio::buffer(io_buf.io_ptr,
                                                    io_buf.io_bytes_requested),
                                boost::asio::bind_executor(strand_,
                                                           [this, async_lookup_gpk_callback, async_assign_id_callback, handler]
                                                           (auto&& ec, auto&& bytes_transferred)
                                                           {
                                                               if (ec) {
                                                                   handler(ec);
                                                                   return;
                                                               }

                                                               server_handshake_context::io_buffer io_buf;

                                                               return_code current_rc = handshake_ctx_.handle_io(0,   // no bytes written
                                                                                                                 bytes_transferred,
                                                                                                                 io_buf);

                                                               this->async_run_state_machine(current_rc,
                                                                                             io_buf,
                                                                                             async_lookup_gpk_callback,
                                                                                             async_assign_id_callback,
                                                                                             handler);
                                                           }));
    }

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename Handler>
    void
    server_context::async_do_write(server_handshake_context::io_buffer io_buf,
                                   GPKLookupCallback async_lookup_gpk_callback,
                                   AssignIdCallback async_assign_id_callback,
                                   Handler handler)
    {
        boost::asio::async_write(socket_,
                                 boost::asio::buffer(io_buf.io_ptr,
                                                     io_buf.io_bytes_requested),
                                 boost::asio::bind_executor(strand_,
                                                            [this, async_lookup_gpk_callback, async_assign_id_callback, handler]
                                                            (auto&& ec, auto&& bytes_transferred)
                                                            {
                                                                if (ec) {
                                                                    handler(ec);
                                                                    return;
                                                                }

                                                                server_handshake_context::io_buffer io_buf;

                                                                return_code current_rc = handshake_ctx_.handle_io(bytes_transferred,
                                                                                                                  0,  // no bytes read
                                                                                                                  io_buf);

                                                                this->async_run_state_machine(current_rc,
                                                                                              io_buf,
                                                                                              async_lookup_gpk_callback,
                                                                                              async_assign_id_callback,
                                                                                              handler);
                                                            }));
    }

    template <typename Handler>
    bool server_context::set_cert(Handler handler)
    {
        if (cert_ != cert_map_.end())
            return true;

        auto suite_spec = handshake_ctx_.get_suite_spec();
        if (!suite_spec) {
            async_send_error_msg([this, handler]()
                                 {
                                     this->ec_ = boost::system::error_code(static_cast<int>(return_code::UNKNOWN_SUITE_SPEC),
                                                                                            get_xtt_category());
                                     handler(this->ec_);
                                 });
            return false;
        }

        auto cert_it = cert_map_.find(*suite_spec);
        if (cert_map_.end() != cert_it) {
            cert_ = cert_it;

            return true;
        } else {
            async_send_error_msg([this, handler]()
                                 {
                                     this->ec_ = boost::system::error_code(static_cast<int>(return_code::BAD_CERTIFICATE),
                                                                           get_xtt_category());
                                     handler(this->ec_);
                                 });
            return false;
        }
    }

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename Handler>
    void
    server_context::async_buildserverattest(GPKLookupCallback async_lookup_gpk_callback,
                                            AssignIdCallback async_assign_id_callback,
                                            Handler handler)
    {
        if (!set_cert(handler)) {
            return; // set_cert takes care of raising the callback
        }

        server_handshake_context::io_buffer io_buf;

        return_code new_rc = handshake_ctx_.build_serverattest(io_buf,
                                                               *cert_->second,
                                                               cookie_ctx_);

        async_run_state_machine(new_rc,
                                io_buf,
                                async_lookup_gpk_callback,
                                async_assign_id_callback,
                                handler);
    }

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename Handler>
    void
    server_context::async_preparseidclientattest(GPKLookupCallback async_lookup_gpk_callback,
                                                 AssignIdCallback async_assign_id_callback,
                                                 Handler handler)
    {
        if (!set_cert(handler)) {
            return; // set_cert takes care of raising the callback
        }

        server_handshake_context::io_buffer io_buf;

        return_code new_rc = handshake_ctx_.preparse_idclientattest(io_buf,
                                                                    requested_client_id_,
                                                                    claimed_group_id_,
                                                                    cookie_ctx_,
                                                                    *cert_->second);

        async_run_state_machine(new_rc,
                                io_buf,
                                async_lookup_gpk_callback,
                                async_assign_id_callback,
                                handler);
    }

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename Handler>
    void
    server_context::async_found_gpk_callback(boost::system::error_code ec,
                                             std::unique_ptr<group_public_key_context> gpk_ctx,
                                             GPKLookupCallback async_lookup_gpk_callback,
                                             AssignIdCallback async_assign_id_callback,
                                             Handler handler)
    {
        if (ec) {
            async_send_error_msg([this, ec, handler]()
                                 {
                                     handler(ec);
                                     return;
                                 });
            return;
        }

        if (!set_cert(handler)) {
            return; // set_cert takes care of raising the callback
        }

        server_handshake_context::io_buffer io_buf;
        return_code new_rc = handshake_ctx_.verify_groupsignature(io_buf,
                                                                  *gpk_ctx,
                                                                  *cert_->second);

        async_run_state_machine(new_rc,
                                io_buf,
                                async_lookup_gpk_callback,
                                async_assign_id_callback,
                                handler);
    }

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename Handler>
    void
    server_context::async_assigned_id_callback(boost::system::error_code ec,
                                               identity assigned_id,
                                               GPKLookupCallback async_lookup_gpk_callback,
                                               AssignIdCallback async_assign_id_callback,
                                               Handler handler)
    {
        if (ec) {
            async_send_error_msg([this, ec, handler]()
                                 {
                                     handler(ec);
                                     return;
                                 });
            return;
        }

        server_handshake_context::io_buffer io_buf;
        return_code new_rc = handshake_ctx_.build_idserverfinished(io_buf,
                                                                   assigned_id);

        async_run_state_machine(new_rc,
                                io_buf,
                                async_lookup_gpk_callback,
                                async_assign_id_callback,
                                handler);
    }

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename Handler>
    void
    server_context::async_verifygroupsignature(GPKLookupCallback async_lookup_gpk_callback,
                                               AssignIdCallback async_assign_id_callback,
                                               Handler handler)
    {
        boost::asio::post(strand_,
                          [this, async_lookup_gpk_callback, async_assign_id_callback, handler]()
                          {
                              async_lookup_gpk_callback(claimed_group_id_,
                                                        requested_client_id_,
                                                        [this, async_lookup_gpk_callback, async_assign_id_callback, handler]
                                                        (auto&& ec, std::unique_ptr<group_public_key_context> gpk_ctx)
                                                        {
                                                            this->async_found_gpk_callback(ec,
                                                                                           std::move(gpk_ctx),
                                                                                           async_lookup_gpk_callback,
                                                                                           async_assign_id_callback,
                                                                                           handler);
                                                        });
                          });
    }


    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename Handler>
    void
    server_context::async_buildidserverfinished(GPKLookupCallback async_lookup_gpk_callback,
                                                AssignIdCallback async_assign_id_callback,
                                                Handler handler)
    {
        boost::asio::post(strand_,
                          [this, async_lookup_gpk_callback, async_assign_id_callback, handler]()
                          {
                              async_assign_id_callback(claimed_group_id_,
                                                 requested_client_id_,
                                                 [this, async_lookup_gpk_callback, async_assign_id_callback, handler]
                                                 (auto&& ec, identity assigned_id)
                                                 {
                                                      this->async_assigned_id_callback(ec,
                                                                                       assigned_id,
                                                                                       async_lookup_gpk_callback,
                                                                                       async_assign_id_callback,
                                                                                       handler);
                                                 });
                          });
    }

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename Handler>
    void
    server_context::async_run_state_machine(return_code current_rc,
                                            server_handshake_context::io_buffer io_buf,
                                            GPKLookupCallback async_lookup_gpk_callback,
                                            AssignIdCallback async_assign_id_callback,
                                            Handler handler)
    {
        boost::asio::post(strand_,
                          [this, current_rc, io_buf, async_lookup_gpk_callback, async_assign_id_callback, handler]()
                          {
                              switch (current_rc) {
                                  case return_code::WANT_WRITE:
                                      async_do_write(io_buf, async_lookup_gpk_callback, async_assign_id_callback, handler);

                                      break;
                                  case return_code::WANT_READ:
                                      async_do_read(io_buf, async_lookup_gpk_callback, async_assign_id_callback, handler);

                                      break;
                                  case return_code::WANT_BUILDSERVERATTEST:
                                      async_buildserverattest(async_lookup_gpk_callback, async_assign_id_callback, handler);

                                      break;
                                  case return_code::WANT_PREPARSEIDCLIENTATTEST:
                                      async_preparseidclientattest(async_lookup_gpk_callback, async_assign_id_callback, handler);

                                      break;
                                  case return_code::WANT_VERIFYGROUPSIGNATURE:
                                      async_verifygroupsignature(async_lookup_gpk_callback, async_assign_id_callback, handler);

                                      break;
                                  case return_code::WANT_BUILDIDSERVERFINISHED:
                                      async_buildidserverfinished(async_lookup_gpk_callback, async_assign_id_callback, handler);

                                      break;
                                  case return_code::HANDSHAKE_FINISHED:
                                      this->ec_ = boost::system::error_code();

                                      boost::asio::post(strand_,
                                                        [this, handler]()
                                                        {
                                                            handler(this->ec_);
                                                        });

                                      break;
                                  case return_code::RECEIVED_ERROR_MSG:
                                      this->ec_ = boost::system::error_code(static_cast<int>(return_code::RECEIVED_ERROR_MSG),
                                                                            get_xtt_category());

                                      boost::asio::post(strand_,
                                                        [this, handler]()
                                                        {
                                                            handler(this->ec_);
                                                        });
                                      break;
                                  default:
                                      this->ec_ = boost::system::error_code(static_cast<int>(current_rc),
                                                                            get_xtt_category());

                                      async_send_error_msg([this, handler, current_rc]()
                                                           {
                                                               handler(this->ec_);
                                                           });
                                      return;
                              }
                          });
    }

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename Handler>
    void
    server_context::async_handle_connect(GPKLookupCallback async_lookup_gpk_callback,
                                         AssignIdCallback async_assign_id_callback,
                                         Handler handler)
    {
        server_handshake_context::io_buffer io_buf;
        return_code current_rc = handshake_ctx_.handle_connect(io_buf);

        async_run_state_machine(current_rc,
                                io_buf,
                                std::move(async_lookup_gpk_callback),
                                std::move(async_assign_id_callback),
                                std::move(handler));
    }

    template <typename Handler>
    void
    server_context::async_send_error_msg(Handler handler)
    {
        server_handshake_context::io_buffer io_buf;
        (void)handshake_ctx_.build_error_msg(io_buf);
        boost::asio::async_write(socket_,
                                 boost::asio::buffer(io_buf.io_ptr,
                                                     io_buf.io_bytes_requested),
                                 boost::asio::bind_executor(strand_,
                                                            [handler](auto&& /*ec*/, auto&& /*bytes_transferred*/)
                                                            {
                                                                // Don't even check ec, just always raise callback
                                                                handler();
                                                            }));
    }

}   // namespace asio
}   // namespace xtt

