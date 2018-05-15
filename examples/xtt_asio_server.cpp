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

#include <xtt/asio.hpp>

#include <sodium.h>

#include <boost/asio.hpp>

#include <cstdlib>

#include <iostream>
#include <fstream>
#include <memory>

const char *daa_gpk_file = "daa_gpk.bin";
const char *basename_file = "basename.bin";
const char *server_certificate_file = "server_certificate.bin";
const char *server_privatekey_file = "server_privatekey.bin";

class xtt_server {
public:
    xtt_server(boost::asio::io_context& io_context,
               short port,
               const std::vector<unsigned char>& certificate,
               const std::vector<unsigned char>& private_key,
               xtt::server_cookie_context& cookie_ctx,
               std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map)
        : acceptor_(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
          certificate_(certificate),
          private_key_(private_key),
          cookie_ctx_(cookie_ctx),
          gpk_map_(gpk_map),
          xtt_contexts_(),
          io_context_(io_context)
    {
        do_accept();
    }

private:
    void do_accept()
    {
        acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket)
                               {
                                   if (!ec) {
                                       run_handshake(std::move(socket));
                                   }

                                   do_accept();
                               });
    }

    void run_handshake(boost::asio::ip::tcp::socket socket)
    {
        xtt_contexts_.emplace_back(std::move(socket), cookie_ctx_);
        xtt::asio::server_context& xtt_context = xtt_contexts_.back();

        boost::system::error_code cert_ec;
        xtt_context.load_certificate(certificate_, private_key_, cert_ec);
        if (cert_ec) {
            std::cerr << "Error deserializing certificate\n";
            return;
        }

        xtt_context.async_handle_connect([this](xtt::group_identity claimed_gid,
                                                xtt::identity requested_client_id,
                                                auto&& continuation)
                                         {
                                            (void)requested_client_id;

                                             this->async_lookup_gpk(claimed_gid, continuation);
                                         },
                                         [this, &xtt_context](xtt::group_identity claimed_gid,
                                                              xtt::identity requested_client_id,
                                                              auto&& continuation)
                                         {
                                             this->async_assign_id(claimed_gid, requested_client_id, xtt_context, continuation);
                                         },
                                         [this, &xtt_context](const boost::system::error_code& ec)
                                         {
                                             this->handle_handshake(ec, xtt_context);
                                         });
    }

    template <typename AsyncContinuation>
    void
    async_lookup_gpk(const xtt::group_identity& claimed_gid, AsyncContinuation continuation)
    {
        auto gpk_it = gpk_map_.find(claimed_gid);
        if (gpk_map_.end() == gpk_it) {
            std::cerr << "Error: claimed group ID '" << claimed_gid << "' doesn't match any known\n";
            boost::asio::post(io_context_,
                              [continuation]()
                              {
                                  continuation(boost::asio::error::access_denied,
                                               std::unique_ptr<xtt::group_public_key_context>());
                              });
            return;
        }

        boost::asio::post(io_context_,
                          [continuation, gpk_it]()
                          {
                              continuation(boost::system::error_code(), gpk_it->second->clone());
                          });
    }

    template <typename AsyncContinuation>
    void
    async_assign_id(const xtt::group_identity& claimed_gid,
                    const xtt::identity requested_client_id,
                    xtt::asio::server_context& xtt_context,
                    AsyncContinuation continuation)
    {
        auto clients_pseudonym = xtt_context.get_clients_pseudonym();
        if (!clients_pseudonym) {
            std::cerr << "Unable to get client's pseudonym, while assigning an ID\n";
            boost::asio::post(io_context_,
                              [continuation]()
                              {
                                  continuation(boost::asio::error::invalid_argument,
                                               xtt::identity());
                              });
            return;
        }

        xtt::identity assigned_id;
        // If the client sent xtt_null_client_id assign them id = SHA-256(GID || pseudonym) (truncated to first 16bytes)
        // Otherwise, just echo back what they requested.
        if (requested_client_id.is_null()) {
            std::vector<unsigned char> new_id_serialized(crypto_hash_sha256_BYTES);
            crypto_hash_sha256_state h;
            crypto_hash_sha256_init(&h);
            std::vector<unsigned char> gid_serial = claimed_gid.serialize();
            crypto_hash_sha256_update(&h, gid_serial.data(), gid_serial.size());
            std::vector<unsigned char> pseudonym_serial = clients_pseudonym->serialize();
            crypto_hash_sha256_update(&h, pseudonym_serial.data(), pseudonym_serial.size());
            crypto_hash_sha256_final(&h, new_id_serialized.data());
            new_id_serialized.resize(sizeof(xtt_identity_type));
            auto new_id = xtt::identity::deserialize(new_id_serialized);
            if (!new_id) {
                std::cerr << "Error creating new identity\n";
                boost::asio::post(io_context_,
                                  [continuation]()
                                  {
                                      continuation(boost::asio::error::invalid_argument,
                                                   xtt::identity());
                                  });
                return;
            }

            assigned_id = *new_id;
        } else {
            assigned_id = requested_client_id;
        }

        boost::asio::post(io_context_,
                          [continuation, assigned_id]()
                          {
                              continuation(boost::system::error_code(), assigned_id);
                          });
    }

    void handle_handshake(const boost::system::error_code& ec,
                          xtt::asio::server_context& xtt_context)
    {
        if (!ec) {
            std::cout << "Successfully finished handshake:\n";

            auto clients_pseudonym = xtt_context.get_clients_pseudonym();
            if (!clients_pseudonym) {
                std::cerr << "Error retrieving client's pseudonym!";
                return;
            }
            std::cout << "\tClient's pseudonym:       " << *clients_pseudonym << "\n";

            auto clients_id = xtt_context.get_clients_identity();
            if (!clients_id) {
                std::cerr << "Error retrieving client's assigned id!";
                return;
            }
            std::cout << "\tWe assigned the identity: " << *clients_id << "\n";

            auto clients_longterm_key = xtt_context.get_clients_longterm_key();
            if (!clients_longterm_key) {
                std::cerr << "Error retrieving client's longterm public key!";
                return;
            }
            std::cout << "\tClient has longterm key:  " << *clients_longterm_key << "\n";
        } else {
            std::cout << "Error during handshake: " << ec << std::endl;
        }

        xtt_context.lowest_layer().close(); // we should also remove xtt_context from our vector
    }

private:
    boost::asio::ip::tcp::acceptor acceptor_;

    std::vector<unsigned char> certificate_;
    std::vector<unsigned char> private_key_;

    xtt::server_cookie_context& cookie_ctx_;
    std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map_;

    std::vector<xtt::asio::server_context> xtt_contexts_;

    boost::asio::io_context& io_context_;
};

void parse_cmd_args(int argc, char *argv[], short *port);

int initialize(std::vector<unsigned char>& certificate,
               std::vector<unsigned char>& private_key,
               std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map);

int main(int argc, char *argv[])
{
    // 1) Parse args
    short server_port;
    parse_cmd_args(argc, argv, &server_port);

    // 2) Setup necessary XTT information (used by all handshakes)
    std::vector<unsigned char> certificate;
    std::vector<unsigned char> private_key;
    xtt::server_cookie_context cookie_ctx;
    std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>> gpk_map;
    int ret;
    ret = initialize(certificate, private_key, gpk_map);
    if (0 != ret) {
        std::cerr << "Error initializing persistent XTT contexts\n";
        return 1;
    }

    // 3) Start server
    boost::asio::io_context io_context;
    xtt_server serv{io_context, server_port, certificate, private_key, cookie_ctx, gpk_map};

    // 4) Run event loop
    io_context.run();
}

void parse_cmd_args(int argc, char *argv[], short *port)
{
    if (2 != argc) {
        std::cerr<< "usage: " << argv[0] << " <server port>\n";
        exit(1);
    }

    *port = std::atoi(argv[1]);
}

int initialize(std::vector<unsigned char>& certificate,
               std::vector<unsigned char>& private_key,
               std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map)
{
    // 1) Read DAA GPK from file.
    std::ifstream gpk_file(daa_gpk_file, std::ios::in | std::ios::binary);
    std::vector<unsigned char> serialized_gpk((std::istreambuf_iterator<char>(gpk_file)), std::istreambuf_iterator<char>());
    
    // 2) Read DAA basename from file
    std::ifstream bsn_file(basename_file, std::ios::in | std::ios::binary);
    std::vector<unsigned char> basename((std::istreambuf_iterator<char>(bsn_file)), std::istreambuf_iterator<char>());

    // 3) Initialize DAA context
    auto gpk = xtt::group_public_key_context_lrsw::from_gpk_and_basename(serialized_gpk, basename);
    if (!gpk) {
        std::cerr << "Error deserializing GPK and basename\n";
        return -1;
    }
    std::cout << "Using group public key context: " << *gpk << std::endl;

    // 4) Generate GID from GPK (GID = SHA-256(GPK))
    std::vector<unsigned char> raw_gid(crypto_hash_sha256_BYTES);
    crypto_hash_sha256_state h;
    crypto_hash_sha256_init(&h);
    std::vector<unsigned char> gpk_serial = gpk->get_gpk();
    crypto_hash_sha256_update(&h, gpk_serial.data(), gpk_serial.size());
    crypto_hash_sha256_final(&h, raw_gid.data());
    auto gid = xtt::group_identity::deserialize(raw_gid);
    if (!gid) {
        std::cerr << "Error computing GID from GPK\n";
        return -1;
    }
    std::cout << "\twith GID: " << *gid << std::endl;

    // 4ii) Insert gpk into map
    gpk_map[*gid] = std::move(gpk);

    // 5) Read in my certificate from file
    std::ifstream cert_file(server_certificate_file, std::ios::in | std::ios::binary);
    certificate.assign((std::istreambuf_iterator<char>(cert_file)), std::istreambuf_iterator<char>());

    // 6) Read in my private key from file
    std::ifstream privkey_file(server_privatekey_file, std::ios::in | std::ios::binary);
    private_key.assign((std::istreambuf_iterator<char>(privkey_file)), std::istreambuf_iterator<char>());

    return 0;
}
