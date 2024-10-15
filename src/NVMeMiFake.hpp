#include "NVMeIntf.hpp"

#include <boost/asio.hpp>
#include <boost/endian.hpp>

#include <iostream>
#include <thread>

struct ListNode
{
    ListNode *next, *prev;
};

struct nvme_mi_ctrl
{
    void* ep;
    __u16 id;
    ListNode ep_entry;
};

class NVMeMiFake :
    public NVMeMiIntf,
    public std::enable_shared_from_this<NVMeMiFake>
{
  public:
    NVMeMiFake(boost::asio::io_context& io, std::chrono::milliseconds delay) :
        io(io), valid(true) /*, worker(workerIO.get_executor())*/
    {
        // start worker thread
        thread = std::thread([&io = workerIO, &stop = workerStop,
                              &mtx = workerMtx, &cv = workerCv,
                              &isNotified = workerIsNotified, delay]() {
            std::cerr << "NVMeMiFake worker thread started: " << io.stopped()
                      << std::endl;
            // With BOOST_ASIO_DISABLE_THREADS, boost::asio::executor_work_guard
            // issues null_event across the thread, which caused invalid
            // invokation. We implement a simple invoke machenism based
            // std::condition_variable.
            io.stop();
            io.restart();
            while (true)
            {
                // mimik the communication delay.
                std::this_thread::sleep_for(delay);
                io.run();
                io.restart();
                std::cerr << "job done" << std::endl;
                {
                    std::unique_lock<std::mutex> lock(mtx);
                    cv.wait(lock, [&]() { return isNotified; });
                    isNotified = false;
                    if (stop)
                    {
                        // exhaust all tasks and exit
                        io.run();
                        break;
                    }
                }
            }
            std::cerr << "NVMeMi worker this line should not be reached"
                      << std::endl;
        });

        ctrls.resize(3);
        std::cerr << "NVMeMiFake constructor" << std::endl;
    }

    ~NVMeMiFake() override
    {
        if (valid)
        {
            std::cerr << "NVMeMiFake destroyer" << std::endl;
        }
        else
        {
            std::cerr << "NVMeMiFake default destroyer" << std::endl;
        }

        // close worker
        workerStop = true;
        {
            std::unique_lock<std::mutex> lock(workerMtx);
            workerIsNotified = true;
            workerCv.notify_all();
        }
        thread.join();
    }

    void start(const std::shared_ptr<MctpEndpoint>& endpoint
               [[maybe_unused]]) override
    {}
    void stop() override {}
    void recover() override {}

    void miSubsystemHealthStatusPoll(
        std::function<void(const std::error_code&,
                           nvme_mi_nvm_ss_health_status*)>&& cb) override
    {
        io.post([cb{std::move(cb)}]() {
            nvme_mi_nvm_ss_health_status status{};
            status.nss = 1 << 5;
            status.ctemp = 24;
            cb({}, &status);
        });
    }

    void miScanCtrl(std::function<void(const std::error_code&,
                                       const std::vector<nvme_mi_ctrl_t>&)>
                        cb) override
    {
        if (workerStop)
        {
            std::cerr << "worker thread for nvme endpoint is stopped"
                      << std::endl;

            io.post([cb{std::move(cb)}]() {
                cb(std::make_error_code(std::errc::no_such_device), {});
            });
            return;
        }

        post([self{shared_from_this()}, cb = std::move(cb)] {
            std::cerr << "libnvme: scan" << std::endl;
            self->io.post(
                [self{self->shared_from_this()}, cb{std::move(cb)}]() {
                auto& ctrl1 = self->ctrls[0];
                auto& ctrl2 = self->ctrls[1];
                auto& ctrl3 = self->ctrls[2];
                ctrl1.id = 0;
                ctrl2.id = 1;
                ctrl3.id = 2;
                std::vector<nvme_mi_ctrl_t> list{&ctrl1, &ctrl2, &ctrl3};
                cb({}, list);
            });
        });
    }

    bool flushOperations(std::function<void()>&& cb) override
    {
        post([self{shared_from_this()}, cb{std::move(cb)}]() {
            self->io.post(cb);
        });
        return true;
    }

    void adminIdentify(
        [[maybe_unused]] nvme_mi_ctrl_t ctrl, nvme_identify_cns cns,
        [[maybe_unused]] uint32_t nsid, [[maybe_unused]] uint16_t cntid,
        std::function<void(nvme_ex_ptr, std::span<uint8_t>)>&& cb) override
    {
        std::cerr << "identify" << std::endl;
        post([self{shared_from_this()}, cb = std::move(cb), cns]() {
            std::cerr << "libnvme: identify" << std::endl;
            self->io.post([cb{std::move(cb)}, cns]() {
                std::vector<uint8_t> data;
                switch (cns)
                {
                    case NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST:
                    {
                        nvme_secondary_ctrl_list list{};
                        list.num = 2;
                        list.sc_entry[0].pcid = 0;
                        list.sc_entry[0].scid = 1;
                        list.sc_entry[0].scs = 1;
                        list.sc_entry[1].pcid = 0;
                        list.sc_entry[1].scid = 2;
                        list.sc_entry[1].scs = 0;
                        data.resize(sizeof(nvme_secondary_ctrl_list));
                        memcpy(data.data(), &list, data.size());
                        break;
                    }
                    default:
                        data.resize(NVME_IDENTIFY_DATA_SIZE);
                }
                cb({}, std::span<uint8_t>(data.begin(), data.size()));
            });
        });
    }

    void adminGetLogPage(nvme_mi_ctrl_t ctrl, nvme_cmd_get_log_lid lid,
                         uint32_t nsid, uint8_t lsp, uint16_t lsi,
                         std::function<void(const std::error_code&,
                                            std::span<uint8_t>)>&& cb) override
    {
        try
        {
            post([ctrl, lid, nsid, lsp, lsi, self{shared_from_this()},
                  cb{std::move(cb)}]() {
                int rc = 0;
                std::vector<uint8_t> data;
                try
                {
                    switch (lid)
                    {
                        case NVME_LOG_LID_TELEMETRY_HOST:
                        {
                            data.resize(sizeof(nvme_telemetry_log));
                            nvme_telemetry_log& log =
                                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                                *reinterpret_cast<nvme_telemetry_log*>(
                                    data.data());
                            if (lsp == NVME_LOG_TELEM_HOST_LSP_CREATE)
                            {
                                log.lpi = 0x07;
                                if (rc != 0)
                                {
                                    std::cerr
                                        << "failed to create telemetry host log"
                                        << std::endl;
                                    throw std::system_error(
                                        errno, std::generic_category());
                                }
                            }
                            else if (lsp == NVME_LOG_TELEM_HOST_LSP_RETAIN)
                            {
                                // nvme rev 1.3 only applies upto Area 3
                                log.dalb1 = 512;
                                log.dalb2 = 512;
                                log.dalb3 = 512;
                                data.resize(sizeof(nvme_telemetry_log) + 512);
                                std::string str = "hello world";
                                for (std::size_t i = 0; i < str.size(); i++)
                                {
                                    data[sizeof(nvme_telemetry_log) + i] =
                                        static_cast<uint8_t>(str[i]);
                                }

                                if (rc != 0)
                                {
                                    std::cerr
                                        << "failed to retain telemetry host "
                                           "log full log"
                                        << std::endl;
                                    throw std::system_error(
                                        errno, std::generic_category());
                                }
                            }
                            else
                            {
                                throw std::system_error(std::make_error_code(
                                    std::errc::invalid_argument));
                            }
                        }
                        break;
                        case NVME_LOG_LID_SMART:
                        {
                            data.resize(sizeof(nvme_smart_log));
                            nvme_smart_log& log =
                                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                                *reinterpret_cast<nvme_smart_log*>(data.data());
                            uint8_t temp = 40;
                            log.temperature[0] = temp;
                            log.temperature[1] = 1;
                            break;
                        }

                        default:
                        {
                            std::cerr << "unknown lid for GetLogPage"
                                      << std::endl;
                            throw std::system_error(std::make_error_code(
                                std::errc::invalid_argument));
                        }
                    }
                }
                catch (const ::std::system_error& e)
                {
                    self->io.post(
                        [cb{std::move(cb)}, ec = e.code()]() { cb(ec, {}); });
                }
                self->io.post(
                    [cb{std::move(cb)}, data{std::move(data)}]() mutable {
                    std::span<uint8_t> span{data.data(), data.size()};
                    cb({}, span);
                });
            });
        }
        catch (const std::runtime_error& e)
        {
            std::cerr << e.what() << std::endl;
            io.post([cb{std::move(cb)}]() {
                cb(std::make_error_code(std::errc::no_such_device), {});
            });
            return;
        }
    }
    void adminFwCommit(
        nvme_mi_ctrl_t ctrl, nvme_fw_commit_ca action, uint8_t slot, bool bpid,
        std::function<void(const std::error_code&, nvme_status_field)>&& cb)
        override
    {
        try
        {
            nvme_fw_commit_args args{};
            memset(&args, 0, sizeof(args));
            args.action = action;
            args.slot = slot;
            args.bpid = bpid;
            io.post([ctrl, args, cb{std::move(cb)},
                     self{shared_from_this()}]() mutable {
                // int rc = nvme_mi_admin_fw_commit(ctrl, &args);
                int rc = 1;
                if (rc < 0)
                {
                    std::cerr << "fail to subsystem_health_status_poll: "
                              << std::strerror(errno) << std::endl;
                    self->io.post([cb{std::move(cb)}]() {
                        cb(std::make_error_code(static_cast<std::errc>(errno)),
                           nvme_status_field::NVME_SC_MASK);
                    });
                    return;
                }
                if (rc > 0)
                {
                    switch (rc & 0x7ff)
                    {
                        case NVME_SC_FW_NEEDS_CONV_RESET:
                        case NVME_SC_FW_NEEDS_SUBSYS_RESET:
                        case NVME_SC_FW_NEEDS_RESET:
                            self->io.post([rc, cb{std::move(cb)}]() {
                                cb({}, static_cast<nvme_status_field>(rc));
                            });
                            break;
                        default:
                            std::string_view errMsg = statusToString(
                                static_cast<nvme_mi_resp_status>(rc));
                            std::cerr
                                << "fail to subsystem_health_status_poll: "
                                << errMsg << std::endl;
                            self->io.post([rc, cb{std::move(cb)}]() {
                                cb(std::make_error_code(std::errc::bad_message),
                                   static_cast<nvme_status_field>(rc));
                            });
                    }
                    return;
                }
            });
        }
        catch (const std::runtime_error& e)
        {
            std::cerr << e.what() << std::endl;
            io.post([cb{std::move(cb)}]() {
                cb(std::make_error_code(std::errc::no_such_device),
                   nvme_status_field::NVME_SC_MASK);
            });
            return;
        }
    }

    void adminXfer(nvme_mi_ctrl_t ctrl, const nvme_mi_admin_req_hdr& adminReq,
                   std::span<uint8_t> data, unsigned int /*timeout_ms*/,
                   std::function<void(const std::error_code&,
                                      const nvme_mi_admin_resp_hdr&,
                                      std::span<uint8_t>)>&& cb) override
    {
        try
        {
            std::vector<uint8_t> req(sizeof(nvme_mi_admin_req_hdr) +
                                     data.size());
            memcpy(req.data(), &adminReq, sizeof(nvme_mi_admin_req_hdr));
            memcpy(req.data() + sizeof(nvme_mi_admin_req_hdr), data.data(),
                   data.size());
            post([ctrl, req{std::move(req)}, self{shared_from_this()},
                  cb{std::move(cb)}]() mutable {
                int rc = 0;

                nvme_mi_admin_req_hdr* reqHeader =
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    reinterpret_cast<nvme_mi_admin_req_hdr*>(req.data());

                size_t respDataSize =
                    boost::endian::little_to_native<size_t>(reqHeader->dlen);
                // off_t respDataOffset =
                //     boost::endian::little_to_native<off_t>(reqHeader->doff);
                size_t bufSize = sizeof(nvme_mi_admin_resp_hdr) + respDataSize;
                std::vector<uint8_t> buf(bufSize);
                nvme_mi_admin_resp_hdr* respHeader =
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    reinterpret_cast<nvme_mi_admin_resp_hdr*>(buf.data());
                (void)respHeader;
                // rc = nvme_mi_admin_xfer(
                //     ctrl, reqHeader, req.size() -
                //     sizeof(nvme_mi_admin_req_hdr), respHeader,
                //     respDataOffset, &respDataSize);

                if (rc < 0)
                {
                    std::cerr << "failed to nvme_mi_admin_xfer" << std::endl;
                    self->io.post([cb{std::move(cb)}]() {
                        cb(std::make_error_code(static_cast<std::errc>(errno)),
                           {}, {});
                    });
                    return;
                }
                // the MI interface will only consume protocol/io errors
                // The client will take the reponsibility to deal with nvme-mi
                // status flag and nvme status field(cwd3). cmd specific return
                // value (cdw0) is also client's job.

                buf.resize(sizeof(nvme_mi_admin_resp_hdr) + respDataSize);
                self->io.post(
                    [cb{std::move(cb)}, data{std::move(buf)}]() mutable {
                    std::span<uint8_t> span(data.begin() +
                                                sizeof(nvme_mi_admin_resp_hdr),
                                            data.end());
                    nvme_smart_log& log =
                        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                        *reinterpret_cast<nvme_smart_log*>(span.data());
                    uint8_t temp = 40;
                    log.temperature[0] = temp;
                    log.temperature[1] = 1;
                    cb({},
                       // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                       *reinterpret_cast<nvme_mi_admin_resp_hdr*>(data.data()),
                       span);
                });
            });
        }
        catch (const std::runtime_error& e)
        {
            std::cerr << e.what() << std::endl;
            io.post([cb{std::move(cb)}]() {
                cb(std::make_error_code(std::errc::no_such_device), {}, {});
            });
            return;
        }
    }

    void adminSecuritySend(
        [[maybe_unused]] nvme_mi_ctrl_t ctrl, [[maybe_unused]] uint8_t proto,
        [[maybe_unused]] uint16_t protoSpecific,
        [[maybe_unused]] std::span<uint8_t> data,
        std::function<void(const std::error_code&, int nvmeStatus)>&& cb)
        override
    {
        cb(std::make_error_code(std::errc::not_supported), 0);
    }
    void adminSecurityReceive(
        [[maybe_unused]] nvme_mi_ctrl_t ctrl, [[maybe_unused]] uint8_t proto,
        [[maybe_unused]] uint16_t protoSpecific,
        [[maybe_unused]] uint32_t transferLength,
        std::function<void(const std::error_code&, int nvmeStatus,
                           const std::span<uint8_t> data)>&& cb) override
    {
        cb(std::make_error_code(std::errc::not_supported), 0, {});
    }

    void adminFwDownload(
        [[maybe_unused]] nvme_mi_ctrl_t ctrl,
        [[maybe_unused]] std::string firmwarefile,
        [[maybe_unused]] std::function<void(const std::error_code&,
                                            nvme_status_field)>&& cb) override
    {
        cb(std::make_error_code(std::errc::not_supported),
           nvme_status_field::NVME_SC_SUCCESS);
    }

    void adminNonDataCmd(
        [[maybe_unused]] nvme_mi_ctrl_t ctrl, [[maybe_unused]] uint8_t opcode,
        [[maybe_unused]] uint32_t cdw1, [[maybe_unused]] uint32_t cdw2,
        [[maybe_unused]] uint32_t cdw3, [[maybe_unused]] uint32_t cdw10,
        [[maybe_unused]] uint32_t cdw11, [[maybe_unused]] uint32_t cdw12,
        [[maybe_unused]] uint32_t cdw13, [[maybe_unused]] uint32_t cdw14,
        [[maybe_unused]] uint32_t cdw15,
        [[maybe_unused]] std::function<void(
            const std::error_code&, int nvmeStatus, uint32_t comptionDw0)>&& cb)
        override
    {
        cb(std::make_error_code(std::errc::not_supported), 0, 0);
    }

    void createNamespace(
        [[maybe_unused]] nvme_mi_ctrl_t ctrl, [[maybe_unused]] uint64_t size,
        [[maybe_unused]] size_t lbaFormat, [[maybe_unused]] bool metadataAtEnd,
        [[maybe_unused]] std::function<void(nvme_ex_ptr ex)>&& submittedCb,
        [[maybe_unused]] std::function<
            void(nvme_ex_ptr ex, NVMeNSIdentify newid)>&& finishedCb) override
    {
        /* TODO: return not support to the cb/s */
    }

    void adminDeleteNamespace(
        [[maybe_unused]] nvme_mi_ctrl_t ctrl, [[maybe_unused]] uint32_t nsid,
        [[maybe_unused]] std::function<void(const std::error_code&,
                                            int nvmeStatus)>&& cb) override
    {
        cb(std::make_error_code(std::errc::not_supported), 0);
    }

    void adminListNamespaces(
        [[maybe_unused]] nvme_mi_ctrl_t ctrl,
        [[maybe_unused]] std::function<
            void(nvme_ex_ptr ex, std::vector<uint32_t> ns)>&& cb) override
    {
        // return empty NS list
        return cb({}, {});
    }

    void adminAttachDetachNamespace(
        [[maybe_unused]] nvme_mi_ctrl_t ctrl, [[maybe_unused]] uint16_t ctrlid,
        [[maybe_unused]] uint32_t nsid, [[maybe_unused]] bool attach,
        [[maybe_unused]] std::function<void(const std::error_code&,
                                            int nvmeStatus)>&& cb) override
    {
        cb(std::make_error_code(std::errc::not_supported), 0);
    }

    void adminSanitize(
        [[maybe_unused]] nvme_mi_ctrl_t ctrl,
        [[maybe_unused]] enum nvme_sanitize_sanact sanact,
        [[maybe_unused]] uint8_t passes, [[maybe_unused]] uint32_t pattern,
        [[maybe_unused]] bool invertPattern,
        [[maybe_unused]] std::function<void(nvme_ex_ptr ex)>&& cb) override
    {
        /* TODO: return not support to the cb/s */
    }

  private:
    boost::asio::io_context& io;
    bool valid = false;

    bool workerStop = false;
    std::mutex workerMtx;
    std::condition_variable workerCv;
    boost::asio::io_context workerIO;
    bool workerIsNotified = false;
    std::thread thread;

    void post(std::function<void(void)>&& func);

    std::vector<nvme_mi_ctrl> ctrls;
};

void NVMeMiFake::post(std::function<void(void)>&& func)
{
    if (!workerStop)
    {
        std::unique_lock<std::mutex> lock(workerMtx);
        if (!workerStop)
        {
            std::cerr << "do post" << std::endl;
            workerIsNotified = true;
            workerIO.post(std::move(func));
            workerCv.notify_all();
            return;
        }
    }
    throw std::runtime_error("NVMeMi has been stopped");
}
