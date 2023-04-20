#include "NVMeMi.hpp"

#include "NVMeError.hpp"
#include "NVMeUtil.hpp"

#include <endian.h>

#include <boost/endian.hpp>

#include <cerrno>
#include <fstream>
#include <iostream>

std::map<int, std::weak_ptr<NVMeMi::Worker>> NVMeMi::workerMap{};

// libnvme-mi root service
nvme_root_t NVMeMi::nvmeRoot = nvme_mi_create_root(stderr, DEFAULT_LOGLEVEL);

constexpr size_t maxNVMeMILength = 4096;
constexpr int tcgDefaultTimeoutMS = 20 * 1000;

NVMeMi::NVMeMi(boost::asio::io_context& io,
               std::shared_ptr<sdbusplus::asio::connection> conn, int bus,
               int addr, bool singleThreadMode, PowerState readState) :
    io(io),
    conn(conn), dbus(*conn.get()), bus(bus), addr(addr), readState(readState)
{
    // reset to unassigned nid/eid and endpoint
    nid = -1;
    eid = 0;
    mctpPath.erase();
    nvmeEP = nullptr;

    // set update the worker thread
    if (!nvmeRoot)
    {
        throw std::runtime_error("invalid NVMe root");
    }

    if (singleThreadMode)
    {
        auto root = deriveRootBus(bus);

        if (!root || *root < 0)
        {
            throw std::runtime_error("invalid root bus number");
        }
        auto res = workerMap.find(*root);

        if (res == workerMap.end() || res->second.expired())
        {
            worker = std::make_shared<Worker>();
            workerMap[*root] = worker;
        }
        else
        {
            worker = res->second.lock();
        }
    }
    else
    {
        worker = std::make_shared<Worker>();
    }

    // setup the power state
    if (readState == PowerState::on || readState == PowerState::biosPost ||
        readState == PowerState::chassisOn)
    {
        // life time of the callback is binding to the NVMeMi instance, so only
        // this capture is required.
        powerCallback = setupPowerMatchCallback(conn, [this](PowerState, bool) {
            if (::readingStateGood(this->readState))
            {
                initMCTP();
            }
            else
            {
                closeMCTP();
            }
        });
    }

    // TODO: check the powerstate.
    initMCTP();
}

void NVMeMi::initMCTP()
{
    // already initiated
    if (isMCTPconnect())
    {
        return;
    }

    // init mctp ep via mctpd
    std::unique_lock<std::mutex> lock(mctpMtx);
    std::cerr << "[bus: " << bus << ", addr: " << addr << "]"
              << "start MCTP initialization" << std::endl;
    int i = 0;
    for (;; i++)
    {
        try
        {
            auto msg = dbus.new_method_call(
                "xyz.openbmc_project.MCTP", "/xyz/openbmc_project/mctp",
                "au.com.CodeConstruct.MCTP", "SetupEndpoint");

            msg.append("mctpi2c" + std::to_string(bus));
            msg.append(std::vector<uint8_t>{static_cast<uint8_t>(addr)});
            auto reply = msg.call(); // throw SdBusError

            reply.read(eid);
            reply.read(nid);
            reply.read(mctpPath);
            break;
        }
        catch (const std::exception& e)
        {
            if (i < 5)
            {
                std::cerr << "[bus: " << bus << ", addr: " << addr << "]"
                          << "retry to SetupEndpoint: " << e.what()
                          << std::endl;
            }
            else
            {
                nid = -1;
                eid = 0;
                mctpPath.erase();
                nvmeEP = nullptr;
                std::cerr << "[bus: " << bus << ", addr: " << addr << "]"
                          << "fail to init MCTP endpoint: " << e.what()
                          << std::endl;
                return;
            }
        }
    }

    // open mctp endpoint
    nvmeEP = nvme_mi_open_mctp(nvmeRoot, nid, eid);
    if (nvmeEP == nullptr)
    {
        nid = -1;
        eid = 0;
        // MCTPd won't expect to delete the ep object, just to erase the record
        // here.
        mctpPath.erase();
        nvmeEP = nullptr;
        std::cerr << "[bus: " << bus << ", addr: " << addr << "]"
                  << "can't open MCTP endpoint "
                  << std::to_string(nid) + ":" + std::to_string(eid)
                  << std::endl;
    }
    // TODO: make a flag to indicate the next health poll should return
    // no_such_device error. This is to inform the subsystem that the connected
    // has been reset or hot-swapped.
    std::cerr << "[bus: " << bus << ", addr: " << addr << "]"
              << "finish MCTP initialization.  "
              << std::to_string(nid) + ":" + std::to_string(eid) << std::endl;
}

void NVMeMi::closeMCTP()
{
    if (!isMCTPconnect())
    {
        return;
    }
    // each nvme mi message transaction should take relatively short time
    // (typically <= 200 ms). So the blocking time should be short
    std::unique_lock<std::mutex> lock(mctpMtx);
    std::cerr << "[bus: " << bus << ", addr: " << addr << "]"
              << "start MCTP closure" << std::endl;

    nvme_mi_close(nvmeEP);

    // Note: No need to remove MCTP ep from MCTPd since the routing table will
    // re-establish on the next init

    nid = -1;
    eid = 0;
    mctpPath.erase();
    nvmeEP = nullptr;
    std::cerr << "[bus: " << bus << ", addr: " << addr << "]"
              << "finish MCTP closure." << std::endl;
}

bool NVMeMi::isMCTPconnect() const
{
    return nid >= 0 && !mctpPath.empty() && nvmeEP != nullptr;
}

NVMeMi::Worker::Worker()
{ // start worker thread
    workerStop = false;
    thread = std::thread([&io = workerIO, &stop = workerStop, &mtx = workerMtx,
                          &cv = workerCv]() {
        // With BOOST_ASIO_DISABLE_THREADS, boost::asio::executor_work_guard
        // issues null_event across the thread, which caused invalid invokation.
        // We implement a simple invoke machenism based std::condition_variable.
        while (1)
        {
            io.run();
            io.restart();
            {
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock);
                if (stop)
                {
                    // exhaust all tasks and exit
                    io.run();
                    break;
                }
            }
        }
    });
}

NVMeMi::Worker::~Worker()
{
    // close worker
    workerStop = true;
    {
        std::unique_lock<std::mutex> lock(workerMtx);
        workerCv.notify_all();
    }
    thread.join();
}
NVMeMi::~NVMeMi()
{
    closeMCTP();
}

void NVMeMi::Worker::post(std::function<void(void)>&& func)
{
    if (workerStop)
    {
        throw std::runtime_error("NVMeMi has been stopped");
    }

    // TODO: need a timeout on this lock so we can return
    // a useful "busy" error message when the NVMe-MI endpoint is in-use
    std::unique_lock<std::mutex> lock(workerMtx);
    workerIO.post(std::move(func));
    workerCv.notify_all();
}

void NVMeMi::post(std::function<void(void)>&& func)
{
    worker->post(
        [self{std::move(shared_from_this())}, func{std::move(func)}]() {
        std::unique_lock<std::mutex> lock(self->mctpMtx);
        func();
    });
}

// Calls .post(), catching runtime_error and returning an error code on failure.
std::error_code NVMeMi::try_post(std::function<void(void)>&& func)
{
    try
    {
        post([self{shared_from_this()}, func{std::move(func)}]() { func(); });
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]" << e.what()
                  << std::endl;
        return std::make_error_code(std::errc::no_such_device);
    }
    return std::error_code();
}

void NVMeMi::miSubsystemHealthStatusPoll(
    std::function<void(const std::error_code&, nvme_mi_nvm_ss_health_status*)>&&
        cb)
{
    if (!nvmeEP)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]"
                  << "nvme endpoint is invalid" << std::endl;

        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device), nullptr);
        });
        return;
    }

    try
    {
        post([self{shared_from_this()}, cb{std::move(cb)}]() {
            nvme_mi_nvm_ss_health_status ss_health;
            auto rc = nvme_mi_mi_subsystem_health_status_poll(self->nvmeEP,
                                                              true, &ss_health);
            if (rc < 0)
            {
                std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                          << ", eid: " << static_cast<int>(self->eid) << "]"
                          << "fail to subsystem_health_status_poll: "
                          << std::strerror(errno) << std::endl;
                self->io.post([cb{std::move(cb)}, last_errno{errno}]() {
                    cb(std::make_error_code(static_cast<std::errc>(last_errno)),
                       nullptr);
                });
                return;
            }
            else if (rc > 0)
            {
                std::string_view errMsg =
                    statusToString(static_cast<nvme_mi_resp_status>(rc));
                std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                          << ", eid: " << static_cast<int>(self->eid) << "]"
                          << "fail to subsystem_health_status_poll: " << errMsg
                          << std::endl;
                self->io.post([cb{std::move(cb)}]() {
                    cb(std::make_error_code(std::errc::bad_message), nullptr);
                });
                return;
            }

            self->io.post(
                [cb{std::move(cb)}, ss_health{std::move(ss_health)}]() mutable {
                cb({}, &ss_health);
            });
        });
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]" << e.what()
                  << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device), {});
        });
        return;
    }
}

void NVMeMi::miScanCtrl(std::function<void(const std::error_code&,
                                           const std::vector<nvme_mi_ctrl_t>&)>
                            cb)
{
    if (!nvmeEP)
    {
        std::cerr << "nvme endpoint is invalid" << std::endl;

        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device), {});
        });
        return;
    }

    try
    {
        post([self{shared_from_this()}, cb{std::move(cb)}]() {
            int rc = nvme_mi_scan_ep(self->nvmeEP, true);
            if (rc < 0)
            {
                std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                          << ", eid: " << static_cast<int>(self->eid) << "]"
                          << "fail to scan controllers: "
                          << std::strerror(errno) << std::endl;
                self->io.post([cb{std::move(cb)}, last_errno{errno}]() {
                    cb(std::make_error_code(static_cast<std::errc>(last_errno)),
                       {});
                });
                return;
            }
            else if (rc > 0)
            {
                std::string_view errMsg =
                    statusToString(static_cast<nvme_mi_resp_status>(rc));
                std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                          << ", eid: " << static_cast<int>(self->eid) << "]"
                          << "fail to scan controllers: " << errMsg
                          << std::endl;
                self->io.post([cb{std::move(cb)}]() {
                    cb(std::make_error_code(std::errc::bad_message), {});
                });
                return;
            }

            std::vector<nvme_mi_ctrl_t> list;
            nvme_mi_ctrl_t c;
            nvme_mi_for_each_ctrl(self->nvmeEP, c)
            {
                list.push_back(c);
            }
            self->io.post(
                [cb{std::move(cb)}, list{std::move(list)}]() { cb({}, list); });
        });
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]" << e.what()
                  << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device), {});
        });
        return;
    }
}

void NVMeMi::adminIdentify(
    nvme_mi_ctrl_t ctrl, nvme_identify_cns cns, uint32_t nsid, uint16_t cntid,
    std::function<void(nvme_ex_ptr, std::span<uint8_t>)>&& cb)
{
    if (!nvmeEP)
    {
        std::cerr << "nvme endpoint is invalid" << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(makeLibNVMeError("nvme endpoint is invalid"), {});
        });
        return;
    }
    try
    {
        post([ctrl, cns, nsid, cntid, self{shared_from_this()},
              cb{std::move(cb)}]() {
            int rc = 0;
            std::vector<uint8_t> data;
            switch (cns)
            {
                case NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST:
                {
                    data.resize(sizeof(nvme_secondary_ctrl_list));
                    nvme_identify_args args{};
                    memset(&args, 0, sizeof(args));
                    args.result = nullptr;
                    args.data = data.data();
                    args.args_size = sizeof(args);
                    args.cns = cns;
                    args.csi = NVME_CSI_NVM;
                    args.nsid = nsid;
                    args.cntid = cntid;
                    args.cns_specific_id = NVME_CNSSPECID_NONE;
                    args.uuidx = NVME_UUID_NONE,

                    rc = nvme_mi_admin_identify_partial(ctrl, &args, 0,
                                                        data.size());

                    break;
                }

                default:
                {
                    data.resize(NVME_IDENTIFY_DATA_SIZE);
                    nvme_identify_args args{};
                    memset(&args, 0, sizeof(args));
                    args.result = nullptr;
                    args.data = data.data();
                    args.args_size = sizeof(args);
                    args.cns = cns;
                    args.csi = NVME_CSI_NVM;
                    args.nsid = nsid;
                    args.cntid = cntid;
                    args.cns_specific_id = NVME_CNSSPECID_NONE;
                    args.uuidx = NVME_UUID_NONE,

                    rc = nvme_mi_admin_identify(ctrl, &args);
                }
            }

            if (rc < 0)
            {
                std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                          << ", eid: " << static_cast<int>(self->eid) << "]"
                          << "fail to do nvme identify: "
                          << std::strerror(errno) << std::endl;
            }
            else if (rc > 0)
            {
                std::string_view errMsg =
                    statusToString(static_cast<nvme_mi_resp_status>(rc));
                std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                          << ", eid: " << static_cast<int>(self->eid) << "]"
                          << "fail to do nvme identify: " << errMsg
                          << std::endl;
            }

            auto ex = makeLibNVMeError(errno, rc, "adminIdentify");
            if (ex)
            {
                std::cerr << "fail to do nvme identify: " << ex->description()
                          << std::endl;
            }

            self->io.post(
                [cb{std::move(cb)}, ex, data{std::move(data)}]() mutable {
                std::span<uint8_t> span{data.data(), data.size()};
                cb(ex, span);
            });
        });
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]" << e.what()
                  << std::endl;
        auto msg = std::string("Runtime error: ") + e.what();
        std::cerr << msg << std::endl;
        io.post([cb{std::move(cb)}, msg]() { cb(makeLibNVMeError(msg), {}); });
        return;
    }
}

static int nvme_mi_admin_get_log_telemetry_host_rae(nvme_mi_ctrl_t ctrl,
                                                    bool /*rae*/, __u64 offset,
                                                    __u32 len, void* log)
{
    return nvme_mi_admin_get_log_telemetry_host(ctrl, offset, len, log);
}

// Get Temetery Log header and return the size for hdr + data area (Area 1, 2,
// 3, or maybe 4)
int getTelemetryLogSize(nvme_mi_ctrl_t ctrl, bool host, uint32_t& size)
{
    int rc = 0;
    nvme_telemetry_log log;
    auto func = host ? nvme_mi_admin_get_log_telemetry_host_rae
                     : nvme_mi_admin_get_log_telemetry_ctrl;

    // Only host telemetry log requires create.
    if (host)
    {
        rc = nvme_mi_admin_get_log_create_telemetry_host(ctrl, &log);
        if (rc)
        {
            std::cerr << "failed to create telemetry host log" << std::endl;
            return rc;
        }
    }

    rc = func(ctrl, false, 0, sizeof(log), &log);

    if (rc)
    {
        std::cerr << "failed to retain telemetry log for "
                  << (host ? "host" : "ctrl") << std::endl;
        return rc;
    }

    // Restrict the telemetry log to Data Area 1 and 2. Getting Data Area 3
    // OOB is not suitable due to its possible size. Data Area 3 can be up to
    // 30000 data blocks with each block being 512 bytes in size. Restricting
    // to Area 1 and 2.
    size = static_cast<uint32_t>(
               (boost::endian::little_to_native(log.dalb2) + 1)) *
           NVME_LOG_TELEM_BLOCK_SIZE;
    return rc;
}

void NVMeMi::getTelemetryLogChuck(
    nvme_mi_ctrl_t ctrl, bool host, uint64_t offset,
    std::vector<uint8_t>&& data,
    std::function<void(const std::error_code&, std::span<uint8_t>)>&& cb)
{
    if (offset >= data.size())
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]"
                  << "get telemetry log: offset exceed the log size. "
                  << "offset: " << offset << ", size: " << data.size()
                  << std::endl;
        cb(std::make_error_code(std::errc::invalid_argument), {});
        return;
    }

    post([self{shared_from_this()}, ctrl, host, offset, data{std::move(data)},
          cb{std::move(cb)}]() mutable {
        int rc = 0;
        bool rae = 1;
        auto func = host ? nvme_mi_admin_get_log_telemetry_host_rae
                         : nvme_mi_admin_get_log_telemetry_ctrl;
        uint32_t size = 0;

        // final transaction
        if (offset + nvme_mi_xfer_size >= data.size())
        {
            rae = 0;
        }
        size = std::min(static_cast<uint32_t>(nvme_mi_xfer_size),
                        static_cast<uint32_t>(data.size() - offset));

        rc = func(ctrl, rae, offset, size, data.data() + offset);

        if (rc < 0)
        {
            std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                      << ", eid: " << static_cast<int>(self->eid) << "]"
                      << "fail to get chuck for telemetry log: "
                      << std::strerror(errno) << std::endl;
            boost::asio::post(self->io,
                              [cb{std::move(cb)}, last_errno{errno}]() {
                cb(std::make_error_code(static_cast<std::errc>(last_errno)),
                   {});
            });
            return;
        }
        else if (rc > 0)
        {
            std::string_view errMsg =
                statusToString(static_cast<nvme_mi_resp_status>(rc));
            std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                      << ", eid: " << static_cast<int>(self->eid) << "]"
                      << "fail to get chuck for telemetry log: " << errMsg
                      << std::endl;
            boost::asio::post(self->io, [cb{std::move(cb)}]() {
                cb(std::make_error_code(std::errc::bad_message), {});
            });
            return;
        }

        if (rae == 0)
        {
            boost::asio::post(
                self->io, [cb{std::move(cb)}, data{std::move(data)}]() mutable {
                std::span<uint8_t> span{data.data(), data.size()};
                cb({}, span);
            });
            return;
        }

        offset += size;
        boost::asio::post(self->io,
                          [self, ctrl, host, offset, data{std::move(data)},
                           cb{std::move(cb)}]() mutable {
            self->getTelemetryLogChuck(ctrl, host, offset, std::move(data),
                                       std::move(cb));
        });
    });
}

void NVMeMi::adminGetLogPage(
    nvme_mi_ctrl_t ctrl, nvme_cmd_get_log_lid lid, uint32_t nsid, uint8_t lsp,
    uint16_t lsi,
    std::function<void(const std::error_code&, std::span<uint8_t>)>&& cb)
{
    if (!nvmeEP)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]"
                  << "nvme endpoint is invalid" << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device), {});
        });
        return;
    }

    try
    {
        post([ctrl, nsid, lid, lsp, lsi, self{shared_from_this()},
              cb{std::move(cb)}]() {
            std::vector<uint8_t> data;
            std::function<void(void)> logHandler;
            int rc = 0;
            switch (lid)
            {
                case NVME_LOG_LID_ERROR:
                {
                    data.resize(nvme_mi_xfer_size);
                    // The number of entries for most recent error logs.
                    // Currently we only do one nvme mi transfer for the
                    // error log to avoid blocking other tasks
                    static constexpr int num = nvme_mi_xfer_size /
                                               sizeof(nvme_error_log_page);
                    nvme_error_log_page* log =
                        reinterpret_cast<nvme_error_log_page*>(data.data());

                    rc = nvme_mi_admin_get_log_error(ctrl, num, false, log);
                    if (rc)
                    {
                        std::cerr
                            << "[bus: " << self->bus << ", addr: " << self->addr
                            << ", eid: " << static_cast<int>(self->eid) << "]"
                            << "fail to get error log" << std::endl;
                        break;
                    }
                }
                break;
                case NVME_LOG_LID_SMART:
                {
                    data.resize(sizeof(nvme_smart_log));
                    nvme_smart_log* log =
                        reinterpret_cast<nvme_smart_log*>(data.data());
                    rc = nvme_mi_admin_get_log_smart(ctrl, nsid, false, log);
                    if (rc)
                    {
                        std::cerr
                            << "[bus: " << self->bus << ", addr: " << self->addr
                            << ", eid: " << static_cast<int>(self->eid) << "]"
                            << "fail to get smart log" << std::endl;
                        break;
                    }
                }
                break;
                case NVME_LOG_LID_FW_SLOT:
                {
                    data.resize(sizeof(nvme_firmware_slot));
                    nvme_firmware_slot* log =
                        reinterpret_cast<nvme_firmware_slot*>(data.data());
                    rc = nvme_mi_admin_get_log_fw_slot(ctrl, false, log);
                    if (rc)
                    {
                        std::cerr
                            << "[bus: " << self->bus << ", addr: " << self->addr
                            << ", eid: " << static_cast<int>(self->eid) << "]"
                            << "fail to get firmware slot" << std::endl;
                        break;
                    }
                }
                break;
                case NVME_LOG_LID_CMD_EFFECTS:
                {
                    data.resize(sizeof(nvme_cmd_effects_log));
                    nvme_cmd_effects_log* log =
                        reinterpret_cast<nvme_cmd_effects_log*>(data.data());

                    // nvme rev 1.3 doesn't support csi,
                    // set to default csi = NVME_CSI_NVM
                    rc = nvme_mi_admin_get_log_cmd_effects(ctrl, NVME_CSI_NVM,
                                                           log);
                    if (rc)
                    {
                        std::cerr
                            << "[bus: " << self->bus << ", addr: " << self->addr
                            << ", eid: " << static_cast<int>(self->eid) << "]"
                            << "fail to get cmd supported and effects log"
                            << std::endl;
                        break;
                    }
                }
                break;
                case NVME_LOG_LID_DEVICE_SELF_TEST:
                {
                    data.resize(sizeof(nvme_self_test_log));
                    nvme_self_test_log* log =
                        reinterpret_cast<nvme_self_test_log*>(data.data());
                    rc = nvme_mi_admin_get_log_device_self_test(ctrl, log);
                    if (rc)
                    {
                        std::cerr
                            << "[bus: " << self->bus << ", addr: " << self->addr
                            << ", eid: " << static_cast<int>(self->eid) << "]"
                            << "fail to get device self test log" << std::endl;
                        break;
                    }
                }
                break;
                case NVME_LOG_LID_CHANGED_NS:
                {
                    data.resize(sizeof(nvme_ns_list));
                    nvme_ns_list* log =
                        reinterpret_cast<nvme_ns_list*>(data.data());
                    rc = nvme_mi_admin_get_log_changed_ns_list(ctrl, false,
                                                               log);
                    if (rc)
                    {
                        std::cerr
                            << "[bus: " << self->bus << ", addr: " << self->addr
                            << ", eid: " << static_cast<int>(self->eid) << "]"
                            << "fail to get changed namespace list"
                            << std::endl;
                        break;
                    }
                }
                break;
                case NVME_LOG_LID_TELEMETRY_HOST:
                // fall through to NVME_LOG_LID_TELEMETRY_CTRL
                case NVME_LOG_LID_TELEMETRY_CTRL:
                {
                    bool host = (lid == NVME_LOG_LID_TELEMETRY_HOST) ? true
                                                                     : false;

                    uint32_t size = 0;
                    rc = getTelemetryLogSize(ctrl, host, size);
                    if (rc == 0)
                    {
                        data.resize(size);
                        logHandler = [self, ctrl, host, data{std::move(data)},
                                      cb{std::move(cb)}]() mutable {
                            self->getTelemetryLogChuck(
                                ctrl, host, 0, std::move(data), std::move(cb));
                        };
                    }
                }
                break;
                case NVME_LOG_LID_RESERVATION:
                {
                    data.resize(sizeof(nvme_resv_notification_log));
                    nvme_resv_notification_log* log =
                        reinterpret_cast<nvme_resv_notification_log*>(
                            data.data());

                    int rc = nvme_mi_admin_get_log_reservation(ctrl, false,
                                                               log);
                    if (rc)
                    {
                        std::cerr
                            << "[bus: " << self->bus << ", addr: " << self->addr
                            << ", eid: " << static_cast<int>(self->eid) << "]"
                            << "fail to get reservation "
                               "notification log"
                            << std::endl;
                        break;
                    }
                }
                break;
                case NVME_LOG_LID_SANITIZE:
                {
                    data.resize(sizeof(nvme_sanitize_log_page));
                    nvme_sanitize_log_page* log =
                        reinterpret_cast<nvme_sanitize_log_page*>(data.data());

                    int rc = nvme_mi_admin_get_log_sanitize(ctrl, false, log);
                    if (rc)
                    {
                        std::cerr
                            << "[bus: " << self->bus << ", addr: " << self->addr
                            << ", eid: " << static_cast<int>(self->eid) << "]"
                            << "fail to get sanitize status log" << std::endl;
                        break;
                    }
                }
                break;
                default:
                {
                    std::cerr << "[bus: " << self->bus
                              << ", addr: " << self->addr
                              << ", eid: " << static_cast<int>(self->eid) << "]"
                              << "unknown lid for GetLogPage" << std::endl;
                    rc = -1;
                    errno = EINVAL;
                }
            }

            if (rc < 0)
            {
                std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                          << ", eid: " << static_cast<int>(self->eid) << "]"
                          << "fail to get log page: " << std::strerror(errno)
                          << std::endl;
                logHandler = [cb{std::move(cb)}, last_errno{errno}]() {
                    cb(std::make_error_code(static_cast<std::errc>(last_errno)),
                       {});
                };
            }
            else if (rc > 0)
            {
                std::string_view errMsg =
                    statusToString(static_cast<nvme_mi_resp_status>(rc));
                std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                          << ", eid: " << static_cast<int>(self->eid) << "]"
                          << "fail to get log pag: " << errMsg << std::endl;
                logHandler = [cb{std::move(cb)}]() {
                    cb(std::make_error_code(std::errc::bad_message), {});
                };
            }

            if (!logHandler)
            {
                logHandler = [cb{std::move(cb)},
                              data{std::move(data)}]() mutable {
                    std::span<uint8_t> span{data.data(), data.size()};
                    cb({}, span);
                };
            }
            boost::asio::post(self->io, logHandler);
        });
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]"
                  << "NVMeMi adminGetLogPage throws: " << e.what() << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device), {});
        });
        return;
    }
}

void NVMeMi::adminXfer(
    nvme_mi_ctrl_t ctrl, const nvme_mi_admin_req_hdr& admin_req,
    std::span<uint8_t> data, unsigned int timeout_ms,
    std::function<void(const std::error_code&, const nvme_mi_admin_resp_hdr&,
                       std::span<uint8_t>)>&& cb)
{
    if (!nvmeEP)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]"
                  << "nvme endpoint is invalid" << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device), {}, {});
        });
        return;
    }
    try
    {
        std::vector<uint8_t> req(sizeof(nvme_mi_admin_req_hdr) + data.size());
        memcpy(req.data(), &admin_req, sizeof(nvme_mi_admin_req_hdr));
        memcpy(req.data() + sizeof(nvme_mi_admin_req_hdr), data.data(),
               data.size());
        post([ctrl, req{std::move(req)}, self{shared_from_this()}, timeout_ms,
              cb{std::move(cb)}]() mutable {
            int rc = 0;

            nvme_mi_admin_req_hdr* reqHeader =
                reinterpret_cast<nvme_mi_admin_req_hdr*>(req.data());

            size_t respDataSize =
                boost::endian::little_to_native<size_t>(reqHeader->dlen);
            off_t respDataOffset =
                boost::endian::little_to_native<off_t>(reqHeader->doff);
            size_t bufSize = sizeof(nvme_mi_admin_resp_hdr) + respDataSize;
            std::vector<uint8_t> buf(bufSize);
            nvme_mi_admin_resp_hdr* respHeader =
                reinterpret_cast<nvme_mi_admin_resp_hdr*>(buf.data());

            // set timeout
            unsigned timeout = nvme_mi_ep_get_timeout(self->nvmeEP);
            nvme_mi_ep_set_timeout(self->nvmeEP, timeout_ms);

            rc = nvme_mi_admin_xfer(ctrl, reqHeader,
                                    req.size() - sizeof(nvme_mi_admin_req_hdr),
                                    respHeader, respDataOffset, &respDataSize);
            // revert to previous timeout
            nvme_mi_ep_set_timeout(self->nvmeEP, timeout);

            if (rc < 0)
            {
                std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                          << ", eid: " << static_cast<int>(self->eid) << "]"
                          << "failed to nvme_mi_admin_xfer" << std::endl;
                self->io.post([cb{std::move(cb)}, last_errno{errno}]() {
                    cb(std::make_error_code(static_cast<std::errc>(last_errno)),
                       {}, {});
                });
                return;
            }
            // the MI interface will only consume protocol/io errors
            // The client will take the reponsibility to deal with nvme-mi
            // status flag and nvme status field(cwd3). cmd specific return
            // value (cdw0) is also client's job.

            buf.resize(sizeof(nvme_mi_admin_resp_hdr) + respDataSize);
            self->io.post([cb{std::move(cb)}, data{std::move(buf)}]() mutable {
                std::span<uint8_t> span(
                    data.begin() + sizeof(nvme_mi_admin_resp_hdr), data.end());
                cb({}, *reinterpret_cast<nvme_mi_admin_resp_hdr*>(data.data()),
                   span);
            });
        });
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]" << e.what()
                  << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device), {}, {});
        });
        return;
    }
}

void NVMeMi::adminFwCommit(
    nvme_mi_ctrl_t ctrl, nvme_fw_commit_ca action, uint8_t slot, bool bpid,
    std::function<void(const std::error_code&, nvme_status_field)>&& cb)
{
    if (!nvmeEP)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]"
                  << "nvme endpoint is invalid" << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device),
               nvme_status_field::NVME_SC_MASK);
        });
        return;
    }
    try
    {
        nvme_fw_commit_args args;
        memset(&args, 0, sizeof(args));
        args.args_size = sizeof(args);
        args.action = action;
        args.slot = slot;
        args.bpid = bpid;
        io.post([ctrl, args, cb{std::move(cb)},
                 self{shared_from_this()}]() mutable {
            int rc = nvme_mi_admin_fw_commit(ctrl, &args);
            if (rc < 0)
            {
                std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                          << ", eid: " << static_cast<int>(self->eid) << "]"
                          << "fail to nvme_mi_admin_fw_commit: "
                          << std::strerror(errno) << std::endl;
                self->io.post([cb{std::move(cb)}, last_errno{errno}]() {
                    cb(std::make_error_code(static_cast<std::errc>(last_errno)),
                       nvme_status_field::NVME_SC_MASK);
                });
                return;
            }
            else if (rc >= 0)
            {
                switch (rc & 0x7ff)
                {
                    case NVME_SC_SUCCESS:
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
                            << "fail to nvme_mi_admin_fw_commit: " << errMsg
                            << std::endl;
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
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]" << e.what()
                  << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device),
               nvme_status_field::NVME_SC_MASK);
        });
        return;
    }
}

void NVMeMi::adminFwDownloadChunk(
    nvme_mi_ctrl_t ctrl, std::string firmwarefile, size_t size, size_t offset,
    int attempt_count,
    std::function<void(const std::error_code&, nvme_status_field)>&& cb)
{
    if (!nvmeEP)
    {
        std::cerr << "nvme endpoint is invalid" << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device),
               nvme_status_field::NVME_SC_MASK);
        });
        return;
    }
    try
    {
        post([ctrl, firmwarefile, size, offset, attempt_count,
              cb{std::move(cb)}, self{shared_from_this()}]() mutable {
            char data[nvme_mi_xfer_size];
            std::ifstream fwFile(firmwarefile, std::ios::in | std::ios::binary);
            if (fwFile.fail())
            {
                std::cerr << "fail to open fw image file: " << firmwarefile
                          << strerror(errno) << std::endl;
                self->io.post([cb{std::move(cb)}]() {
                    cb(std::make_error_code(static_cast<std::errc>(errno)),
                       nvme_status_field::NVME_SC_MASK);
                });
                return;
            }
            fwFile.seekg(offset, std::ios::beg);
            nvme_fw_download_args args;
            memset(&args, 0, sizeof(args));
            args.args_size = sizeof(args);
            int data_len = std::min(size - offset, nvme_mi_xfer_size);
            fwFile.read(data, data_len);
            fwFile.close();
            args.offset = offset;
            args.data_len = data_len;
            args.data = data;

            int rc = nvme_mi_admin_fw_download(ctrl, &args);
            if (rc < 0)
            {
                if (attempt_count > 0)
                {
                    std::cout << "Retrying the firmware chunk. With Offset :"
                              << offset << " Total firmware Size :" << size
                              << std::endl;
                    attempt_count = attempt_count - 1;
                }
                else
                {
                    std::cerr << "fail to nvme_mi_admin_fw_download: "
                              << std::strerror(errno) << std::endl;
                    self->io.post([cb{std::move(cb)}]() {
                        cb(std::make_error_code(static_cast<std::errc>(errno)),
                           nvme_status_field::NVME_SC_MASK);
                    });
                    return;
                }
            }
            else
            {
                attempt_count = 3; /* Reset the attempt count*/
                offset = offset + args.data_len;
            }
            if (offset >= size)
            {
                std::cout
                    << "Successfully transferred the firmware. Transfer Size : "
                    << offset << " Total Size :" << size << std::endl;
                self->io.post([rc, cb{std::move(cb)}]() {
                    cb({}, static_cast<nvme_status_field>(rc));
                });
                return;
            }
            self->adminFwDownloadChunk(ctrl, firmwarefile, size, offset,
                                       attempt_count, std::move(cb));
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

void NVMeMi::adminFwDownload(
    nvme_mi_ctrl_t ctrl, std::string firmwarefile,
    std::function<void(const std::error_code&, nvme_status_field)>&& cb)
{
    size_t offset = 0;
    int tryCount = 3;
    std::ifstream imageFile(firmwarefile,
                            std::ios::in | std::ios::binary | std::ios::ate);
    if (imageFile.fail())
    {
        std::cerr << "Can't open the firmware file: " << std::strerror(errno)
                  << std::endl;
        io.post([cb{std::move(cb)}]() {
            cb(std::make_error_code(std::errc::no_such_device),
               nvme_status_field::NVME_SC_MASK);
        });
    }
    size_t size = imageFile.tellg();
    imageFile.close();
    adminFwDownloadChunk(ctrl, firmwarefile, size, offset, tryCount,
                         std::move(cb));
}

void NVMeMi::adminSecuritySend(
    nvme_mi_ctrl_t ctrl, uint8_t proto, uint16_t proto_specific,
    std::span<uint8_t> data,
    std::function<void(const std::error_code&, int nvme_status)>&& cb)
{
    std::error_code post_err =
        try_post([self{shared_from_this()}, ctrl, proto, proto_specific, data,
                  cb{std::move(cb)}]() {
        struct nvme_security_send_args args;
        memset(&args, 0x0, sizeof(args));
        args.secp = proto;
        args.spsp0 = proto_specific & 0xff;
        args.spsp1 = proto_specific >> 8;
        args.nssf = 0;
        args.data = data.data();
        args.data_len = data.size_bytes();
        args.args_size = sizeof(struct nvme_security_send_args);

        unsigned timeout = nvme_mi_ep_get_timeout(self->nvmeEP);
        nvme_mi_ep_set_timeout(self->nvmeEP, tcgDefaultTimeoutMS);
        int status = nvme_mi_admin_security_send(ctrl, &args);
        nvme_mi_ep_set_timeout(self->nvmeEP, timeout);

        self->io.post([cb{std::move(cb)}, nvme_errno{errno}, status]() {
            auto err = std::make_error_code(static_cast<std::errc>(nvme_errno));
            cb(err, status);
        });
    });
    if (post_err)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]"
                  << "adminSecuritySend post failed: " << post_err << std::endl;
        io.post([cb{std::move(cb)}, post_err]() { cb(post_err, -1); });
    }
}

void NVMeMi::adminSecurityReceive(
    nvme_mi_ctrl_t ctrl, uint8_t proto, uint16_t proto_specific,
    uint32_t transfer_length,
    std::function<void(const std::error_code&, int nvme_status,
                       std::span<uint8_t> data)>&& cb)
{
    if (transfer_length > maxNVMeMILength)
    {
        cb(std::make_error_code(std::errc::invalid_argument), -1, {});
        return;
    }

    std::error_code post_err =
        try_post([self{shared_from_this()}, ctrl, proto, proto_specific,
                  transfer_length, cb{std::move(cb)}]() {
        std::vector<uint8_t> data(transfer_length);

        struct nvme_security_receive_args args;
        memset(&args, 0x0, sizeof(args));
        args.secp = proto;
        args.spsp0 = proto_specific & 0xff;
        args.spsp1 = proto_specific >> 8;
        args.nssf = 0;
        args.data = data.data();
        args.data_len = data.size();
        args.args_size = sizeof(struct nvme_security_receive_args);

        unsigned timeout = nvme_mi_ep_get_timeout(self->nvmeEP);
        nvme_mi_ep_set_timeout(self->nvmeEP, tcgDefaultTimeoutMS);
        int status = nvme_mi_admin_security_recv(ctrl, &args);
        nvme_mi_ep_set_timeout(self->nvmeEP, timeout);

        if (args.data_len > maxNVMeMILength)
        {
            std::cerr << "[bus: " << self->bus << ", addr: " << self->addr
                      << ", eid: " << static_cast<int>(self->eid) << "]"
                      << "nvme_mi_admin_security_send returned excess data, "
                      << args.data_len << std::endl;
            self->io.post([cb]() {
                cb(std::make_error_code(std::errc::protocol_error), -1, {});
            });
            return;
        }

        data.resize(args.data_len);
        self->io.post(
            [cb{std::move(cb)}, nvme_errno{errno}, status, data]() mutable {
            std::span<uint8_t> span{data.data(), data.size()};
            auto err = std::make_error_code(static_cast<std::errc>(nvme_errno));
            cb(err, status, span);
        });
    });
    if (post_err)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]"
                  << "adminSecurityReceive post failed: " << post_err
                  << std::endl;
        io.post([cb{std::move(cb)}, post_err]() { cb(post_err, -1, {}); });
    }
}

void NVMeMi::adminNonDataCmd(
    nvme_mi_ctrl_t ctrl, uint8_t opcode, uint32_t cdw1, uint32_t cdw2,
    uint32_t cdw3, uint32_t cdw10, uint32_t cdw11,
    uint32_t cdw12, uint32_t cdw13, uint32_t cdw14, uint32_t cdw15,
    std::function<void(const std::error_code&, int nvme_status,
                       uint32_t comption_dw0)>&& cb)
{
    std::error_code post_err =
        try_post([self{shared_from_this()}, ctrl, opcode, cdw1, cdw2, cdw3,
             cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, cb{std::move(cb)}]() {
        uint32_t comption_dw0 = 0;
        int nvme_status = nvme_mi_admin_admin_passthru(
            ctrl, opcode, 0, 0, cdw1, cdw2, cdw3, cdw10, cdw11, cdw12, cdw13,
            cdw14, cdw15, 0, nullptr, 0, nullptr, 10*1000, &comption_dw0);
        self->io.post(
            [cb{std::move(cb)}, nvme_errno{errno}, nvme_status, comption_dw0]() mutable {
            auto err = std::make_error_code(static_cast<std::errc>(nvme_errno));
            cb(err, nvme_status, comption_dw0);
        });
    });
    if (post_err)
    {
        std::cerr << "[bus: " << bus << ", addr: " << addr
                  << ", eid: " << static_cast<int>(eid) << "]"
                  << "adminNonDataCmd post failed: " << post_err
                  << std::endl;
        io.post([cb{std::move(cb)}, post_err]() { cb(post_err, -1, 0); });
    }
}

/* throws a nvme_ex_ptr on failure */
size_t NVMeMi::getBlockSize(nvme_mi_ctrl_t ctrl, size_t lba_format)
{
    struct nvme_id_ns id;
    printf("getblocksize\n");
    int status = nvme_mi_admin_identify_ns(ctrl, NVME_NSID_ALL, &id);
    auto e = makeLibNVMeError(errno, status, "getBlockSize");
    if (e)
    {
        throw e;
    }

    printf("nlbaf %d, lbaf %d\n", (int)id.nlbaf, (int)lba_format);

    // Sanity check for the value from the drive
    size_t max_lbaf = std::min(63, (int)id.nlbaf);

    // NLBAF is the maximum allowed index (not a count)
    if (lba_format > max_lbaf)
    {
        throw makeLibNVMeError("LBA format out of range, maximum is " +
                                   std::to_string(max_lbaf),
                               std::make_shared<CommonErr::InvalidArgument>());
    }

    return 1 << id.lbaf[lba_format].ds;
}

/*
 finished_cb will not be called if submitted_cb is called with a failure.
 */
void NVMeMi::createNamespace(
    nvme_mi_ctrl_t ctrl, uint64_t size, size_t lba_format, bool metadata_at_end,
    std::function<void(nvme_ex_ptr ex)>&& submitted_cb,
    std::function<void(nvme_ex_ptr ex, NVMeNSIdentify newid)>&& finished_cb)
{
    printf("createns %d\n", (int)gettid());
    std::error_code post_err = try_post(
        [self{shared_from_this()}, ctrl, size, lba_format, metadata_at_end,
         submitted_cb{std::move(submitted_cb)},
         finished_cb{std::move(finished_cb)}]() {
        size_t block_size;

        try
        {
            block_size = self->getBlockSize(ctrl, lba_format);
        }
        catch (nvme_ex_ptr e)
        {
            submitted_cb(e);
            return;
        }

        if (size % block_size != 0)
        {
            auto msg =
                std::string("Size must be a multiple of the block size ") +
                std::to_string(block_size);
            submitted_cb(std::make_shared<NVMeSdBusPlusError>(msg));
            return;
        }

        uint64_t blocks = size / block_size;

        // TODO: this will become nvme_ns_mgmt_host_sw_specified in a newer
        // libnvme.
        struct nvme_id_ns data;
        uint32_t new_nsid = 0;

        uint8_t flbas = 0;
        if (metadata_at_end)
        {
            flbas |= (1 << 4);
        }
        // low 4 bits at 0:3
        flbas |= (lba_format & 0xf);
        // high 2 bits at 5:6
        flbas |= ((lba_format & 0x30) << 1);

        memset(&data, 0x0, sizeof(data));
        data.nsze = ::htole64(blocks);
        data.ncap = ::htole64(blocks);
        data.flbas = flbas;

        printf("verified %d\n", (int)gettid());

        // submission has been verified.
        submitted_cb(nvme_ex_ptr());
        printf("after submitted_cb %d\n", (int)gettid());

        int status = nvme_mi_admin_ns_mgmt_create(ctrl, &data, 0, &new_nsid);
        nvme_ex_ptr e = makeLibNVMeError(errno, status, "createVolume");

        NVMeNSIdentify newns = {
            .namespaceId = new_nsid,
            .size = size,
            .capacity = size,
            .blockSize = block_size,
            .lbaFormat = lba_format,
            .metadataAtEnd = metadata_at_end,
        };

        self->io.post([finished_cb{std::move(finished_cb)}, e, newns]() {
            finished_cb(e, newns);
        });

#if 0
        // TODO testing purposes
        static uint32_t counter = 20;

        printf("createNamespace top, sleeping 5 seconds\n");
        sleep(5);

        uint32_t new_ns = counter++;

        printf("create complete. ns %d\n", new_ns);

        auto err = std::make_error_code(static_cast<std::errc>(0));
        cb(err, 0, new_ns);
#endif
    });

    printf("submitted cb %d\n", (int)gettid());

    if (post_err)
    {
        std::cerr << "adminAttachDetachNamespace post failed: " << post_err
                  << std::endl;
        auto e = makeLibNVMeError(post_err, -1, "createVolume");
        io.post(
            [submitted_cb{std::move(submitted_cb)}, e]() { submitted_cb(e); });
    }
}

// Deletes a namespace
void NVMeMi::adminDeleteNamespace(
    nvme_mi_ctrl_t ctrl, uint32_t nsid,
    std::function<void(const std::error_code&, int nvme_status)>&& cb)
{
    std::error_code post_err = try_post(
        [self{shared_from_this()}, ctrl, nsid, cb{std::move(cb)}]() {
        int status = nvme_mi_admin_ns_mgmt_delete(ctrl, nsid);

        self->io.post([cb{std::move(cb)}, nvme_errno{errno}, status]() {
            auto err = std::make_error_code(static_cast<std::errc>(nvme_errno));
            cb(err, status);
        });
    });
    if (post_err)
    {
        std::cerr << "deleteNamespace post failed: " << post_err << std::endl;
        io.post([cb{std::move(cb)}, post_err]() { cb(post_err, -1); });
    }
}

void NVMeMi::adminListNamespaces(
    nvme_mi_ctrl_t ctrl,
    std::function<void(nvme_ex_ptr, std::vector<uint32_t> ns)>&& cb)
{
    std::error_code post_err = try_post(
        [self{shared_from_this()}, ctrl, cb{std::move(cb)}]() {
        int status, nvme_errno;
        std::vector<uint32_t> ns;
        // sanity in case of bad drives, allows for >1million NSes
        const int MAX_ITER = 1000;

        for (int i = 0; i < MAX_ITER; i++)
        {
            struct nvme_ns_list list;
            uint32_t start = NVME_NSID_NONE;
            if (!ns.empty())
            {
                start = ns.back() + 1;
            }
            status =
                nvme_mi_admin_identify_allocated_ns_list(ctrl, start, &list);
            nvme_errno = errno;
            if (status != 0)
            {
                ns.clear();
                break;
            }

            for (size_t i = 0; i < NVME_ID_NS_LIST_MAX; i++)
            {
                if (!list.ns[i])
                {
                    break;
                }
                ns.push_back(list.ns[i]);
            }
            if (list.ns[NVME_ID_NS_LIST_MAX - 1] == 0)
            {
                // all entries read
                break;
            }
        }

        auto ex = makeLibNVMeError(nvme_errno, status, "adminListNamespaces");
        self->io.post([cb{std::move(cb)}, ex, ns]() { cb(ex, ns); });
    });
    if (post_err)
    {
        auto ex = makeLibNVMeError("post failed");
        io.post([cb{std::move(cb)}, ex]() { cb(ex, std::vector<uint32_t>()); });
    }
}

// Attaches or detaches a namespace from a controller
void NVMeMi::adminAttachDetachNamespace(
    nvme_mi_ctrl_t ctrl, uint16_t ctrlid, uint32_t nsid, bool attach,
    std::function<void(const std::error_code&, int nvme_status)>&& cb)
{
    std::error_code post_err = try_post([self{shared_from_this()}, ctrl, nsid,
                                         attach, ctrlid, cb{std::move(cb)}]() {
        struct nvme_ctrl_list ctrl_list;
        struct nvme_ns_attach_args args;
        memset(&args, 0x0, sizeof(args));

        // TODO: add this to a newer libnvme
        // uint16_t ctrl_id = nvme_mi_ctrl_id(ctrl);
        uint16_t ctrl_id = ctrlid;
        nvme_init_ctrl_list(&ctrl_list, 1, &ctrl_id);
        args.ctrlist = &ctrl_list;
        args.nsid = nsid;
        if (attach)
        {
            args.sel = NVME_NS_ATTACH_SEL_CTRL_ATTACH;
        }
        else
        {
            args.sel = NVME_NS_ATTACH_SEL_CTRL_DEATTACH;
        }
        args.args_size = sizeof(args);

        int status = nvme_mi_admin_ns_attach(ctrl, &args);
        self->io.post([cb{std::move(cb)}, nvme_errno{errno}, status]() {
            auto err = std::make_error_code(static_cast<std::errc>(nvme_errno));
            cb(err, status);
        });
    });
    if (post_err)
    {
        std::cerr << "adminAttachDetachNamespace post failed: " << post_err
                  << std::endl;
        io.post([cb{std::move(cb)}, post_err]() { cb(post_err, -1); });
    }
}
