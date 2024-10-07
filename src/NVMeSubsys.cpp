#include "NVMeSubsys.hpp"

#include "AsioHelper.hpp"
#include "NVMeDrive.hpp"
#include "NVMeError.hpp"
#include "NVMePlugin.hpp"
#include "NVMeUtil.hpp"
#include "Thresholds.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <dlfcn.h>

#include <boost/asio/spawn.hpp>

#include <charconv>
#include <filesystem>
#include <stdexcept>

void NVMeSubsystem::createAssociation()
{
    assocIntf = objServer.add_interface(path, association::interface);
    assocIntf->register_property("Associations", makeAssociation());
    assocIntf->initialize();
}

void NVMeSubsystem::updateAssociation()
{
    assocIntf->set_property("Associations", makeAssociation());
}

std::vector<Association> NVMeSubsystem::makeAssociation() const
{
    std::vector<Association> associations;
    std::filesystem::path p(path);

    associations.emplace_back("chassis", "storage", p.parent_path().string());
    associations.emplace_back("chassis", "drive", p.parent_path().string());
    associations.emplace_back("drive", "storage", path);

    for (const auto& [_, prog] : createProgress)
    {
        associations.emplace_back("awaiting", "awaited", prog->path);
    }

    for (const auto& [_, vol] : volumes)
    {
        associations.emplace_back("containing", "contained", vol->path);
    }

    return associations;
}

// get temporature from a NVMe Basic reading.
static double getTemperatureReading(int8_t reading)
{
    if (reading == static_cast<int8_t>(0x80) ||
        reading == static_cast<int8_t>(0x81))
    {
        // 0x80 = No temperature data or temperature data is more the 5 s
        // old 0x81 = Temperature sensor failure
        return std::numeric_limits<double>::quiet_NaN();
    }

    return reading;
}

std::shared_ptr<NVMeSubsystem> NVMeSubsystem::create(
    boost::asio::io_context& io, sdbusplus::asio::object_server& objServer,
    std::shared_ptr<sdbusplus::asio::connection> conn, const std::string& path,
    const std::string& name, const SensorData& configData, NVMeIntf intf)
{
    auto self = std::shared_ptr<NVMeSubsystem>(
        new NVMeSubsystem(io, objServer, conn, path, name, configData, intf));
    self->init();
    return self;
}

NVMeSubsystem::NVMeSubsystem(boost::asio::io_context& io,
                             sdbusplus::asio::object_server& objServer,
                             std::shared_ptr<sdbusplus::asio::connection> conn,
                             const std::string& path, const std::string& name,
                             const SensorData& configData, NVMeIntf intf) :
    NVMeStorage(objServer, *dynamic_cast<sdbusplus::bus_t*>(conn.get()),
                path.c_str()),
    path(path), io(io), objServer(objServer), conn(conn), name(name),
    config(configData), nvmeIntf(intf), status(Status::Stop)
{}

// Performs initialisation after shared_from_this() has been set up.
void NVMeSubsystem::init()
{
    NVMeIntf::Protocol protocol{NVMeIntf::Protocol::NVMeBasic};
    try
    {
        protocol = nvmeIntf.getProtocol();
    }
    catch (const std::runtime_error&)
    {
        throw std::runtime_error("NVMe interface is null");
    }

    // initiate the common interfaces (thermal sensor, Drive and Storage)
    if (protocol != NVMeIntf::Protocol::NVMeBasic &&
        protocol != NVMeIntf::Protocol::NVMeMI)
    {
        throw std::runtime_error("Unsupported NVMe interface");
    }

    /* xyz.openbmc_project.Inventory.Item.Storage */
    NVMeStorage::init(
        std::static_pointer_cast<NVMeStorage>(shared_from_this()));

    /* xyz.openbmc_project.Inventory.Item.Drive */
    drive = std::make_shared<NVMeDrive>(io, conn, path, weak_from_this());
    drive->protocol(NVMeDrive::DriveProtocol::NVMe);
    drive->type(NVMeDrive::DriveType::SSD);
    // TODO: update capacity

    // make association for Drive/Storage/Chassis
    createAssociation();
}

NVMeSubsystem::~NVMeSubsystem()
{
    objServer.remove_interface(assocIntf);
}

void NVMeSubsystem::processSecondaryControllerList(
    nvme_secondary_ctrl_list* secCntlrList)
{
    auto findPrimary = controllers.begin();
    int secCntlrCount = 0;
    if (secCntlrList != nullptr)
    {
        // all sc_entry pointing to a single pcid, so we only check
        // the first entry.
        findPrimary = controllers.find(secCntlrList->sc_entry[0].pcid);
        if (findPrimary == controllers.end())
        {
            std::cerr << "fail to match primary controller from "
                         "identify sencondary cntrl list"
                      << std::endl;
            status = Status::Aborting;
            markFunctional(false);
            markAvailable(false);
            return;
        }
        secCntlrCount = secCntlrList->num;
    }

    // Enable primary controller since they are required to work
    auto& pc = findPrimary->second.first;
    primaryController = NVMeControllerEnabled::create(std::move(*pc));
    // replace with the new controller object
    pc = primaryController;

    std::vector<std::shared_ptr<NVMeController>> secCntrls;
    for (int i = 0; i < secCntlrCount; i++)
    {
        auto findSecondary = controllers.find(secCntlrList->sc_entry[i].scid);
        if (findSecondary == controllers.end())
        {
            std::cerr << "fail to match secondary controller from "
                         "identify sencondary cntrl list"
                      << std::endl;
            break;
        }

        auto& secondaryController = findSecondary->second.first;

        // Check Secondary Controller State
        if (secCntlrList->sc_entry[i].scs != 0)
        {
            secondaryController =
                NVMeControllerEnabled::create(std::move(*secondaryController));
        }
        secondaryController->setSecondary();
        secCntrls.push_back(secondaryController);
    }
    primaryController->setPrimary(secCntrls);

    boost::asio::spawn(
        io, [self{shared_from_this()}](boost::asio::yield_context yield) {
        try
        {
            self->fillDrive(yield);
            self->updateVolumes(yield);
            self->querySupportedFormats(yield);
            std::cerr << "finished NS enum" << std::endl;
        }
        catch (const std::exception& e)
        {
            std::cerr << std::format("[{}] failed starting the subsystem: {}",
                                     self->name, e.what())
                      << std::endl;
            self->status = Status::Aborting;
            self->markFunctional(false);
            self->markAvailable(false);
            return;
        }
        // start controller
        for (auto& [_, pair] : self->controllers)
        {
            // create controller plugin
            if (self->plugin)
            {
                pair.second = self->plugin->createControllerPlugin(
                    *pair.first, self->config);
            }
            pair.first->start(pair.second);
        }
        // start plugin
        if (self->plugin)
        {
            self->plugin->start();
        }

        self->status = Status::Start;
    });
}

void NVMeSubsystem::markFunctional(bool toggle)
{
    if (ctemp)
    {
        ctemp->markFunctional(toggle);
    }

    if (nvmeIntf.getProtocol() == NVMeIntf::Protocol::NVMeBasic)
    {
        return;
    }

    // disable the subsystem
    if (!toggle)
    {
        if (status == Status::Intiatilzing)
        {
            throw std::runtime_error(
                "cannot stop: the subsystem is intiatilzing");
        }

        if (status == Status::Terminating || status == Status::Stop)
        {
            return;
        }

        assert(status == Status::Start || status == Status::Aborting);

        status = Status::Terminating;
        if (plugin)
        {
            plugin->stop();
        }
        // TODO: the controller should be stopped after controller level polling
        // is enabled

        // Tell any progress objects we're aborting the operation
        for (auto& [_, v] : createProgress)
        {
            v->abort();
        }

        // Tell the controllers they mustn't post further jobs
        if (primaryController)
        {
            primaryController->stop();
        }

        for (auto& [_, v] : controllers)
        {
            v.first->stop();
        }

        // Avoid triggering C*V D-Bus updates by clearing internal state
        // directly. The controller and volume objects and interfaces will be
        // removed which will update the mapper.
        attached.clear();
        volumes.clear();
        primaryController.reset();
        controllers.clear();
        // plugin.reset();

        updateAssociation();

        if (nvmeIntf.getProtocol() == NVMeIntf::Protocol::NVMeMI)
        {
            auto nvme =
                std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());

            bool posted =
                nvme->flushOperations([self{shared_from_this()}]() mutable {
                self->status = Status::Stop;
            });

            if (!posted)
            {
                std::cerr
                    << "Failed to flush operations, subsystem has stalled!"
                    << std::endl;
            }
        }

        return;
    }

    if (status == Status::Intiatilzing)
    {
        throw std::runtime_error("cannot start: the subsystem is intiatilzing");
    }

    if (status == Status::Aborting)
    {
        throw std::runtime_error(
            "cannot start: subsystem initialisation has aborted and must transition to stopped");
    }

    if (status == Status::Start || status == Status::Terminating)
    {
        // Prevent consecutive calls to NVMeMiIntf::miScanCtrl()
        //
        // NVMeMiIntf::miScanCtrl() calls nvme_mi_scan_ep(..., true), which
        // forces a rescan and invalidates any nvme_mi_ctrl objects created on a
        // previous scan.
        //
        // We require a transition through Status::Stop (via
        // `markFunctional(false)`) so that the lifetime of the NVMeController
        // instances in this->controllers do not exceed the lifetime of their
        // associated nvme_mi_ctrl object.
        return;
    }

    assert(status == Status::Stop);

    status = Status::Intiatilzing;
    markAvailable(toggle);

    // add controllers for the subsystem
    if (nvmeIntf.getProtocol() == NVMeIntf::Protocol::NVMeMI)
    {
        auto nvme =
            std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());
        nvme->miScanCtrl(
            [self{shared_from_this()},
             nvme](const std::error_code& ec,
                   const std::vector<nvme_mi_ctrl_t>& ctrlList) mutable {
            if (ec || ctrlList.empty())
            {
                // TODO: mark the subsystem invalid and reschedule refresh
                std::cerr << "fail to scan controllers for the nvme subsystem"
                          << (ec ? ": " + ec.message() : "") << std::endl;
                self->status = Status::Aborting;
                self->markFunctional(false);
                self->markAvailable(false);
                return;
            }

            // TODO: manually open nvme_mi_ctrl_t from cntrl id, instead hacking
            // into structure of nvme_mi_ctrl
            for (auto* c : ctrlList)
            {
                /* calucate the cntrl id from nvme_mi_ctrl:
                struct nvme_mi_ctrl
                {
                    struct nvme_mi_ep* ep;
                    __u16 id;
                    struct list_node ep_entry;
                };
                */
                uint16_t* index = reinterpret_cast<uint16_t*>(
                    (reinterpret_cast<uint8_t*>(c) +
                     std::max(sizeof(uint16_t), sizeof(void*))));
                std::filesystem::path path = std::filesystem::path(self->path) /
                                             "controllers" /
                                             std::to_string(*index);

                try
                {
                    auto nvmeController = std::make_shared<NVMeController>(
                        self->io, self->objServer, self->conn, path.string(),
                        nvme, c, self->weak_from_this());

                    self->controllers.insert({*index, {nvmeController, {}}});
                }
                catch (const std::exception& e)
                {
                    std::cerr << "failed to create controller: "
                              << std::to_string(*index)
                              << ", reason: " << e.what() << std::endl;
                }

                index++;
            }
            // self->createStorageAssociation();

            /* Begin of patch context
             *
             *
             *
             */
            /*
             *
             *
             * End of patch context
             */

            /*
            find primary controller and make association
            The controller is SR-IOV, meaning all controllers (within a
            subsystem) are pointing to a single primary controller. So we
            only need to do identify on an arbatary controller.
            If the controller list contains a single controller. Skip
            identifying the secondary controller list. It will be the primary
            controller.
            */
            if (ctrlList.size() == 1)
            {
                self->processSecondaryControllerList(nullptr);
                return;
            }
            auto* ctrl = ctrlList.back();
            nvme->adminIdentify(
                ctrl, nvme_identify_cns::NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST,
                0, 0,
                [self{self->shared_from_this()}](nvme_ex_ptr ex,
                                                 std::span<uint8_t> data) {
                if (ex || data.size() < sizeof(nvme_secondary_ctrl_list))
                {
                    std::cerr << "fail to identify secondary controller list"
                              << std::endl;
                    self->status = Status::Aborting;
                    self->markFunctional(false);
                    self->markAvailable(false);
                    return;
                }
                nvme_secondary_ctrl_list* listHdr =
                    reinterpret_cast<nvme_secondary_ctrl_list*>(data.data());

                if (listHdr->num == 0)
                {
                    std::cerr << "empty identify secondary controller list"
                              << std::endl;
                    self->status = Status::Aborting;
                    self->markFunctional(false);
                    self->markAvailable(false);
                    return;
                }
                self->processSecondaryControllerList(listHdr);
            });
        });
    }
}

void NVMeSubsystem::markAvailable(bool toggle)
{
    if (ctemp)
    {
        ctemp->markAvailable(toggle);
    }

    if (nvmeIntf.getProtocol() == NVMeIntf::Protocol::NVMeBasic)
    {
        return;
    }

    if (toggle)
    {
        // TODO: make the Available interface true
        unavailableCount = 0;
        return;
    }
    // TODO: make the Available interface false
    unavailableCount = unavailableMaxCount;
}

std::shared_ptr<NVMeControllerEnabled>
    NVMeSubsystem::getPrimaryController() const
{
    if (!primaryController)
    {
        std::cerr << "dbus call for inactive NVMe subsystem " << name
                  << ". Returning Unavailable\n";
        throw sdbusplus::xyz::openbmc_project::Common::Error::Unavailable();
    }
    return primaryController;
}

/* Begin of patch context
 *
 *
 *
 */
/*
 *
 *
 * End of patch context
 */

void NVMeSubsystem::start()
{
    for (auto [_, lib] : pluginLibMap)
    {
        createplugin_t pluginFunc =
            reinterpret_cast<createplugin_t>(::dlsym(lib, "createPlugin"));
        auto p = pluginFunc(shared_from_this(), config);
        if (p)
        {
            plugin = p;
            break;
        }
    }
    // add thermal sensor for the subsystem
    std::optional<std::string> sensorName = createSensorNameFromPath(path);
    if (!sensorName)
    {
        // fail to parse sensor name from path, using name instead.
        sensorName.emplace(name);
    }

    std::vector<thresholds::Threshold> sensorThresholds;
    if (!parseThresholdsFromConfig(config, sensorThresholds))
    {
        std::cerr << "error populating thresholds for " << *sensorName << "\n";
        throw std::runtime_error("error populating thresholds for " +
                                 *sensorName);
    }

    if (ctemp || ctempTimer)
    {
        throw std::logic_error(
            "NVMeSubsystem::start() called from invalid state");
    }

    assert(!ctemp && !ctempTimer);

    PowerState powerState = PowerState::always;
    auto sensorBase = config.find(configInterfaceName(nvme::sensorType));
    if (sensorBase == config.end())
    {
        std::cerr << "Warning: " << name
                  << ": cannot find sensor config " +
                         configInterfaceName(nvme::sensorType)
                  << std::endl;
    }
    else
    {
        const SensorBaseConfigMap& sensorConfig = sensorBase->second;
        powerState = getPowerState(sensorConfig);
    }

    /* Begin of patch context
     *
     *
     *
     */
    /*
     *
     *
     * End of patch context
     */

    ctemp = std::make_shared<NVMeSensor>(objServer, io, conn, *sensorName,
                                         std::move(sensorThresholds), path,
                                         powerState);
    ctempTimer = std::make_shared<boost::asio::steady_timer>(io);

    // start to poll value for CTEMP sensor.
    if (nvmeIntf.getProtocol() == NVMeIntf::Protocol::NVMeBasic)
    {
        auto intf =
            std::get<std::shared_ptr<NVMeBasicIntf>>(nvmeIntf.getInferface());
        ctemp_fetch_t<NVMeBasicIntf::DriveStatus*> dataFetcher =
            [intf, self{std::move(shared_from_this())},
             timer = std::weak_ptr<boost::asio::steady_timer>(ctempTimer)](
                std::function<void(const std::error_code&,
                                   NVMeBasicIntf::DriveStatus*)>&& cb) {
            /* Potentially defer sampling the sensor sensor if it is in error */
            if (!self->ctemp->sample())
            {
                cb(std::make_error_code(std::errc::operation_canceled),
                   nullptr);
                return;
            }

            intf->getStatus(std::move(cb));
        };
        ctemp_process_t<NVMeBasicIntf::DriveStatus*> dataProcessor =
            [self{shared_from_this()},
             timer = std::weak_ptr<boost::asio::steady_timer>(ctempTimer)](
                const std::error_code& error,
                NVMeBasicIntf::DriveStatus* status) {
            // deferred sampling
            if (error == std::errc::operation_canceled)
            {
                return;
            }
            // The device is physically absent
            if (error == std::errc::no_such_device)
            {
                std::cerr << "error reading ctemp from subsystem"
                          << ", reason:" << error.message() << "\n";
                self->markFunctional(false);
                self->markAvailable(false);
                return;
            }
            // other communication errors
            if (error)
            {
                std::cerr << "error reading ctemp from subsystem"
                          << ", reason:" << error.message() << "\n";
                self->ctemp->incrementError();
                return;
            }

            if (status == nullptr)
            {
                std::cerr << "empty data returned by data fetcher" << std::endl;
                self->markFunctional(false);
                return;
            }

            uint8_t flags = status->Status;
            if (((flags & NVMeBasicIntf::StatusFlags::
                              NVME_MI_BASIC_SFLGS_DRIVE_NOT_READY) != 0) ||
                ((flags & NVMeBasicIntf::StatusFlags::
                              NVME_MI_BASIC_SFLGS_DRIVE_FUNCTIONAL) == 0))
            {
                std::cerr
                    << self->name
                    << ": health poll returns drive not ready or drive not functional"
                    << std::endl;
                self->markFunctional(false);
                return;
            }
            self->ctemp->updateValue(getTemperatureReading(status->Temp));
        };

        pollCtemp(ctempTimer, pollingInterval, dataFetcher, dataProcessor);
    }
    else if (nvmeIntf.getProtocol() == NVMeIntf::Protocol::NVMeMI)
    {
        auto intf =
            std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());

        ctemp_fetch_t<nvme_mi_nvm_ss_health_status*> dataFetcher =
            [intf, self{std::move(shared_from_this())},
             timer = std::weak_ptr<boost::asio::steady_timer>(ctempTimer)](
                std::function<void(const std::error_code&,
                                   nvme_mi_nvm_ss_health_status*)>&& cb) {
            // do not poll the health status if subsystem is in cooldown
            if (self->unavailableCount > 0)
            {
                cb(std::make_error_code(std::errc::operation_canceled),
                   nullptr);
                return;
            }

            // do not poll the health status if the subsystem is intiatilzing
            if (self->status == Status::Intiatilzing)
            {
                std::cerr << "subsystem is intiatilzing, cancel the health poll"
                          << std::endl;
                cb(std::make_error_code(std::errc::operation_canceled),
                   nullptr);
                return;
            }
            intf->miSubsystemHealthStatusPoll(std::move(cb));
        };
        ctemp_process_t<nvme_mi_nvm_ss_health_status*> dataProcessor =
            [self{shared_from_this()},
             timer = std::weak_ptr<boost::asio::steady_timer>(ctempTimer)](
                const std::error_code& error,
                nvme_mi_nvm_ss_health_status* status) {
            if (self->unavailableCount > 0)
            {
                self->unavailableCount--;
                return;
            }

            if (error == std::errc::operation_canceled)
            {
                std::cerr << "processing health data has been cancelled"
                          << std::endl;
                return;
            }

            if (self->status == Status::Intiatilzing)
            {
                // on initialization, the subsystem will not update the status.
                std::cerr
                    << "subsystem is intiatilzing, do not process the status"
                    << std::endl;
                return;
            }

            if (error == std::errc::no_such_device)
            {
                std::cerr << "error reading ctemp "
                             "from subsystem"
                          << ", reason:" << error.message() << "\n";
                // stop the subsystem
                self->markFunctional(false);
                self->markAvailable(false);

                return;
            }
            if (error)
            {
                std::cerr << "error reading ctemp "
                             "from subsystem"
                          << ", reason:" << error.message() << "\n";
                self->ctemp->incrementError();
                if (self->ctemp->inError())
                {
                    auto intf = std::get<std::shared_ptr<NVMeMiIntf>>(
                        self->nvmeIntf.getInferface());
                    intf->recover();
                    // stop the subsystem
                    self->markFunctional(false);
                    self->markAvailable(false);
                }
                return;
            }

            // Drive Functional
            bool df = (status->nss & 0x20) != 0;
            if (!df)
            {
                // stop the subsystem
                std::cerr << self->name << ": health poll returns df status 0"
                          << std::endl;
                self->markFunctional(false);
                return;
            }

            self->markFunctional(true);

            // TODO: update the drive interface

            self->ctemp->updateValue(getTemperatureReading(status->ctemp));
            return;
        };

        pollCtemp(ctempTimer, pollingInterval, dataFetcher, dataProcessor);
    }
}

void NVMeSubsystem::stop()
{
    if (ctempTimer)
    {
        ctempTimer->cancel();
        ctempTimer.reset();
        ctemp.reset();
    }

    if (status == Status::Intiatilzing)
    {
        std::cerr << "status init" << std::endl;
        auto timer = std::make_shared<boost::asio::steady_timer>(
            io, std::chrono::milliseconds(100));
        timer->async_wait(
            [self{shared_from_this()}, timer](boost::system::error_code ec) {
            if (ec)
            {
                return;
            }
            self->stop();
        });
    }
    else
    {
        std::cerr << "status else" << std::endl;
        markFunctional(false);

        // There's been an explicit request to stop the subsystem. If it has
        // entered an unavailable state, reset that too. If the subsystem
        // continues to be unavailable beyond a subsequent invocation of start()
        // this will be detected in the usual fashion. Put another way: Don't
        // unnecessarily impede the progress of a subsequent start().
        unavailableCount = 0;
    }

    if (plugin)
    {
        plugin.reset();
    }
}

sdbusplus::message::object_path
    NVMeSubsystem::createVolume(boost::asio::yield_context yield, uint64_t size,
                                size_t lbaFormat, bool metadataAtEnd)
{
    if (status != Status::Start)
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::Unavailable();
    }

    // #0 (sequence of runtime/callbacks)
    auto progId = getRandomId();

    auto pc = getPrimaryController();
    nvme_mi_ctrl_t ctrl = pc->getMiCtrl();

    auto intf = std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());

    using submit_callback_t = void(std::tuple<nvme_ex_ptr>);
    auto [ex] = boost::asio::async_initiate<boost::asio::yield_context,
                                            submit_callback_t>(
        [weak{weak_from_this()}, progId, intf, ctrl, size, lbaFormat,
         metadataAtEnd](auto&& handler) {
        auto h = asio_helper::CopyableCallback(std::move(handler));

        // #1
        intf->createNamespace(
            ctrl, size, lbaFormat, metadataAtEnd,

            // submitted_cb
            [h](nvme_ex_ptr ex) mutable {
            // #2

            // Async completion of the createNamespace call.
            // The actual nvme_mi_admin_ns_mgmt_create() call is still running
            // in a separate thread. Pass the error status back out.
            h(std::make_tuple(ex));
        },

            // finished_cb
            [weak, progId](nvme_ex_ptr ex, NVMeNSIdentify newns) mutable {
            // #5. This will only be called once #4 completes.
            // It will not be called if the submit failed.
            auto self = weak.lock();
            if (!self)
            {
                std::cerr << "createNamespace completed while nvmesensor was "
                             "exiting\n";
                return;
            }
            // The NS create has completed (either successfully or not)
            self->createVolumeFinished(progId, ex, newns);
        });
    },
        yield);

    // #3

    // Exception must be thrown outside of the async block
    if (ex)
    {
        throw *ex;
    }

    // Progress endpoint for clients to poll, if the submit was successful.
    std::string progPath = path + "/CreateProgress/" + progId;

    auto prog = std::make_shared<NVMeCreateVolumeProgress>(conn, progPath);
    if (!createProgress.insert({progId, prog}).second)
    {
        throw std::logic_error("duplicate progress id");
    }

    updateAssociation();

    // #4
    return progPath;
}

void NVMeSubsystem::createVolumeFinished(std::string progId, nvme_ex_ptr ex,
                                         NVMeNSIdentify ns)
{
    try
    {
        auto p = createProgress.find(progId);
        if (p == createProgress.end())
        {
            throw std::logic_error("Missing progress entry");
        }
        auto prog = p->second;

        if (prog->status() == OperationStatus::Aborted)
        {
            return;
        }
        assert(status == Status::Start);

        if (ex)
        {
            prog->createFailure(ex);
            return;
        }

        std::shared_ptr<NVMeVolume> vol;
        try
        {
            vol = addVolume(ns);
        }
        catch (nvme_ex_ptr e)
        {
            prog->createFailure(e);
            return;
        }

        prog->createSuccess(vol);
        updateAssociation();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Unhandled error in createVolumeFinished: " << e.what()
                  << "\n";
    }
}

std::string NVMeSubsystem::volumePath(uint32_t nsid) const
{
    return path + "/volumes/" + std::to_string(nsid);
}

void NVMeSubsystem::addIdentifyNamespace(boost::asio::yield_context yield,
                                         uint32_t nsid)
{
    assert((status == Status::Start || status == Status::Intiatilzing) &&
           std::format("Subsystem not in Start state, have {}",
                       static_cast<int>(status))
               .c_str());

    auto pc = getPrimaryController();
    nvme_mi_ctrl_t ctrl = getPrimaryController()->getMiCtrl();

    auto intf = std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());

    using admin_identify_t = void(std::tuple<nvme_ex_ptr, std::span<uint8_t>>);

    auto [ex, data] = boost::asio::async_initiate<boost::asio::yield_context,
                                                  admin_identify_t>(
        [intf, ctrl, nsid](auto&& handler) {
        auto h = asio_helper::CopyableCallback(std::move(handler));
        intf->adminIdentify(
            ctrl, nvme_identify_cns::NVME_IDENTIFY_CNS_ALLOCATED_NS, nsid,
            NVME_CNTLID_NONE,
            [h](nvme_ex_ptr ex, std::span<uint8_t> data) mutable {
            h(std::make_tuple(ex, data));
        });
    }, yield);

    if (ex)
    {
        throw *ex;
    }

    nvme_id_ns& id = *reinterpret_cast<nvme_id_ns*>(data.data());

    // msb 6:5 and lsb 3:0
    size_t lbafIndex = ((id.flbas >> 1) & 0x30) | (id.flbas & 0x0f);
    size_t blockSize = 1UL << id.lbaf[lbafIndex].ds;
    bool metadataAtEnd = (id.flbas & (1 << 4)) != 0;

    NVMeNSIdentify ns = {
        .namespaceId = nsid,
        .size = ::le64toh(id.nsze * blockSize),
        .capacity = ::le64toh(id.ncap * blockSize),
        .blockSize = blockSize,
        .lbaFormat = lbafIndex,
        .metadataAtEnd = metadataAtEnd,
    };

    addVolume(ns);

    // determine attached controllers
    std::tie(ex, data) = boost::asio::async_initiate<boost::asio::yield_context,
                                                     admin_identify_t>(
        [intf, ctrl, nsid](auto&& handler) {
        auto h = asio_helper::CopyableCallback(std::move(handler));
        intf->adminIdentify(
            ctrl, nvme_identify_cns::NVME_IDENTIFY_CNS_NS_CTRL_LIST, nsid,
            NVME_CNTLID_NONE,
            [h](nvme_ex_ptr ex, std::span<uint8_t> data) mutable {
            h(std::make_tuple(ex, data));
        });
    }, yield);

    if (ex)
    {
        throw *ex;
    }

    nvme_ctrl_list& list = *reinterpret_cast<nvme_ctrl_list*>(data.data());
    uint16_t num = ::le16toh(list.num);
    if (num == NVME_ID_CTRL_LIST_MAX)
    {
        std::cerr << "Warning: full ctrl list returned\n";
    }

    for (auto i = 0; i < num; i++)
    {
        uint16_t c = ::le16toh(list.identifier[i]);
        attachCtrlVolume(c, nsid);
    }
}

void NVMeSubsystem::updateVolumes(boost::asio::yield_context yield)
{
    assert((status == Status::Start || status == Status::Intiatilzing) &&
           std::format("Subsystem not in Start state, have {}",
                       static_cast<int>(status))
               .c_str());

    auto pc = getPrimaryController();
    nvme_mi_ctrl_t ctrl = getPrimaryController()->getMiCtrl();

    auto intf = std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());
    using admin_list_ns_t =
        void(std::tuple<nvme_ex_ptr, std::vector<uint32_t>>);
    auto [ex, ns] = boost::asio::async_initiate<boost::asio::yield_context,
                                                admin_list_ns_t>(
        [intf, ctrl](auto&& handler) {
        auto h = asio_helper::CopyableCallback(std::move(handler));
        intf->adminListNamespaces(
            ctrl, [h](nvme_ex_ptr ex, std::vector<uint32_t> ns) mutable {
            h(std::make_tuple(ex, ns));
        });
    }, yield);

    if (ex)
    {
        throw *ex;
    }

    std::vector<uint32_t> existing;
    for (auto& [n, _] : volumes)
    {
        existing.push_back(n);
    }

    std::vector<uint32_t> additions;
    std::vector<uint32_t> deletions;

    // namespace lists are ordered
    std::set_difference(ns.begin(), ns.end(), existing.begin(), existing.end(),
                        std::back_inserter(additions));

    std::set_difference(existing.begin(), existing.end(), ns.begin(), ns.end(),
                        std::back_inserter(deletions));

    std::cerr << std::format(
        "[{}] subsystem enum {} NS, {} will be added, {} will be deleted\n",
        name, ns.size(), additions.size(), deletions.size());

    for (auto n : deletions)
    {
        forgetVolume(volumes.find(n)->second);
    }

    for (auto n : additions)
    {
        addIdentifyNamespace(yield, n);
    }
}

void NVMeSubsystem::fillDrive(boost::asio::yield_context yield)
{
    assert(status == Status::Intiatilzing);
    auto pc = getPrimaryController();
    nvme_mi_ctrl_t ctrl = pc->getMiCtrl();

    auto intf = std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());

    using admin_identify_t = void(std::tuple<nvme_ex_ptr, std::span<uint8_t>>);

    auto [ex, data] = boost::asio::async_initiate<boost::asio::yield_context,
                                                  admin_identify_t>(
        [intf, ctrl](auto&& handler) {
        auto h = asio_helper::CopyableCallback(std::move(handler));
        intf->adminIdentify(
            ctrl, nvme_identify_cns::NVME_IDENTIFY_CNS_CTRL, NVME_NSID_NONE,
            NVME_CNTLID_NONE,
            [h](nvme_ex_ptr ex, std::span<uint8_t> data) mutable {
            h(std::make_tuple(ex, data));
        });
    }, yield);

    if (ex)
    {
        throw std::runtime_error(
            std::format("{}: Error for controller identify", name));
    }

    nvme_id_ctrl& id = *reinterpret_cast<nvme_id_ctrl*>(data.data());
    drive->serialNumber(nvmeString(id.sn, sizeof(id.sn)));
    drive->model(nvmeString(id.mn, sizeof(id.mn)));
    drive->capacity(char128ToUint64(id.tnvmcap));

    auto fwVer = nvmeString(id.fr, sizeof(id.fr));
    if (!fwVer.empty())
    {
        // Formatting per
        // https://gerrit.openbmc.org/c/openbmc/phosphor-dbus-interfaces/+/43458/2/xyz/openbmc_project/Software/Version.interface.yaml#47
        // TODO find/write a better reference
        std::string v("xyz.openbmc_project.NVMe.ControllerFirmwareVersion");
        auto pc = getPrimaryController();
        pc->version(v);
        pc->purpose(SoftwareVersion::VersionPurpose::Other);
        pc->extendedVersion(v + ":" + fwVer);
    }
}

std::shared_ptr<NVMeVolume> NVMeSubsystem::getVolume(
    const sdbusplus::message::object_path& volPath) const
{
    if (volPath.parent_path() != path + "/volumes")
    {
        std::cerr << "getVolume path '" << volPath.str
                  << "' doesn't match parent " << path << "\n";
        return nullptr;
    }

    std::string id = volPath.filename();
    uint32_t nsid;
    auto e = std::from_chars(id.data(), id.data() + id.size(), nsid);
    if (e.ptr != id.data() + id.size() || e.ec != std::errc())
    {
        std::cerr << "getVolume path '" << volPath.str << "' bad nsid\n";
        return nullptr;
    }

    auto v = volumes.find(nsid);
    if (v == volumes.end())
    {
        std::cerr << "getVolume nsid " << nsid << " not found\n";
        return nullptr;
    }

    return v->second;
}

std::vector<uint32_t> NVMeSubsystem::attachedVolumes(uint16_t ctrlId) const
{
    std::vector<uint32_t> vols;

    if (!controllers.contains(ctrlId))
    {
        std::cerr << "attachedVolumes bad controller " << ctrlId << std::endl;
        return vols;
    }

    try
    {
        std::ranges::copy(attached.at(ctrlId), std::back_inserter(vols));
    }
    catch (std::out_of_range&)
    {
        // no volumes attached
    }
    return vols;
}

void NVMeSubsystem::attachCtrlVolume(uint16_t c, uint32_t ns)
{
    assert((status == Status::Start || status == Status::Intiatilzing) &&
           std::format("Subsystem not in Start state, have {}",
                       static_cast<int>(status))
               .c_str());

    if (!controllers.contains(c))
    {
        throw std::runtime_error(
            std::format("attachCtrlVolume bad controller {}", c));
    }
    if (!volumes.contains(ns))
    {
        throw std::runtime_error(std::format("attachCtrlVolume bad ns {}", ns));
    }
    attached[c].insert(ns);
    std::cout << name << " attached insert " << c << " " << ns << "\n";
    controllers[c].first->updateAssociation();
}

void NVMeSubsystem::detachCtrlVolume(uint16_t c, uint32_t ns)
{
    assert(status == Status::Start &&
           std::format("Subsystem is not in Start state: {}",
                       static_cast<int>(status))
               .c_str());

    if (!controllers.contains(c))
    {
        throw std::runtime_error(
            std::format("detachCtrlVolume bad controller {}", c));
    }
    if (!volumes.contains(ns))
    {
        throw std::runtime_error(std::format("detachCtrlVolume bad ns {}", ns));
    }
    attached[c].erase(ns);
    std::cout << name << " attached erase " << c << " " << ns << "\n";
    controllers[c].first->updateAssociation();
}

void NVMeSubsystem::detachAllCtrlVolume(uint32_t ns)
{
    assert(status == Status::Start &&
           std::format("Subsystem is not in Start state: {}",
                       static_cast<int>(status))
               .c_str());

    if (!volumes.contains(ns))
    {
        throw std::runtime_error(std::format("detachCtrlVolume bad ns {}", ns));
    }
    // remove from attached controllers list
    for (auto& [c, attach_vols] : attached)
    {
        if (attach_vols.erase(ns) == 1)
        {
            controllers[c].first->updateAssociation();
        }
    }
}

// Will throw a nvme_ex_ptr if the NS already exists */
std::shared_ptr<NVMeVolume> NVMeSubsystem::addVolume(const NVMeNSIdentify& ns)
{
    assert((status == Status::Start || status == Status::Intiatilzing) &&
           std::format("Subsystem not in Start state, have {}",
                       static_cast<int>(status))
               .c_str());

    if (volumes.contains(ns.namespaceId))
    {
        std::string errMsg = std::string("Internal error, NSID exists " +
                                         std::to_string(ns.namespaceId));
        std::cerr << errMsg << "\n";
        throw makeLibNVMeError(errMsg);
    }

    auto vol = NVMeVolume::create(objServer, conn, shared_from_this(), ns);
    volumes.insert({ns.namespaceId, vol});

    updateAssociation();
    return vol;
}

void NVMeSubsystem::forgetVolume(std::shared_ptr<NVMeVolume> volume)
{
    // remove any progress references
    for (const auto& [progId, prog] : createProgress)
    {
        std::string s = prog->volumePath();
        if (prog->volumePath() == volume->path)
        {
            createProgress.erase(progId);
            break;
        }
    }

    // remove from attached controllers list
    detachAllCtrlVolume(volume->namespaceId());

    if (volumes.erase(volume->namespaceId()) != 1)
    {
        throw std::runtime_error(std::format(
            "volume {} disappeared unexpectedly", volume->namespaceId()));
    }

    updateAssociation();
}

void NVMeSubsystem::querySupportedFormats(boost::asio::yield_context yield)
{
    assert((status == Status::Start || status == Status::Intiatilzing) &&
           std::format("Subsystem not in Start state, have {}",
                       static_cast<int>(status))
               .c_str());

    auto pc = getPrimaryController();
    nvme_mi_ctrl_t ctrl = pc->getMiCtrl();

    auto intf = std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());

    using admin_identify_t = void(std::tuple<nvme_ex_ptr, std::span<uint8_t>>);
    auto [ex, data] = boost::asio::async_initiate<boost::asio::yield_context,
                                                  admin_identify_t>(
        [intf, ctrl](auto&& handler) {
        auto h = asio_helper::CopyableCallback(std::move(handler));
        intf->adminIdentify(
            ctrl, nvme_identify_cns::NVME_IDENTIFY_CNS_NS, NVME_NSID_ALL,
            NVME_CNTLID_NONE,
            [h](nvme_ex_ptr ex, std::span<uint8_t> data) mutable {
            h(std::make_tuple(ex, data));
        });
    }, yield);

    if (ex)
    {
        throw std::runtime_error(
            std::format("{}: Error getting LBA formats :{}", name, ex->what()));
    }

    nvme_id_ns& id = *reinterpret_cast<nvme_id_ns*>(data.data());

    // nlbaf is 0’s based
    size_t nlbaf = id.nlbaf + 1;
    if (nlbaf > 64)
    {
        throw std::runtime_error(std::format("{}: Bad nlbaf {}", name, nlbaf));
    }

    std::cerr << name << ": Got nlbaf " << nlbaf << "\n";
    std::vector<LBAFormat> formats;
    for (size_t i = 0; i < nlbaf; i++)
    {
        size_t blockSize = 1UL << id.lbaf[i].ds;
        size_t metadataSize = id.lbaf[i].ms;
        RelPerf rp = relativePerformanceFromRP(id.lbaf[i].rp);
        std::cerr << name << ": lbaf " << i << " blocksize " << blockSize
                  << "\n";
        formats.push_back({.index = i,
                           .blockSize = blockSize,
                           .metadataSize = metadataSize,
                           .relativePerformance = rp});
    }
    setSupportedFormats(formats);
}

void NVMeSubsystem::deleteVolume(boost::asio::yield_context yield,
                                 std::shared_ptr<NVMeVolume> volume)
{
    if (status != Status::Start)
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::Unavailable();
    }

    auto pc = getPrimaryController();
    nvme_mi_ctrl_t ctrl = pc->getMiCtrl();

    auto intf = std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());

    using callback_t = void(std::tuple<std::error_code, int>);
    auto [err, nvmeStatus] =
        boost::asio::async_initiate<boost::asio::yield_context, callback_t>(
            [intf, ctrl, nsid{volume->namespaceId()}](auto&& handler) {
        auto h = asio_helper::CopyableCallback(std::move(handler));

        intf->adminDeleteNamespace(
            ctrl, nsid,
            [h](const std::error_code& err, int nvmeStatus) mutable {
            h(std::make_tuple(err, nvmeStatus));
        });
    }, yield);

    // exception must be thrown outside of the async block
    checkLibNVMeError(err, nvmeStatus, "Delete");

    forgetVolume(volume);
}

// submitCb is called once the sanitize has been submitted
void NVMeSubsystem::startSanitize(
    const NVMeSanitizeParams& params,
    std::function<void(nvme_ex_ptr ex)>&& submitCb)
{
    if (status != Status::Start)
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::Unavailable();
    }

    auto pc = getPrimaryController();
    nvme_mi_ctrl_t ctrl = pc->getMiCtrl();

    auto intf = std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());

    intf->adminSanitize(ctrl, params.nvmeAction(), params.passes,
                        params.pattern, params.patternInvert,
                        [submitCb](nvme_ex_ptr ex) { submitCb(ex); });
}

void NVMeSubsystem::sanitizeStatus(
    std::function<void(nvme_ex_ptr ex, bool inProgress, bool failed,
                       bool completed, uint16_t sstat, uint16_t sprog,
                       uint32_t scdw10)>&& cb)
{
    if (status != Status::Start)
    {
        std::cerr << "Subsystem not in Start state, have "
                  << static_cast<int>(status) << std::endl;
        return;
    }

    auto pc = getPrimaryController();
    nvme_mi_ctrl_t ctrl = pc->getMiCtrl();

    auto intf = std::get<std::shared_ptr<NVMeMiIntf>>(nvmeIntf.getInferface());

    intf->adminGetLogPage(
        ctrl, NVME_LOG_LID_SANITIZE, NVME_NSID_NONE, 0, 0,
        [self{shared_from_this()}, cb](const std::error_code& ec,
                                       std::span<uint8_t> data) {
        if (ec)
        {
            std::string msg = "GetLogPage failed: " + ec.message();
            auto ex = makeLibNVMeError(msg);
            cb(ex, false, false, false, 0, 0, 0);
            return;
        }

        nvme_sanitize_log_page* log =
            reinterpret_cast<nvme_sanitize_log_page*>(data.data());
        uint8_t sanStatus = log->sstat & NVME_SANITIZE_SSTAT_STATUS_MASK;
        cb(nvme_ex_ptr(), sanStatus == NVME_SANITIZE_SSTAT_STATUS_IN_PROGESS,
           sanStatus == NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED,
           sanStatus == NVME_SANITIZE_SSTAT_STATUS_COMPLETE_SUCCESS, log->sstat,
           log->sprog, log->scdw10);
    });
}
