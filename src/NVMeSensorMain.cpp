/*
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "MctpEndpoint.hpp"
#include "NVMeBasic.hpp"
#include "NVMeIntf.hpp"
#include "NVMeMi.hpp"
#include "NVMePlugin.hpp"
#include "NVMeSubsys.hpp"

#include <dlfcn.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio/steady_timer.hpp>

#include <filesystem>
#include <fstream>
#include <optional>
#include <regex>
#include <system_error>
#include <unordered_set>

struct NVMeDevice
{
    std::shared_ptr<MctpDevice> dev;
    NVMeIntf intf;
    std::shared_ptr<NVMeSubsystem> subsys;
};

// a map with key value of {path, NVMeSubsystem}
using NVMEMap = std::map<std::string, NVMeDevice>;
static NVMEMap nvmeDevices;

// A map from root bus number to the Worker
// This map means to reuse the same worker for all NVMe EP under the same
// I2C root bus. There is no real physical concurrency among the i2c/mctp
// devices on the same bus. Though mctp kernel drive can schedule and
// sequencialize the transactions but assigning individual worker thread to
// each EP makes no sense.
static std::map<int, std::weak_ptr<NVMeMiWorker>> workerMap{};

std::unordered_map<std::string, void*> pluginLibMap = {};

static std::unordered_set<int> bannedBuses;

static void initBannedI2cBus()
{
    const std::string script = "/usr/bin/init-banned-i2c-bus.sh";
    const std::string confPath = "/var/run/nvmed/banned-i2c-bus.conf";
    if (!std::filesystem::exists(script))
    {
        std::cerr << "Script " << script << " doesn't exist" << std::endl;
        return;
    }

    std::cerr << "Begin to execute " << script << std::endl;
    int rc = std::system(script.c_str());
    std::cerr << "Shell script rc = " << rc << std::endl;

    if (!std::filesystem::exists(confPath))
    {
        std::cerr << "Warning: " << confPath << " doesn't exist." << std::endl;
        // Be optimistic，assume no bus is banned
        return;
    }
    std::ifstream file;
    file.open(confPath);
    if (!file.is_open())
    {
        std::cerr << "Error: cannot open " << confPath << std::endl;
        // Be optimistic，assume no bus is banned
        return;
    }

    bannedBuses.clear();
    int i2cBus{0};
    while (file >> i2cBus)
    {
        std::cerr << "Banned i2c bus: " << i2cBus << std::endl;
        bannedBuses.insert(i2cBus);
    }
    file.close();
}

static std::optional<int>
    extractBusNumber(const std::string& path,
                     const SensorBaseConfigMap& properties)
{
    auto findBus = properties.find("Bus");
    if (findBus == properties.end())
    {
        std::cerr << "could not determine bus number for " << path << "\n";
        return std::nullopt;
    }

    return std::visit(VariantToIntVisitor(), findBus->second);
}

static std::optional<int> extractAddress(const std::string& path,
                                         const SensorBaseConfigMap& properties)
{
    auto findAddr = properties.find("Address");
    if (findAddr == properties.end())
    {
        std::cerr << "could not determine address for " << path << "\n";
        return std::nullopt;
    }

    return std::visit(VariantToIntVisitor(), findAddr->second);
}

static std::optional<std::string>
    extractName(const std::string& path, const SensorBaseConfigMap& properties)
{
    auto findName = properties.find("Name");
    if (findName == properties.end())
    {
        std::cerr << "could not determine configuration name for " << path
                  << "\n";
        return std::nullopt;
    }

    return std::get<std::string>(findName->second);
}

static std::optional<std::string>
    extractProtocol(const std::string& path,
                    const SensorBaseConfigMap& properties)
{
    auto findProtocol = properties.find("Protocol");
    if (findProtocol == properties.end())
    {
        std::cerr << "could not determine nvme protocl for " << path << "\n";
        return std::nullopt;
    }
    return std::get<std::string>(findProtocol->second);
}

static void
    setupMctpDevice(const std::shared_ptr<MctpDevice>& dev,
                    const std::weak_ptr<NVMeMiIntf>& weakIntf,
                    const std::weak_ptr<NVMeSubsystem>& weakSubsys,
                    const std::shared_ptr<boost::asio::steady_timer>& timer)
{
    dev->setup([weakDev{std::weak_ptr(dev)}, weakIntf, weakSubsys,
                timer](const std::error_code& ec,
                       const std::shared_ptr<MctpEndpoint>& ep) {
        if (ec)
        {
            auto dev = weakDev.lock();
            if (!dev)
            {
                return;
            }
            // Setup failed, wait a bit and try again
            timer->expires_from_now(std::chrono::seconds(5));
            timer->async_wait([=](const boost::system::error_code& ec) {
                if (!ec)
                {
                    setupMctpDevice(dev, weakIntf, weakSubsys, timer);
                }
            });
            return;
        }

        ep->subscribe(
            // Degraded
            [weakIntf](const std::shared_ptr<MctpEndpoint>& ep) {
            if (auto miIntf = weakIntf.lock())
            {
                std::cout << "[" << ep->describe() << "]: Degraded"
                          << std::endl;
                miIntf->stop();
            }
        },
            // Available
            [weakIntf, weakSubsys](const std::shared_ptr<MctpEndpoint>& ep) {
            if (auto miIntf = weakIntf.lock())
            {
                if (auto subsys = weakSubsys.lock())
                {
                    std::cout << subsys->getName() << " [" << ep->describe()
                              << "]: Available" << std::endl;
                }
                miIntf->start(ep);
            }
        },
            // Removed
            [=](const std::shared_ptr<MctpEndpoint>& ep) {
            auto nvmeSubsys = weakSubsys.lock();
            auto miIntf = weakIntf.lock();
            auto dev = weakDev.lock();
            if (!nvmeSubsys || !miIntf || !dev)
            {
                return;
            }

            std::cout << "[" << ep->describe() << "]: Removed" << std::endl;
            miIntf->stop();
            // Start polling for the return of the device
            timer->expires_from_now(std::chrono::seconds(5));
            timer->async_wait([=](const boost::system::error_code& ec) {
                if (!ec)
                {
                    setupMctpDevice(dev, weakIntf, weakSubsys, timer);
                }
            });
        });

        auto miIntf = weakIntf.lock();
        auto nvmeSubsys = weakSubsys.lock();
        if (miIntf && nvmeSubsys)
        {
            miIntf->start(ep);
        }
    });
}

static void handleConfigurations(
    boost::asio::io_context& io, sdbusplus::asio::object_server& objectServer,
    std::shared_ptr<sdbusplus::asio::connection>& dbusConnection,
    const ManagedObjectType& nvmeConfigurations)
{
    // Initialize banned i2c bus info on every configuration change
    initBannedI2cBus();

    /* We perform two iterations for configurations here. The first iteration is
     * to set up NVMeIntf. The second iter is to setup NVMe subsystem.
     *
     * The reason to seperate these two processes is NVMeIntf initialization of
     * NVMeMI is via MCTPd, from which the mctp control msg should be relatively
     * short and should not be delayed by NVMe-MI protocol msg from NVMe
     * subsystem.
     */
    std::map<std::string, NVMeDevice> updatedDevices;
    for (const auto& [interfacePath, configData] : nvmeConfigurations)
    {
        // find base configuration
        auto sensorBase =
            configData.find(configInterfaceName(nvme::sensorType));
        if (sensorBase == configData.end())
        {
            continue;
        }

        const SensorBaseConfigMap& sensorConfig = sensorBase->second;
        std::optional<int> busNumber = extractBusNumber(interfacePath,
                                                        sensorConfig);
        std::optional<int> address = extractAddress(interfacePath,
                                                    sensorConfig);
        std::optional<std::string> sensorName = extractName(interfacePath,
                                                            sensorConfig);
        std::optional<std::string> nvmeProtocol = extractProtocol(interfacePath,
                                                                  sensorConfig);

        if (!(busNumber && sensorName))
        {
            continue;
        }

        if (bannedBuses.contains(*busNumber))
        {
            std::cerr << "Skip banned i2c bus:" << *busNumber << std::endl;
            continue;
        }

        // the default protocol is mi_basic
        if (!nvmeProtocol)
        {
            nvmeProtocol.emplace("mi_basic");
        }

        if (*nvmeProtocol == "mi_basic")
        {
            // defualt i2c basic port is 0x6a
            if (!address)
            {
                address.emplace(0x6a);
            }
            try
            {
                NVMeIntf nvmeIntf = NVMeIntf::create<NVMeBasic>(io, *busNumber,
                                                                *address);

                NVMeDevice dev{{}, nvmeIntf, {}};
                updatedDevices.emplace(interfacePath, std::move(dev));
            }
            catch (std::exception& ex)
            {
                std::cerr << "Failed to add nvme basic interface for "
                          << std::string(interfacePath) << ": " << ex.what()
                          << "\n";
                continue;
            }
        }
        else if (*nvmeProtocol == "mi_i2c")
        {
            // defualt i2c nvme-mi port is 0x1d
            if (!address)
            {
                address.emplace(0x1d);
            }

            PowerState powerState = getPowerState(sensorConfig);

            std::shared_ptr<NVMeMiWorker> worker;
            if (singleWorkerFeature)
            {
                auto root = deriveRootBus(*busNumber);

                if (!root || *root < 0)
                {
                    throw std::runtime_error("invalid root bus number");
                }
                auto res = workerMap.find(*root);

                if (res == workerMap.end() || res->second.expired())
                {
                    worker = std::make_shared<NVMeMiWorker>();
                    workerMap[*root] = worker;
                }
                else
                {
                    worker = res->second.lock();
                }
            }
            else
            {
                worker = std::make_shared<NVMeMiWorker>();
            }

            try
            {
                auto mctpDev = std::make_shared<SmbusMctpdDevice>(
                    dbusConnection, *busNumber, *address);
                NVMeIntf nvmeIntf = NVMeIntf::create<NVMeMi>(
                    io, dbusConnection, mctpDev, worker, powerState);

                // Create a partial NVMeDevice entry in the temporary
                // updatedDevices map
                NVMeDevice dev{mctpDev, nvmeIntf, {}};
                updatedDevices.emplace(interfacePath, std::move(dev));
            }
            catch (std::exception& ex)
            {
                std::cerr << "Failed to add nvme mi interface for "
                          << std::string(interfacePath) << ": " << ex.what()
                          << "\n";
                continue;
            }
        }
    }

    for (const auto& [interfacePath, configData] : nvmeConfigurations)
    {
        // find base configuration
        auto sensorBase =
            configData.find(configInterfaceName(nvme::sensorType));
        if (sensorBase == configData.end())
        {
            continue;
        }

        const SensorBaseConfigMap& sensorConfig = sensorBase->second;

        std::optional<std::string> sensorName = extractName(interfacePath,
                                                            sensorConfig);

        auto find = updatedDevices.find(interfacePath);
        if (find == updatedDevices.end())
            continue;
        try
        {
            auto nvmeSubsys = NVMeSubsystem::create(
                io, objectServer, dbusConnection, interfacePath, *sensorName,
                configData, find->second.intf);
            // Complete the NVMeDevice entry with its subsystem and record it in
            // the persistent nvmeDeviceMap
            find->second.subsys = nvmeSubsys;
            auto [entry, _] = nvmeDevices.emplace(interfacePath,
                                                  std::move(find->second));
            auto nvmeDev = entry->second;
            nvmeSubsys->start();
            if (nvmeDev.intf.getProtocol() != NVMeIntf::Protocol::NVMeMI)
            {
                continue;
            }

            auto miIntf = std::get<std::shared_ptr<NVMeMiIntf>>(
                nvmeDev.intf.getInferface());
            auto timer = std::make_shared<boost::asio::steady_timer>(
                io, std::chrono::seconds(5));
            setupMctpDevice(nvmeDev.dev, miIntf, nvmeSubsys, timer);
        }
        catch (std::exception& ex)
        {
            std::cerr << "Failed to add nvme subsystem for "
                      << std::string(interfacePath) << ": " << ex.what()
                      << "\n";
            continue;
        }
    }
}

void createNVMeSubsystems(
    boost::asio::io_context& io, sdbusplus::asio::object_server& objectServer,
    std::shared_ptr<sdbusplus::asio::connection>& dbusConnection)
{
    // todo: it'd be better to only update the ones we care about
    for (const auto& [_, nvmeDev] : nvmeDevices)
    {
        if (nvmeDev.subsys)
        {
            nvmeDev.subsys->stop();
        }
    }
    nvmeDevices.clear();

    static int count = 0;
    static ManagedObjectType configs;
    count += 2;

    auto getter = std::make_shared<GetSensorConfiguration>(
        dbusConnection, [&io, &objectServer, &dbusConnection](
                            const ManagedObjectType& nvmeConfigurations) {
        configs = nvmeConfigurations;
        count--;
        if (count == 0)
        {
            handleConfigurations(io, objectServer, dbusConnection, configs);
        }
        else
        {
            std::cerr << "more than one `handleConfigurations` has been "
                         "scheduled, cancel the current one"
                      << std::endl;
        }
    });
    auto timer = std::make_shared<boost::asio::steady_timer>(
        io, std::chrono::seconds(5));
    timer->async_wait([&io, &objectServer, &dbusConnection,
                       timer](const boost::system::error_code& ec) {
        count--;
        if (ec)
        {
            return;
        }
        if (count == 0)
        {
            handleConfigurations(io, objectServer, dbusConnection, configs);
        }
        else
        {
            std::cerr << "`handleConfigurations` has not been triggered, "
                         "cancel the time"
                      << std::endl;
        }
    });

    getter->getConfiguration(std::vector<std::string>{nvme::sensorType});
}

static void interfaceRemoved(sdbusplus::message_t& message, NVMEMap& devices)
{
    if (message.is_method_error())
    {
        std::cerr << "interfacesRemoved callback method error\n";
        return;
    }

    sdbusplus::message::object_path path;
    std::vector<std::string> interfaces;

    message.read(path, interfaces);

    auto interface = std::find(interfaces.begin(), interfaces.end(),
                               configInterfaceName(nvme::sensorType));
    if (interface == interfaces.end())
    {
        return;
    }

    auto device = devices.find(path);
    if (device == devices.end())
    {
        return;
    }

    device->second.subsys->stop();
    devices.erase(device);
}

int main()
{
    if (singleWorkerFeature)
        std::cerr << "singleWorkerFeature on " << std::endl;

    // Load plugin shared libraries
    try
    {
        for (const auto& entry :
             std::filesystem::directory_iterator(NVMePlugin::libraryPath))
        {
            void* lib = dlopen(entry.path().c_str(), RTLD_NOW);
            if (lib != nullptr)
            {
                pluginLibMap.emplace(entry.path().filename().string(), lib);
            }
            else
            {
                std::cerr << "could not load the plugin: " << dlerror()
                          << std::endl;
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        std::cerr << "failed to open plugin folder: " << e.what() << std::endl;
    }

    // TODO: set single thread mode according to input parameters

    boost::asio::io_context io;
    auto systemBus = std::make_shared<sdbusplus::asio::connection>(io);
    systemBus->request_name("xyz.openbmc_project.NVMe");
    sdbusplus::asio::object_server objectServer(systemBus, true);
    objectServer.add_manager("/xyz/openbmc_project/sensors");
    objectServer.add_manager("/xyz/openbmc_project/inventory");

    io.post([&]() { createNVMeSubsystems(io, objectServer, systemBus); });

    boost::asio::steady_timer filterTimer(io);
    std::function<void(sdbusplus::message_t&)> eventHandler =
        [&filterTimer, &io, &objectServer, &systemBus](sdbusplus::message_t&) {
        // this implicitly cancels the timer
        filterTimer.expires_after(std::chrono::seconds(1));

        filterTimer.async_wait([&](const boost::system::error_code& ec) {
            if (ec == boost::asio::error::operation_aborted)
            {
                return; // we're being canceled
            }

            if (ec)
            {
                std::cerr << "Error: " << ec.message() << "\n";
                return;
            }

            createNVMeSubsystems(io, objectServer, systemBus);
        });
    };

    std::vector<std::unique_ptr<sdbusplus::bus::match_t>> matches =
        setupPropertiesChangedMatches(
            *systemBus, std::to_array<const char*>({NVMeSensor::sensorType}),
            eventHandler);

    // Watch for entity-manager to remove configuration interfaces
    // so the corresponding sensors can be removed.
    auto ifaceRemovedMatch = std::make_unique<sdbusplus::bus::match_t>(
        static_cast<sdbusplus::bus_t&>(*systemBus),
        "type='signal',member='InterfacesRemoved',arg0path='" +
            std::string(inventoryPath) + "/'",
        [](sdbusplus::message_t& msg) { interfaceRemoved(msg, nvmeDevices); });

    setupManufacturingModeMatch(*systemBus);

    // The NVMe controller used pipe to transfer raw data. The pipe could be
    // closed by the client. It should not be considered as an error.
    boost::asio::signal_set signals(io, SIGPIPE);
    signals.async_wait(
        [](const boost::system::error_code& error, int signal_number) {
        std::cerr << "signal: " << strsignal(signal_number) << ", "
                  << error.message() << std::endl;
    });
    io.run();

    for (const auto& [_, lib] : pluginLibMap)
    {
        dlclose(lib);
    }
}
