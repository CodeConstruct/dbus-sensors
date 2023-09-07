#pragma once

#include "NVMeError.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/Inventory/Item/Storage/server.hpp>
#include <xyz/openbmc_project/Nvme/Storage/server.hpp>

#include <memory>

using StorageBase =
    sdbusplus::xyz::openbmc_project::Inventory::Item::server::Storage;
using RelPerf =
    sdbusplus::xyz::openbmc_project::Nvme::server::Storage::RelativePerformance;

struct LBAFormat
{
    size_t index;
    // in bytes
    size_t blockSize;
    // in bytes
    size_t metadataSize;
    RelPerf relativePerformance;
};

RelPerf relativePerformanceFromRP(uint8_t rp);

class NVMeStorage : public StorageBase
{
  public:
    NVMeStorage(sdbusplus::asio::object_server& objServer,
                sdbusplus::bus_t& bus, const char* path);

    ~NVMeStorage() override;

    virtual sdbusplus::message::object_path
        createVolume(boost::asio::yield_context yield, uint64_t size,
                     size_t lbaFormat, bool metadataAtEnd) = 0;

  protected:
    // Called by parent class for setup after shared_ptr has been initialised
    // Will complete asynchronously.
    static void init(std::shared_ptr<NVMeStorage> self);

    void setSupportedFormats(const std::vector<LBAFormat>& formats);

  private:
    // NVMe-specific interface.
    // implemented manually for async, will eventually come from
    // sdbusplus::xyz::openbmc_project::Nvme::Storage
    std::shared_ptr<sdbusplus::asio::dbus_interface> nvmeStorageInterface;

    sdbusplus::asio::object_server& objServer;

    const std::string path;
};
