#pragma once

#include "NVMeError.hpp"

#include <xyz/openbmc_project/Inventory/Item/Storage/server.hpp>

#include <memory>

using StorageBase =
    sdbusplus::xyz::openbmc_project::Inventory::Item::server::Storage;
class NVMeStorage : public StorageBase
{
  public:
    NVMeStorage(sdbusplus::asio::object_server& objServer,
                sdbusplus::bus_t& bus, const char* path) :
        StorageBase(bus, path),
        objServer(objServer), path(path)
    {}

    ~NVMeStorage() override
    {
        objServer.remove_interface(nvmeStorageInterface);
        emit_removed();
    }

    virtual sdbusplus::message::object_path
        createVolume(boost::asio::yield_context yield, uint64_t size,
                     size_t lbaFormat, bool metadataAtEnd) = 0;

  protected:
    // Called by parent class for setup after shared_ptr has been initialised
    static void init(std::shared_ptr<NVMeStorage> self)
    {
        self->nvmeStorageInterface = self->objServer.add_interface(
            self->path, "xyz.openbmc_project.Nvme.Storage");
        self->nvmeStorageInterface->register_method(
            "CreateVolume", [weak{std::weak_ptr<NVMeStorage>(self)}](
                                boost::asio::yield_context yield, uint64_t size,
                                size_t lbaFormat, bool metadataAtEnd) {
                if (auto self = weak.lock())
                {
                    return self->createVolume(yield, size, lbaFormat,
                                              metadataAtEnd);
                }
                throw *makeLibNVMeError("storage removed");
            });
        self->nvmeStorageInterface->initialize();

        self->emit_added();
    }

  private:
    // NVMe-specific interface.
    // implemented manually for async, will eventually come from
    // sdbusplus::xyz::openbmc_project::Nvme::Storage
    std::shared_ptr<sdbusplus::asio::dbus_interface> nvmeStorageInterface;

    sdbusplus::asio::object_server& objServer;

    const std::string path;
};
