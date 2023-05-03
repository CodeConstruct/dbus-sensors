#pragma once

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
        emit_removed();
    }

  protected:
    // Called by parent class for setup after shared_ptr has been initialised
    static void init(std::shared_ptr<NVMeStorage> self)
    {
        self->emit_added();
    }

  private:
    sdbusplus::asio::object_server& objServer;

    const std::string path;
};
